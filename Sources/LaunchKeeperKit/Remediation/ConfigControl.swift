import Foundation

// V0.7 — switches that live in configuration rather than in launchd: a line
// in the user's crontab, a loginwindow hook key. Same rules as every other
// write path: gate first, dry-run by default, a snapshot of the WHOLE source
// before the first write (no snapshot, no write), argv only, and a
// verification that re-reads the source after the change.

/// A refusal from one of the config editors — the engine turns it into an
/// audited `refused(...)` result.
public struct ControlRefusal: Error, Equatable, CustomStringConvertible {
    public let reason: String
    public init(_ reason: String) { self.reason = reason }
    public var description: String { reason }
}

/// One saved copy of a configuration source, taken right before a change.
public struct ConfigSnapshot: Codable, Equatable {
    public var name: String
    public var directory: String
    /// Full path of the saved copy.
    public var file: String
    /// What was saved ("crontab -l (alice)", a plist path …).
    public var source: String
    public var sha256: String
    public var createdAt: String
}

/// Snapshots of config sources under
/// `~/Library/Application Support/launchkeeper/config-snapshots/<stamp>-<label>/`
/// — deliberately NOT under `backups/`, whose `restore` copies launch-dir
/// files back and knows nothing about crontabs. Each snapshot carries a
/// manifest with the sha256 of the copy, re-read and checked after writing.
public struct ConfigSnapshotStore {
    public var root: String
    public var fileManager: FileManager

    public init(root: String, fileManager: FileManager = .default) {
        self.root = root
        self.fileManager = fileManager
    }

    public func save(label: String, fileName: String, contents: Data, source: String,
                     now: Date = Date()) -> Result<ConfigSnapshot, ControlRefusal> {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd-HHmmss"
        formatter.timeZone = TimeZone(identifier: "UTC")
        let base = formatter.string(from: now) + "Z-" + label
        var name = base
        var counter = 2
        while fileManager.fileExists(atPath: root + "/" + name) {
            name = base + "-\(counter)"
            counter += 1
        }
        let directory = root + "/" + name
        let file = directory + "/" + fileName
        guard let sha = BackupCrypto.sha256Hex(contents) else {
            return .failure(ControlRefusal("cannot hash the snapshot — nothing changed"))
        }
        let snapshot = ConfigSnapshot(name: name, directory: directory, file: file, source: source,
                                      sha256: sha, createdAt: ISO8601DateFormatter().string(from: now))
        do {
            try fileManager.createDirectory(atPath: directory, withIntermediateDirectories: true)
            try contents.write(to: URL(fileURLWithPath: file))
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            try encoder.encode(snapshot).write(to: URL(fileURLWithPath: directory + "/manifest.json"))
        } catch {
            return .failure(ControlRefusal("cannot write the snapshot (\(error.localizedDescription)) — nothing changed"))
        }
        // Trust the disk, not the write call.
        guard let written = fileManager.contents(atPath: file), BackupCrypto.sha256Hex(written) == sha else {
            return .failure(ControlRefusal("snapshot does not read back intact — nothing changed"))
        }
        return .success(snapshot)
    }
}

/// Pure crontab editing: comment ONE line out behind the launchkeeper marker,
/// or take the marker off again. Nothing else in the table moves — the edit
/// proves that by re-parsing the result before anyone installs it.
public enum CronEditor {
    public struct Edit: Equatable {
        /// 1-based line in the table.
        public var lineNumber: Int
        public var newText: String
    }

    public static func edit(_ text: String, schedule: String, command: String,
                            operation: RemediationOperation) -> Result<Edit, ControlRefusal> {
        guard operation == .disable || operation == .enable else {
            return .failure(ControlRefusal("cron entries are disabled or enabled, never removed by launchkeeper"))
        }
        let before = CronParser.parse(text, user: "-", source: "crontab")
        let matches = before.filter { $0.schedule == schedule && $0.command == command }
        guard let entry = matches.first else {
            return .failure(ControlRefusal("the crontab no longer contains this entry — scan again"))
        }
        guard matches.count == 1 else {
            return .failure(ControlRefusal("the same schedule and command appear \(matches.count) times — "
                + "edit by hand with `crontab -e`"))
        }
        if operation == .disable, entry.disabled {
            return .failure(ControlRefusal("already disabled — the line carries the launchkeeper marker"))
        }
        if operation == .enable, !entry.disabled {
            return .failure(ControlRefusal("not disabled by launchkeeper — nothing to enable"))
        }

        var lines = text.components(separatedBy: "\n")
        let index = entry.line - 1
        guard lines.indices.contains(index) else {
            return .failure(ControlRefusal("line \(entry.line) is out of range — scan again"))
        }
        let raw = lines[index]
        if operation == .disable {
            lines[index] = CronParser.disabledMarker + raw
        } else {
            let trimmed = String(raw.drop(while: { $0 == " " || $0 == "\t" }))
            guard trimmed.hasPrefix(CronParser.disabledMarker) else {
                return .failure(ControlRefusal("line \(entry.line) has no launchkeeper marker — scan again"))
            }
            lines[index] = String(trimmed.dropFirst(CronParser.disabledMarker.count))
        }
        let newText = lines.joined(separator: "\n")

        // Self-check: the new table holds exactly the same entries, and only
        // this one changed state. Anything else means the edit misread the
        // table — refuse rather than install it.
        let after = CronParser.parse(newText, user: "-", source: "crontab")
        var expected = before
        if let position = expected.firstIndex(of: entry) { expected[position].disabled = (operation == .disable) }
        guard after == expected else {
            return .failure(ControlRefusal("the edited table would differ in more than this entry — refused"))
        }
        return .success(Edit(lineNumber: entry.line, newText: newText))
    }

    /// Line endings aside, is `installed` what we meant to install?
    public static func sameTable(_ lhs: String, _ rhs: String) -> Bool {
        func normalized(_ text: String) -> String {
            var out = text
            while out.hasSuffix("\n") { out.removeLast() }
            return out
        }
        return normalized(lhs) == normalized(rhs)
    }
}
