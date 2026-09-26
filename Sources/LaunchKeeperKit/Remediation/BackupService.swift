import Foundation
#if canImport(Darwin)
import Darwin
#endif
#if canImport(CryptoKit)
import CryptoKit
#endif

/// Environment for snapshot backup/restore. All paths are injectable so tests
/// run against temp directories — nothing here may touch the real $HOME or
/// /Library during unit tests.
public struct BackupEnvironment {
    /// Directories whose *.plist contents get snapshotted (source == restore target).
    public var launchDirs: [String]
    /// Prefixes whose restores go through `sudo cp` (interactive seam) instead of direct writes.
    public var systemDirPrefixes: [String]
    public var backupsRoot: String
    /// Roots that are only READ (restore looks there when a snapshot is not
    /// under `backupsRoot`): the btmctl-era backups directory. New snapshots
    /// always land in `backupsRoot`.
    public var legacyBackupsRoots: [String]
    public var runner: CommandRunner
    public var fileManager: FileManager
    public var uid: Int
    public var toolVersion: String

    public init(launchDirs: [String]? = nil, systemDirPrefixes: [String]? = nil,
                backupsRoot: String? = nil, legacyBackupsRoots: [String]? = nil,
                runner: CommandRunner = SystemCommandRunner(),
                fileManager: FileManager = .default, home: String = NSHomeDirectory(),
                uid: Int = -1, toolVersion: String = "0.9.1") {
        self.launchDirs = launchDirs ?? [
            home + "/Library/LaunchAgents", home + "/Library/LaunchDaemons",
            "/Library/LaunchAgents", "/Library/LaunchDaemons",
        ]
        self.systemDirPrefixes = systemDirPrefixes ?? ["/Library/LaunchAgents", "/Library/LaunchDaemons"]
        self.backupsRoot = backupsRoot ?? LaunchKeeperPaths.backups(home: home)
        // Only the DEFAULT root inherits the legacy location; explicit roots
        // (tests, custom setups) stay exactly where they point.
        self.legacyBackupsRoots = legacyBackupsRoots
            ?? (backupsRoot == nil ? [LaunchKeeperPaths.legacyBackups(home: home)] : [])
        self.runner = runner
        self.fileManager = fileManager
        self.uid = uid >= 0 ? uid : Int(getuid())
        self.toolVersion = toolVersion
    }
}

public struct ManifestEntry: Codable, Equatable {
    /// Path of the staged copy inside the backup, relative to `files/`.
    public var rel: String
    /// Absolute path the file belongs to on this machine (restore target).
    public var target: String
    public var sha256: String
    public var size: Int
    public var mode: Int
    public var uid: Int
}

public struct BackupManifest: Codable {
    public var createdAt: String
    public var toolVersion: String
    public var entries: [ManifestEntry]
}

public struct BackupReport {
    public var backupName: String
    public var backupDir: String
    public var copied: Int
    public var notes: [String]
}

public struct RestoreReport {
    public var restored: [String]
    public var unchanged: [String]
    /// Dry-run output: what WOULD be copied back.
    public var wouldRestore: [String]
    public var refused: [String]
    public var failed: [String]
    public var applied: Bool
    public var auditStatus: String {
        guard applied else { return "planned" }
        let problems = refused.count + failed.count
        return problems == 0 ? "applied-ok" : "applied-fail(\(problems) of \(restored.count + problems))"
    }
}

enum BackupCrypto {
    static func sha256Hex(_ data: Data) -> String? {
        #if canImport(CryptoKit)
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        #else
        return nil
        #endif
    }
}

/// Failure carrier — `Result`'s failure type must conform to Error in Swift 6,
/// and the CLI prints the message verbatim (CustomStringConvertible).
public struct BackupFailure: Error, CustomStringConvertible {
    public let message: String
    public init(_ message: String) { self.message = message }
    public var description: String { message }
}

/// Snapshot + restore of launch-territory state. `backup` is READ-ONLY (no
/// --apply needed); `restore --apply` is the gated write path.
public struct BackupService {
    public var env: BackupEnvironment

    public init(env: BackupEnvironment = BackupEnvironment()) {
        self.env = env
    }

    // MARK: - backup (read-only snapshot)

    public func create(label: String? = nil, now: Date = Date()) -> Result<BackupReport, BackupFailure> {
        let fm = env.fileManager
        let name = makeBackupName(label: label, now: now)
        let dir = env.backupsRoot + "/" + name
        let filesDir = dir + "/files"
        do {
            try fm.createDirectory(atPath: filesDir, withIntermediateDirectories: true)
        } catch {
            return .failure(BackupFailure("cannot create backup dir: \(error.localizedDescription)"))
        }

        var entries: [ManifestEntry] = []
        var notes: [String] = []

        for sourceDir in env.launchDirs where fm.fileExists(atPath: sourceDir) {
            let contents = (try? fm.contentsOfDirectory(atPath: sourceDir)) ?? []
            for file in contents.sorted() where file.hasSuffix(".plist") {
                let full = sourceDir + "/" + file
                guard let data = try? Data(contentsOf: URL(fileURLWithPath: full)) else {
                    notes.append("unreadable, skipped: \(full)")
                    continue
                }
                guard let sha = BackupCrypto.sha256Hex(data) else {
                    notes.append("no sha256, skipped: \(full)")
                    continue
                }
                var mode = -1
                var ownerUid = -1
                if let attrs = try? fm.attributesOfItem(atPath: full) {
                    mode = (attrs[.posixPermissions] as? NSNumber)?.intValue ?? -1
                    ownerUid = (attrs[.ownerAccountID] as? NSNumber)?.intValue ?? -1
                }
                let rel = String(full.drop(while: { $0 == "/" }))
                let staged = filesDir + "/" + rel
                do {
                    try fm.createDirectory(atPath: (staged as NSString).deletingLastPathComponent,
                                           withIntermediateDirectories: true)
                    try data.write(to: URL(fileURLWithPath: staged))
                    entries.append(ManifestEntry(rel: rel, target: full, sha256: sha,
                                                 size: data.count, mode: mode, uid: ownerUid))
                } catch {
                    notes.append("stage failed for \(full): \(error.localizedDescription)")
                }
            }
        }

        // State snapshots: disabled overrides + running services, both domains.
        let stateDir = dir + "/state"
        do {
            try fm.createDirectory(atPath: stateDir, withIntermediateDirectories: true)
        } catch {
            return .failure(BackupFailure("cannot create state dir: \(error.localizedDescription)"))
        }
        for (tag, target) in [("gui", "gui/\(env.uid)"), ("system", "system")] {
            let result = env.runner.run(command: "/bin/launchctl", arguments: ["print-disabled", target])
            let dest = dir + "/state/print-disabled-\(tag).txt"
            if result.exitCode == 0 {
                try? Data(result.stdout.utf8).write(to: URL(fileURLWithPath: dest))
            } else {
                notes.append("print-disabled \(target) unavailable (exit \(result.exitCode))")
            }
        }

        let formatter = ISO8601DateFormatter()
        let manifest = BackupManifest(createdAt: formatter.string(from: now),
                                      toolVersion: env.toolVersion, entries: entries)
        do {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            try encoder.encode(manifest).write(to: URL(fileURLWithPath: dir + "/manifest.json"))
        } catch {
            return .failure(BackupFailure("cannot write manifest: \(error.localizedDescription)"))
        }

        return .success(BackupReport(backupName: name, backupDir: dir,
                                     copied: entries.count, notes: notes))
    }

    private func makeBackupName(label: String?, now: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd-HHmmss"
        formatter.timeZone = TimeZone(identifier: "UTC")
        var name = formatter.string(from: now) + "Z"
        if let label, !label.isEmpty {
            let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_."))
            let cleaned = label.components(separatedBy: allowed.inverted).joined(separator: "-")
            if !cleaned.isEmpty { name += "-" + String(cleaned.prefix(40)) }
        }
        return name
    }

    // MARK: - restore (gated write)

    public func restore(name: String, apply: Bool = false) -> Result<RestoreReport, BackupFailure> {
        // Path injection guard: the backup name must stay inside backupsRoot.
        guard !name.contains("/"), !name.contains("\\") else {
            return .failure(BackupFailure("backup name must not contain path separators"))
        }
        let nameComponents = name.split(separator: "/")
        if name.contains("..") || nameComponents.count != 1 {
            return .failure(BackupFailure("backup name must not contain path separators"))
        }
        // The current root first, then the btmctl-era root — a snapshot
        // written before the rename must still restore.
        let fm = env.fileManager
        let dir = ([env.backupsRoot] + env.legacyBackupsRoots)
            .map { $0 + "/" + name }
            .first { fm.fileExists(atPath: $0 + "/manifest.json") }
            ?? env.backupsRoot + "/" + name
        let filesDir = dir + "/files"
        let manifestURL = URL(fileURLWithPath: dir + "/manifest.json")
        guard let data = try? Data(contentsOf: manifestURL),
              let manifest = try? JSONDecoder().decode(BackupManifest.self, from: data) else {
            return .failure(BackupFailure("no such backup: \(name)"))
        }

        var report = RestoreReport(restored: [], unchanged: [], wouldRestore: [],
                                   refused: [], failed: [], applied: apply)

        for entry in manifest.entries {
            let staged = filesDir + "/" + entry.rel

            // Hard blocklist before anything else.
            if entry.target.hasPrefix("/System/") {
                report.refused.append("\(entry.target) — /System is never written")
                continue
            }
            guard env.launchDirs.contains(where: { entry.target.hasPrefix($0 + "/") }) else {
                report.refused.append("\(entry.target) — outside launch-dir allowlist")
                continue
            }

            guard let stagedData = try? Data(contentsOf: URL(fileURLWithPath: staged)) else {
                report.failed.append("\(entry.target) — staged file missing")
                continue
            }
            guard BackupCrypto.sha256Hex(stagedData) == entry.sha256 else {
                report.failed.append("\(entry.target) — INTEGRITY: staged copy differs from manifest")
                continue
            }

            if let currentData = try? Data(contentsOf: URL(fileURLWithPath: entry.target)),
               BackupCrypto.sha256Hex(currentData) == entry.sha256 {
                report.unchanged.append(entry.target)
                continue
            }
            guard apply else {
                report.wouldRestore.append(entry.target)
                continue
            }

            // Write path: system dirs only via sudo cp (interactive seam),
            // user dirs directly. /System can never be reached from here.
            if env.systemDirPrefixes.contains(where: { entry.target.hasPrefix($0 + "/") }) {
                let code = env.runner.runInteractive(command: "/usr/bin/sudo",
                                                      arguments: ["cp", staged, entry.target],
                                                      timeout: 180)   // a human types the password
                if code != 0 {
                    report.failed.append("\(entry.target) — sudo cp exit \(code)")
                    continue
                }
            } else {
                do {
                    if env.fileManager.fileExists(atPath: entry.target) {
                        try env.fileManager.removeItem(atPath: entry.target)
                    }
                    try env.fileManager.copyItem(atPath: staged, toPath: entry.target)
                } catch {
                    report.failed.append("\(entry.target) — copy failed: \(error.localizedDescription)")
                    continue
                }
            }

            // Verify-after-write: success only if the target now hashes clean.
            if let written = try? Data(contentsOf: URL(fileURLWithPath: entry.target)),
               BackupCrypto.sha256Hex(written) == entry.sha256 {
                report.restored.append(entry.target)
            } else {
                report.failed.append("\(entry.target) — written but NOT verified")
            }
        }
        return .success(report)
    }
}