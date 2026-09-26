import Foundation

// V0.8 — cleanup never `rm`s what it takes away: it MOVES it into a
// quarantine under ~/Library/Application Support/launchkeeper/quarantine/.
// On the same volume that is a rename — instant, no extra space, ownership
// and modes preserved — and `quarantine restore` moves it all back. The only
// real deletion in the tool is `quarantine purge`, explicitly, per entry.

public struct QuarantineMove: Codable, Equatable, Sendable {
    /// Where it lived (logical absolute path).
    public var original: String
    /// Where it is now, inside the quarantine's `files/` tree.
    public var quarantined: String
    public var kind: String
}

public struct QuarantineManifest: Codable, Equatable, Sendable {
    public var name: String
    /// "uninstall" (V0.8.0); later cleanup kinds reuse the format.
    public var kind: String
    public var createdAt: String
    public var toolVersion: String
    public var packageIdentifier: String?
    public var version: String?
    public var moves: [QuarantineMove]
    /// Copies of the receipt (.bom, .plist) taken before `pkgutil --forget`.
    public var receiptCopies: [String]
    public var forgot: Bool
    /// planned | applied-ok | applied-fail(…) | restored | restore-fail(…)
    public var status: String
    public var notes: [String]
}

public struct QuarantineStore {
    public var root: String
    public var fileManager: FileManager

    public init(root: String, fileManager: FileManager = .default) {
        self.root = root
        self.fileManager = fileManager
    }

    public static let toolVersion = "0.9.0"

    /// A name is one path component of our own making — never a path.
    public static func isValidName(_ name: String) -> Bool {
        !name.isEmpty && !name.hasPrefix(".") && !name.contains("/") && !name.contains("..")
            && name.unicodeScalars.allSatisfy {
                CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_.")).contains($0)
            }
    }

    public func directory(_ name: String) -> String { root + "/" + name }
    public func filesRoot(_ name: String) -> String { directory(name) + "/files" }
    /// Where a logical path lands inside the quarantine.
    public func quarantinedPath(_ name: String, original: String) -> String { filesRoot(name) + original }

    public func makeName(kind: String, subject: String, now: Date = Date()) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd-HHmmss"
        formatter.timeZone = TimeZone(identifier: "UTC")
        let allowed = CharacterSet.alphanumerics.union(CharacterSet(charactersIn: "-_."))
        let cleaned = subject.components(separatedBy: allowed.inverted).joined(separator: "-")
        let base = formatter.string(from: now) + "Z-" + kind + "-" + String(cleaned.prefix(60))
        var name = base
        var counter = 2
        while fileManager.fileExists(atPath: directory(name)) { name = base + "-\(counter)"; counter += 1 }
        return name
    }

    public func write(_ manifest: QuarantineManifest) -> ControlRefusal? {
        do {
            try fileManager.createDirectory(atPath: directory(manifest.name), withIntermediateDirectories: true)
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
            let data = try encoder.encode(manifest)
            try data.write(to: URL(fileURLWithPath: directory(manifest.name) + "/manifest.json"))
            guard fileManager.contents(atPath: directory(manifest.name) + "/manifest.json") == data else {
                return ControlRefusal("quarantine manifest does not read back intact")
            }
            return nil
        } catch {
            return ControlRefusal("cannot write the quarantine manifest: \(error.localizedDescription)")
        }
    }

    public func load(_ name: String) -> QuarantineManifest? {
        guard Self.isValidName(name),
              let data = fileManager.contents(atPath: directory(name) + "/manifest.json") else { return nil }
        return try? JSONDecoder().decode(QuarantineManifest.self, from: data)
    }

    /// Newest first.
    public func list() -> [QuarantineManifest] {
        let names = (try? fileManager.contentsOfDirectory(atPath: root)) ?? []
        return names.sorted(by: >).compactMap { load($0) }
    }
}
