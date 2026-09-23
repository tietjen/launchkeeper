import Foundation

// V0.6.1 — inventory snapshots: the whole item list of one scan, saved as
// JSON under ~/Library/Application Support/launchkeeper/inventory/. A
// snapshot is what `diff` compares against. Distinct from the remediation
// backups (plists before a delete) and the BTM dumps (before a reset).

public struct InventorySnapshot: Codable {
    public var format: Int = 1
    public var tool: String
    public var version: String
    public var createdAt: String
    public var host: String
    public var name: String?
    public var incompleteLayers: [String]
    public var items: [BackgroundItem]

    public init(tool: String = LaunchKeeperPaths.productName, version: String, createdAt: Date = Date(),
                host: String, name: String? = nil, incompleteLayers: [String], items: [BackgroundItem]) {
        self.tool = tool; self.version = version
        self.createdAt = ISO8601DateFormatter().string(from: createdAt)
        self.host = host; self.name = name; self.incompleteLayers = incompleteLayers; self.items = items
    }
}

public struct InventorySnapshotStore {
    public struct Entry: Codable, Equatable {
        public var file: String
        public var createdAt: String
        public var name: String?
        public var itemCount: Int
        public var incomplete: Bool
        public var version: String
    }

    let root: String
    let fileManager: FileManager

    public init(root: String, fileManager: FileManager = .default) {
        self.root = root; self.fileManager = fileManager
    }
    public init(home: String, fileManager: FileManager = .default) {
        self.init(root: LaunchKeeperPaths.inventorySnapshots(home: home), fileManager: fileManager)
    }

    static func stamp(_ date: Date) -> String {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyy-MM-dd-HHmmss'Z'"
        return f.string(from: date)
    }

    static func safeName(_ name: String) -> String {
        String(name.map { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" ? $0 : "-" })
    }

    /// Writes the snapshot; the directory is created explicitly and a
    /// failure is an error, never a silent no-op.
    @discardableResult
    public func save(_ snapshot: InventorySnapshot, at date: Date = Date()) throws -> String {
        try fileManager.createDirectory(atPath: root, withIntermediateDirectories: true)
        var base = Self.stamp(date)
        if let name = snapshot.name, !name.isEmpty { base += "-" + Self.safeName(name) }
        let path = root + "/" + base + ".json"
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(snapshot).write(to: URL(fileURLWithPath: path), options: .atomic)
        return path
    }

    /// Newest first.
    public func list() -> [Entry] {
        guard let names = try? fileManager.contentsOfDirectory(atPath: root) else { return [] }
        var entries: [Entry] = []
        for name in names.sorted().reversed() where name.hasSuffix(".json") {
            let path = root + "/" + name
            guard let snapshot = try? load(path: path) else { continue }
            entries.append(Entry(file: path, createdAt: snapshot.createdAt, name: snapshot.name,
                                 itemCount: snapshot.items.count, incomplete: !snapshot.incompleteLayers.isEmpty,
                                 version: snapshot.version))
        }
        return entries
    }

    public func latest() -> Entry? { list().first }

    /// Loads a snapshot file — or a bare `list --json` array, wrapped.
    public func load(path: String) throws -> InventorySnapshot {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        let decoder = JSONDecoder()
        if let snapshot = try? decoder.decode(InventorySnapshot.self, from: data) { return snapshot }
        let items = try decoder.decode([BackgroundItem].self, from: data)
        return InventorySnapshot(version: "unknown", host: "unknown", name: (path as NSString).lastPathComponent,
                                 incompleteLayers: [], items: items)
    }

    /// Resolves what the user typed: a path, a snapshot's file name, or a
    /// name given at save time. nil = the latest snapshot.
    public func resolve(_ reference: String?) -> String? {
        guard let reference, !reference.isEmpty else { return latest()?.file }
        if fileManager.fileExists(atPath: reference) { return reference }
        let candidates = list()
        if let hit = candidates.first(where: { ($0.file as NSString).lastPathComponent == reference
            || ($0.file as NSString).lastPathComponent == reference + ".json" }) { return hit.file }
        return candidates.first { $0.name == reference }?.file
    }
}
