import Foundation

// V0.6.0 — J "Provenance": package receipts. `pkgutil` knows which installer
// package put a file where; launchkeeper indexes every non-Apple receipt's
// file list once per scan and attributes items to packages by path. The
// same index answers `launchkeeper receipts`: what is installed, since
// when, how much of it is still there, and which entries it runs.

public struct ReceiptRecord: Equatable, Sendable {
    public var id: String
    public var version: String?
    public var installTime: Date?
    public var volume: String
    public var location: String
    /// Absolute paths the receipt lists (files and directories).
    public var files: [String]
    public init(id: String, version: String? = nil, installTime: Date? = nil, volume: String = "/",
                location: String = "/", files: [String] = []) {
        self.id = id; self.version = version; self.installTime = installTime
        self.volume = volume; self.location = location; self.files = files
    }
    public var isApple: Bool { id.hasPrefix("com.apple.") }
}

public enum ReceiptInfoParser {
    public struct Info: Equatable {
        public var version: String?
        public var installTime: Date?
        public var volume: String
        public var location: String
    }

    /// `pkgutil --pkg-info-plist <id>`: pkg-version, install-time (epoch),
    /// volume, install-location.
    public static func parse(_ text: String) -> Info? {
        guard let data = text.data(using: .utf8),
              let dict = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        else { return nil }
        var time: Date?
        if let epoch = dict["install-time"] as? Int { time = Date(timeIntervalSince1970: TimeInterval(epoch)) }
        else if let epoch = dict["install-time"] as? Double { time = Date(timeIntervalSince1970: epoch) }
        return Info(version: dict["pkg-version"] as? String, installTime: time,
                    volume: (dict["volume"] as? String) ?? "/",
                    location: (dict["install-location"] as? String) ?? "/")
    }

    /// Joins volume, install location and a receipt-relative path.
    public static func absolutePath(volume: String, location: String, relative: String) -> String {
        var parts: [String] = []
        for piece in [volume, location, relative] {
            let trimmed = piece.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            if !trimmed.isEmpty { parts.append(trimmed) }
        }
        return "/" + parts.joined(separator: "/")
    }
}

public struct ReceiptIndex: Sendable {
    public var receipts: [String: ReceiptRecord] = [:]
    /// Absolute path → package id, for paths exactly one receipt lists.
    var owners: [String: String] = [:]
    /// Paths two or more receipts list (Applications, Library/LaunchDaemons …).
    var shared: Set<String> = []

    public init() {}
    public init(receipts: [ReceiptRecord]) {
        for receipt in receipts { add(receipt) }
    }

    public mutating func add(_ receipt: ReceiptRecord) {
        receipts[receipt.id] = receipt
        for path in receipt.files {
            // AppleDouble side files ("._x") are listed but never on APFS.
            if (path as NSString).lastPathComponent.hasPrefix("._") { continue }
            if let existing = owners[path], existing != receipt.id { shared.insert(path) }
            owners[path] = receipt.id
        }
    }

    public var isEmpty: Bool { receipts.isEmpty }
    public var fileCount: Int { owners.count }

    /// Directories many packages write into confer no ownership, even when
    /// only one receipt on this machine happens to list them: everything
    /// up to two levels deep (/Applications, /Library/LaunchDaemons,
    /// /usr/local), the standard plug-in and support roots, and a user's
    /// ~/Library tree down to its first level. A bundle (a name with an
    /// extension) is never shared by depth: /Applications/Tool.app is one
    /// package's.
    static let sharedRoots: Set<String> = [
        "/Library/Application Support", "/Library/Preferences", "/Library/Frameworks", "/Library/Extensions",
        "/Library/Audio/Plug-Ins", "/Library/Audio/Plug-Ins/HAL", "/Library/Audio/Plug-Ins/Components",
        "/Library/Audio/Plug-Ins/VST", "/Library/Audio/Plug-Ins/VST3", "/Library/Internet Plug-Ins",
        "/Library/PreferencePanes", "/Library/QuickLook", "/Library/Spotlight", "/Library/Input Methods",
        "/Library/Screen Savers", "/Library/ScriptingAdditions", "/Library/Security/SecurityAgentPlugins",
        "/Library/PrivilegedHelperTools", "/Library/SystemExtensions", "/Library/Application Support/Adobe",
        "/usr/local/bin", "/usr/local/lib", "/usr/local/share", "/usr/local/share/man", "/usr/local/etc",
        "/usr/local/include", "/usr/local/sbin", "/usr/local/opt", "/private/etc", "/private/etc/paths.d",
        "/etc/paths.d", "/private/var", "/private/var/db", "/var/db",
    ]

    static func isSharedRoot(_ path: String) -> Bool {
        if sharedRoots.contains(path) { return true }
        let components = path.split(separator: "/").map(String.init)
        guard let last = components.last else { return true }
        if last.contains(".") { return false }
        if components.count <= 2 { return true }
        if components.first == "Users", components.count <= 4 { return true }
        return false
    }

    /// The package that owns a path: the path itself when exactly one
    /// receipt lists it, else the nearest listed ancestor — unless that
    /// ancestor is shared, in which case nobody owns the path.
    public func owner(forPath path: String) -> String? {
        var probe = path
        while true {
            if let id = owners[probe] {
                if shared.contains(probe) || Self.isSharedRoot(probe) { return nil }
                return id
            }
            let parent = (probe as NSString).deletingLastPathComponent
            if parent.isEmpty || parent == probe || parent == "/" { return nil }
            probe = parent
        }
    }

    public func receipt(forPath path: String) -> ReceiptRecord? {
        owner(forPath: path).flatMap { receipts[$0] }
    }
}

public struct ReceiptScanner {
    public struct Result {
        public var index = ReceiptIndex()
        public var warnings: [String] = []
        public var checks: [String] = []
        public var failed = false
        public init() {}
    }

    let runner: CommandRunner
    let includeApple: Bool

    public init(runner: CommandRunner, includeApple: Bool = false) {
        self.runner = runner; self.includeApple = includeApple
    }

    public func scan() -> Result {
        var result = Result()
        let list = runner.run(command: "/usr/sbin/pkgutil", arguments: ["--pkgs"])
        guard list.exitCode == 0 else {
            result.failed = true
            result.warnings.append("package receipts not indexed: pkgutil --pkgs exit \(list.exitCode): "
                + list.stderr.trimmingCharacters(in: .whitespacesAndNewlines))
            result.checks.append("pkgutil: FAILED (exit \(list.exitCode))")
            return result
        }
        let all = list.stdout.components(separatedBy: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        let wanted = includeApple ? all : all.filter { !$0.hasPrefix("com.apple.") }
        var unreadable = 0
        for id in wanted {
            let info = runner.run(command: "/usr/sbin/pkgutil", arguments: ["--pkg-info-plist", id])
            guard info.exitCode == 0, let parsed = ReceiptInfoParser.parse(info.stdout) else { unreadable += 1; continue }
            let files = runner.run(command: "/usr/sbin/pkgutil", arguments: ["--files", id])
            let relative = files.exitCode == 0
                ? files.stdout.components(separatedBy: "\n").filter { !$0.isEmpty }
                : []
            let absolute = relative.map {
                ReceiptInfoParser.absolutePath(volume: parsed.volume, location: parsed.location, relative: $0)
            }
            result.index.add(ReceiptRecord(id: id, version: parsed.version, installTime: parsed.installTime,
                                           volume: parsed.volume, location: parsed.location, files: absolute))
        }
        if unreadable > 0 { result.warnings.append("\(unreadable) package receipts unreadable (pkgutil --pkg-info-plist)") }
        result.checks.append("pkgutil: ok (\(all.count) receipts, \(wanted.count) indexed"
            + (includeApple ? "" : " non-Apple") + ", \(result.index.fileCount) paths)")
        return result
    }
}
