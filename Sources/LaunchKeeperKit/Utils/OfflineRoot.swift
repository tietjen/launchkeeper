import Foundation

// V0.9.1 — offline analysis: `--root <path>` inventories another system —
// a Time Machine backup, a volume in target disk mode, a mounted image —
// from its files alone. Two seams make the existing scanners do that:
// a file manager that reads every absolute path below the root, and a
// runner that lets only file-inspecting tools run (with mapped paths) and
// refuses everything that would describe THIS machine instead.

/// Reads `/x` as `<root>/x`. `/etc`, `/var`, `/tmp` fall back to
/// `<root>/private/…` when the root is a Data volume without the links.
public final class RootedFileManager: FileManager {
    public let root: String

    public init(root: String) {
        self.root = root.hasSuffix("/") && root.count > 1 ? String(root.dropLast()) : root
        super.init()
    }

    public func map(_ path: String) -> String {
        guard path.hasPrefix("/") else { return path }
        if root == "/" { return path }
        if path == root || path.hasPrefix(root + "/") { return path }   // already mapped
        let direct = root + path
        for top in ["/etc", "/var", "/tmp"] where path == top || path.hasPrefix(top + "/") {
            if !super.fileExists(atPath: root + top) { return root + "/private" + path }
        }
        return direct
    }

    public override func fileExists(atPath path: String) -> Bool { super.fileExists(atPath: map(path)) }
    public override func fileExists(atPath path: String, isDirectory: UnsafeMutablePointer<ObjCBool>?) -> Bool {
        super.fileExists(atPath: map(path), isDirectory: isDirectory)
    }
    public override func isReadableFile(atPath path: String) -> Bool { super.isReadableFile(atPath: map(path)) }
    public override func isExecutableFile(atPath path: String) -> Bool { super.isExecutableFile(atPath: map(path)) }
    public override func attributesOfItem(atPath path: String) throws -> [FileAttributeKey: Any] {
        try super.attributesOfItem(atPath: map(path))
    }
    public override func contentsOfDirectory(atPath path: String) throws -> [String] {
        try super.contentsOfDirectory(atPath: map(path))
    }
    public override func contents(atPath path: String) -> Data? { super.contents(atPath: map(path)) }
    /// The link text as stored — an absolute target stays logical and is
    /// mapped again on the next read.
    public override func destinationOfSymbolicLink(atPath path: String) throws -> String {
        try super.destinationOfSymbolicLink(atPath: map(path))
    }
    public override func enumerator(atPath path: String) -> FileManager.DirectoryEnumerator? {
        super.enumerator(atPath: map(path))
    }
    public override func subpathsOfDirectory(atPath path: String) throws -> [String] {
        try super.subpathsOfDirectory(atPath: map(path))
    }

    /// The user homes below the root: `<root>/Users/<name>` with a Library.
    public func homes() -> [String] {
        let names = (try? contentsOfDirectory(atPath: "/Users")) ?? []
        return names.sorted().filter { name in
            guard !name.hasPrefix("."), name != "Shared", name != "Guest" else { return false }
            var isDir: ObjCBool = false
            return fileExists(atPath: "/Users/\(name)/Library", isDirectory: &isDir) && isDir.boolValue
        }.map { "/Users/\($0)" }
    }
}

/// Offline runner: `codesign` and `launchctl plist` read a FILE — they run,
/// with their path arguments mapped into the root. Every other tool reports
/// the live machine (launchctl print, sfltool, pluginkit, lsof, pkgutil,
/// mdfind, security …) and is refused.
public struct OfflineRunner: CommandRunner {
    public let inner: CommandRunner
    public let fileManager: RootedFileManager

    public init(inner: CommandRunner, fileManager: RootedFileManager) {
        self.inner = inner
        self.fileManager = fileManager
    }

    public static func allowed(_ command: String, _ arguments: [String]) -> Bool {
        switch command {
        case "/usr/bin/codesign": return !arguments.contains("--sign") && !arguments.contains("-s")
        case "/bin/launchctl": return arguments.first == "plist"
        default: return false
        }
    }

    public func run(command: String, arguments: [String], timeout: TimeInterval) -> CommandResult {
        guard Self.allowed(command, arguments) else {
            return CommandResult(exitCode: 126, stdout: "", stderr: "offline analysis: \(command) describes the live system — not run")
        }
        let mapped = arguments.map { $0.hasPrefix("/") ? fileManager.map($0) : $0 }
        return inner.run(command: command, arguments: mapped, timeout: timeout)
    }

    public func runInteractive(command: String, arguments: [String], timeout: TimeInterval) -> Int32 { 126 }
}
