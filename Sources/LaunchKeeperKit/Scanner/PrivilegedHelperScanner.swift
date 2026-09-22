import Foundation

/// One binary under /Library/PrivilegedHelperTools (SMJobBless helpers).
public struct PrivilegedHelperRecord: Equatable, Codable {
    public var path: String
    public var name: String
    public var bundleIdentifier: String?
    public var version: String?
    /// Bundle identifiers named in `SMAuthorizedClients` — the apps allowed
    /// to talk to this helper, i.e. its owners.
    public var authorizedClients: [String]
    /// Whether the binary carries an embedded Info.plist at all.
    public var hasInfoPlist: Bool
    /// Filled by the scanner: where the first authorized client app lives, when found.
    public var clientAppPath: String?

    public init(path: String, name: String, bundleIdentifier: String? = nil, version: String? = nil,
                authorizedClients: [String] = [], hasInfoPlist: Bool = false, clientAppPath: String? = nil) {
        self.path = path; self.name = name; self.bundleIdentifier = bundleIdentifier; self.version = version
        self.authorizedClients = authorizedClients; self.hasInfoPlist = hasInfoPlist; self.clientAppPath = clientAppPath
    }
}

/// Parses `launchctl plist __TEXT,__info_plist <binary>` — an OpenStep-style
/// dump of the embedded Info.plist:
///
///     {
///         "CFBundleIdentifier" = "com.example.helper";
///         "SMAuthorizedClients" = (
///             "identifier "com.example.app" and anchor apple generic and …";
///         );
///         "CFBundleVersion" = "1.2";
///     };
public enum EmbeddedInfoPlistParser {
    private static let identifierRequirement = try! NSRegularExpression(pattern: #"identifier "([^"]+)""#)

    public static func parse(_ text: String) -> (bundleIdentifier: String?, version: String?, clients: [String]) {
        func value(_ key: String) -> String? {
            guard let range = text.range(of: "\"\(key)\" = \"") else { return nil }
            let rest = text[range.upperBound...]
            guard let end = rest.range(of: "\";") else { return nil }
            return String(rest[..<end.lowerBound])
        }
        var clients: [String] = []
        if let block = text.range(of: "\"SMAuthorizedClients\" = (") {
            let rest = String(text[block.upperBound...])
            let body = rest.range(of: ");").map { String(rest[..<$0.lowerBound]) } ?? rest
            let range = NSRange(body.startIndex..., in: body)
            for match in identifierRequirement.matches(in: body, range: range) {
                if let r = Range(match.range(at: 1), in: body) {
                    let id = String(body[r])
                    if !clients.contains(id) { clients.append(id) }
                }
            }
        }
        return (value("CFBundleIdentifier"), value("CFBundleVersion"), clients)
    }
}

/// Read-only scan of /Library/PrivilegedHelperTools: every binary, its
/// embedded Info.plist (via `launchctl plist`, no root needed) and the
/// location of its first authorized client app (Spotlight).
public struct PrivilegedHelperScanner {
    public var runner: CommandRunner
    public var fileManager: FileManager
    public var directory: String
    public var timeout: TimeInterval = 15

    public struct Result {
        public var helpers: [PrivilegedHelperRecord]
        public var warnings: [String]
        public var checks: [String]
        public var failed: [String]
    }

    public init(runner: CommandRunner, fileManager: FileManager = .default,
                directory: String = "/Library/PrivilegedHelperTools") {
        self.runner = runner; self.fileManager = fileManager; self.directory = directory
    }

    public func scan() -> Result {
        var helpers: [PrivilegedHelperRecord] = []
        let warnings: [String] = []
        guard fileManager.fileExists(atPath: directory) else {
            return Result(helpers: [], warnings: [], checks: ["privileged helpers: none (\(directory) absent)"], failed: [])
        }
        guard let entries = try? fileManager.contentsOfDirectory(atPath: directory) else {
            return Result(helpers: [], warnings: ["\(directory) unreadable — privileged helpers not scanned"],
                          checks: ["privileged helpers: FAILED (unreadable)"], failed: ["privileged-helpers"])
        }
        var clientCache: [String: String?] = [:]
        for entry in entries.sorted() where !entry.hasPrefix(".") {
            let path = directory + "/" + entry
            var isDir: ObjCBool = false
            guard fileManager.fileExists(atPath: path, isDirectory: &isDir), !isDir.boolValue else { continue }
            let plist = runner.run(command: "/bin/launchctl", arguments: ["plist", "__TEXT,__info_plist", path],
                                   timeout: timeout)
            var record = PrivilegedHelperRecord(path: path, name: entry)
            if plist.exitCode == 0, plist.stdout.contains("CFBundleIdentifier") {
                let parsed = EmbeddedInfoPlistParser.parse(plist.stdout)
                record.bundleIdentifier = parsed.bundleIdentifier
                record.version = parsed.version
                record.authorizedClients = parsed.clients
                record.hasInfoPlist = true
            }
            // The first authorized client is the helper's owner; find it once.
            if let client = record.authorizedClients.first {
                if let cached = clientCache[client] {
                    record.clientAppPath = cached
                } else {
                    let found = runner.run(command: "/usr/bin/mdfind",
                                           arguments: ["kMDItemCFBundleIdentifier == '\(client)'"], timeout: timeout)
                    let hit = found.exitCode == 0
                        ? found.stdout.split(separator: "\n").map(String.init).first(where: { $0.hasSuffix(".app") })
                        : nil
                    clientCache[client] = hit
                    record.clientAppPath = hit
                }
            }
            helpers.append(record)
        }
        let orphans = helpers.filter { !$0.hasInfoPlist }.count
        return Result(helpers: helpers, warnings: warnings,
                      checks: ["privileged helpers: \(helpers.count) in \(directory)"
                               + (orphans > 0 ? " (\(orphans) without embedded Info.plist)" : "")],
                      failed: [])
    }
}
