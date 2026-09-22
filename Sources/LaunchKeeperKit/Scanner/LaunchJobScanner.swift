import Foundation

/// Scans the three LaunchAgent/LaunchDaemon directories for plist files.
/// Read-only by construction: this type has no way to modify anything.
public struct LaunchJobScanner {
    public struct Directory {
        public var path: String          // may start with "~"
        public var domain: ItemDomain
        public var kind: ItemType
        public init(path: String, domain: ItemDomain, kind: ItemType) {
            self.path = path; self.domain = domain; self.kind = kind
        }
    }

    public static func defaultDirectories(home: String) -> [Directory] {
        [
            Directory(path: home + "/Library/LaunchAgents", domain: .user, kind: .launchAgentUser),
            Directory(path: "/Library/LaunchAgents", domain: .system, kind: .launchAgentSystem),
            Directory(path: "/Library/LaunchDaemons", domain: .system, kind: .launchDaemon),
        ]
    }

    public var directories: [Directory]
    public var fileManager: FileManager

    public init(directories: [Directory]? = nil, fileManager: FileManager = .default) {
        self.directories = directories ?? LaunchJobScanner.defaultDirectories(home: NSHomeDirectory())
        self.fileManager = fileManager
    }

    public func scan() -> (records: [LaunchJobRecord], warnings: [String]) {
        var records: [LaunchJobRecord] = []
        var warnings: [String] = []

        for dir in directories {
            guard let entries = try? fileManager.contentsOfDirectory(atPath: dir.path) else { continue }
            for name in entries.sorted() where name.hasSuffix(".plist") {
                let fullPath = dir.path + "/" + name
                let label = String(name.dropLast(".plist".count))
                do {
                    let dict = try PlistReader.readDictionary(fromFile: fullPath, fileManager: fileManager)
                    let job = PlistReader.extractJob(dict: dict)
                    let owner = PathUtils.ownerInfo(fullPath, fileManager: fileManager)?.name ?? "unknown"
                    records.append(LaunchJobRecord(
                        label: label, path: fullPath, domain: dir.domain, kind: dir.kind,
                        program: job.program, arguments: job.arguments,
                        runAtLoad: job.runAtLoad, keepAlive: job.keepAlive,
                        ownerName: owner, malformed: job.program == nil,
                        parsedKeys: job.unknownKeys,
                        schedule: PlistReader.extractSchedule(dict: dict)
                    ))
                } catch {
                    warnings.append("malformed plist: \(fullPath)")
                }
            }
        }
        return (records, warnings)
    }
}