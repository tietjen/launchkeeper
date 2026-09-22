import Foundation

// V0.5.6 — G "Legacy": loginwindow hooks, /Library/StartupItems, rc.local &
// friends, emond rules. Everything here is either a leftover of a mechanism
// macOS no longer runs or an unusual place to persist — worth a look.

public struct LoginHookRecord: Equatable, Sendable {
    public var kind: String          // LoginHook / LogoutHook
    public var script: String
    public var source: String        // the loginwindow plist that sets it
    public var domain: ItemDomain
    public init(kind: String, script: String, source: String, domain: ItemDomain) {
        self.kind = kind; self.script = script; self.source = source; self.domain = domain
    }
}

public struct StartupItemRecord: Equatable, Sendable {
    public var name: String
    public var directory: String
    public var script: String?       // <directory>/<name>, when present
    public var description: String?
    public var provides: [String]
    public var hasParameters: Bool   // StartupParameters.plist present
    public init(name: String, directory: String, script: String? = nil, description: String? = nil,
                provides: [String] = [], hasParameters: Bool = false) {
        self.name = name; self.directory = directory; self.script = script
        self.description = description; self.provides = provides; self.hasParameters = hasParameters
    }
}

public struct LegacyFileRecord: Equatable, Sendable {
    public var kind: String          // rc-script / launchd-conf / emond-rule
    public var path: String
    public init(kind: String, path: String) { self.kind = kind; self.path = path }
}

public struct LegacyScanner {
    public struct Result {
        public var hooks: [LoginHookRecord] = []
        public var startupItems: [StartupItemRecord] = []
        public var files: [LegacyFileRecord] = []
        public var warnings: [String] = []
        public var checks: [String] = []
        public init() {}
    }

    let fileManager: FileManager
    let loginwindowPlists: [(path: String, domain: ItemDomain)]
    let startupItemsDirectories: [String]
    let legacyFiles: [(kind: String, path: String)]
    let emondRulesDirectory: String

    public init(fileManager: FileManager = .default, home: String = NSHomeDirectory(),
                loginwindowPlists: [(path: String, domain: ItemDomain)]? = nil,
                startupItemsDirectories: [String] = ["/Library/StartupItems"],
                legacyFiles: [(kind: String, path: String)] = [
                    ("rc-script", "/etc/rc.local"), ("rc-script", "/etc/rc.shutdown.local"),
                    ("launchd-conf", "/etc/launchd.conf")],
                emondRulesDirectory: String = "/etc/emond.d/rules") {
        self.fileManager = fileManager
        self.loginwindowPlists = loginwindowPlists ?? [
            ("/Library/Preferences/com.apple.loginwindow.plist", .system),
            (home + "/Library/Preferences/com.apple.loginwindow.plist", .user)]
        self.startupItemsDirectories = startupItemsDirectories
        self.legacyFiles = legacyFiles
        self.emondRulesDirectory = emondRulesDirectory
    }

    public func scan() -> Result {
        var result = Result()

        for plist in loginwindowPlists {
            guard fileManager.isReadableFile(atPath: plist.path),
                  let dict = try? PlistReader.readDictionary(fromFile: plist.path, fileManager: fileManager) else { continue }
            for kind in ["LoginHook", "LogoutHook"] {
                if let script = dict[kind] as? String, !script.isEmpty {
                    result.hooks.append(LoginHookRecord(kind: kind, script: script, source: plist.path, domain: plist.domain))
                }
            }
        }
        result.checks.append("loginwindow hooks: \(result.hooks.count)")

        for root in startupItemsDirectories {
            guard let names = try? fileManager.contentsOfDirectory(atPath: root) else { continue }
            for name in names.sorted() where !name.hasPrefix(".") {
                let dir = root + "/" + name
                var isDir: ObjCBool = false
                guard fileManager.fileExists(atPath: dir, isDirectory: &isDir), isDir.boolValue else { continue }
                var record = StartupItemRecord(name: name, directory: dir)
                let script = dir + "/" + name
                if fileManager.fileExists(atPath: script) { record.script = script }
                let params = dir + "/StartupParameters.plist"
                if let dict = try? PlistReader.readDictionary(fromFile: params, fileManager: fileManager) {
                    record.hasParameters = true
                    record.description = dict["Description"] as? String
                    record.provides = (dict["Provides"] as? [String]) ?? []
                }
                result.startupItems.append(record)
            }
        }
        result.checks.append("StartupItems: \(result.startupItems.count)")

        for file in legacyFiles where fileManager.fileExists(atPath: file.path) {
            result.files.append(LegacyFileRecord(kind: file.kind, path: file.path))
        }
        if let rules = try? fileManager.contentsOfDirectory(atPath: emondRulesDirectory) {
            for name in rules.sorted() where name.hasSuffix(".plist") && name != "SampleRules.plist" {
                result.files.append(LegacyFileRecord(kind: "emond-rule", path: emondRulesDirectory + "/" + name))
            }
        }
        result.checks.append("rc/launchd.conf/emond: \(result.files.count) files")
        return result
    }
}
