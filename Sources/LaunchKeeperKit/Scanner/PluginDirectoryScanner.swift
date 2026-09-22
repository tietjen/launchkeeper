import Foundation

// V0.5.6 — I "Plugin directories": bundles that the OS or an app loads by
// location — authorization plugins, HAL audio drivers, Spotlight importers,
// QuickLook generators, input methods, Internet plug-ins, screen savers,
// preference panes, scripting additions, color pickers. Authorization
// plugins are checked against the login mechanism chain.

public struct PluginBundleRecord: Equatable, Sendable {
    public var kind: String
    public var path: String
    public var name: String              // bundle file name without extension
    public var bundleIdentifier: String?
    public var version: String?
    public var domain: ItemDomain
    /// Authorization plugins only: referenced by `system.login.console`.
    public var wiredIntoLogin: Bool?
    public init(kind: String, path: String, name: String, bundleIdentifier: String? = nil, version: String? = nil,
                domain: ItemDomain, wiredIntoLogin: Bool? = nil) {
        self.kind = kind; self.path = path; self.name = name; self.bundleIdentifier = bundleIdentifier
        self.version = version; self.domain = domain; self.wiredIntoLogin = wiredIntoLogin
    }
}

public struct PluginDirectory: Sendable {
    public var kind: String
    public var path: String
    public var domain: ItemDomain
    public init(kind: String, path: String, domain: ItemDomain) { self.kind = kind; self.path = path; self.domain = domain }

    public static func defaults(home: String) -> [PluginDirectory] {
        var dirs: [PluginDirectory] = [
            PluginDirectory(kind: "authorization", path: "/Library/Security/SecurityAgentPlugins", domain: .system),
            PluginDirectory(kind: "audio-hal", path: "/Library/Audio/Plug-Ins/HAL", domain: .system),
        ]
        for (kind, sub) in [("spotlight", "Spotlight"), ("quicklook", "QuickLook"), ("input-method", "Input Methods"),
                            ("internet-plugin", "Internet Plug-Ins"), ("screen-saver", "Screen Savers"),
                            ("prefpane", "PreferencePanes"), ("scripting-addition", "ScriptingAdditions"),
                            ("color-picker", "ColorPickers")] {
            dirs.append(PluginDirectory(kind: kind, path: "/Library/" + sub, domain: .system))
            dirs.append(PluginDirectory(kind: kind, path: home + "/Library/" + sub, domain: .user))
        }
        return dirs
    }
}

public enum AuthorizationMechanismParser {
    /// `security authorizationdb read <right>` prints an XML plist; the
    /// `mechanisms` array names "<Plugin>:<mechanism>[,privileged]".
    public static func pluginNames(_ text: String) -> [String] {
        guard let data = text.data(using: .utf8),
              let dict = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let mechanisms = dict["mechanisms"] as? [String] else { return [] }
        return mechanisms.compactMap { $0.split(separator: ":").first.map(String.init) }
    }
}

public struct PluginDirectoryScanner {
    public struct Result {
        public var plugins: [PluginBundleRecord] = []
        public var warnings: [String] = []
        public var checks: [String] = []
        public init() {}
    }

    let runner: CommandRunner
    let fileManager: FileManager
    let directories: [PluginDirectory]

    public init(runner: CommandRunner, fileManager: FileManager = .default, home: String = NSHomeDirectory(),
                directories: [PluginDirectory]? = nil) {
        self.runner = runner; self.fileManager = fileManager
        self.directories = directories ?? PluginDirectory.defaults(home: home)
    }

    public func scan() -> Result {
        var result = Result()
        var loginPlugins: Set<String>?
        if directories.contains(where: { $0.kind == "authorization" }) {
            let auth = runner.run(command: "/usr/bin/security", arguments: ["authorizationdb", "read", "system.login.console"])
            if auth.exitCode == 0 {
                let names = AuthorizationMechanismParser.pluginNames(auth.stdout)
                loginPlugins = Set(names)
                result.checks.append("authorizationdb system.login.console: ok (\(names.count) mechanisms)")
            } else {
                result.warnings.append("authorizationdb unreadable (exit \(auth.exitCode)) — "
                    + "authorization plugins listed without their login wiring")
                result.checks.append("authorizationdb system.login.console: FAILED (exit \(auth.exitCode))")
            }
        }

        var scanned = 0
        for dir in directories {
            guard let names = try? fileManager.contentsOfDirectory(atPath: dir.path) else { continue }
            scanned += 1
            for name in names.sorted() where !name.hasPrefix(".") && name.contains(".") {
                let path = dir.path + "/" + name
                var isDir: ObjCBool = false
                guard fileManager.fileExists(atPath: path, isDirectory: &isDir), isDir.boolValue else { continue }
                let base = (name as NSString).deletingPathExtension
                var record = PluginBundleRecord(kind: dir.kind, path: path, name: base, domain: dir.domain)
                if let info = try? PlistReader.readDictionary(fromFile: path + "/Contents/Info.plist", fileManager: fileManager) {
                    record.bundleIdentifier = info["CFBundleIdentifier"] as? String
                    record.version = (info["CFBundleShortVersionString"] as? String) ?? (info["CFBundleVersion"] as? String)
                }
                if dir.kind == "authorization", let loginPlugins {
                    record.wiredIntoLogin = loginPlugins.contains(base)
                }
                result.plugins.append(record)
            }
        }
        result.checks.append("plugin directories: \(result.plugins.count) bundles in \(scanned) directories")
        return result
    }
}
