import Foundation

/// One row of `systemextensionsctl list`.
public struct SystemExtensionRecord: Equatable, Codable {
    /// `network_extension`, `driver_extension`, `cmio`, `endpoint_security`, …
    public var kind: String
    /// The System Settings pane the section header points at, e.g. "Network Extensions".
    public var pane: String?
    public var enabled: Bool
    public var active: Bool
    public var teamIdentifier: String?
    public var bundleIdentifier: String
    public var version: String?
    public var name: String
    /// "[activated enabled]", "[activated waiting for user]", "[terminated waiting to uninstall on reboot]" …
    public var state: String
    /// Filled by the scanner: the installed copy under /Library/SystemExtensions.
    public var installedPath: String?
    /// Filled by the scanner: the host app that ships the extension, when found.
    public var hostAppPath: String?

    public init(kind: String, pane: String? = nil, enabled: Bool, active: Bool, teamIdentifier: String? = nil,
                bundleIdentifier: String, version: String? = nil, name: String, state: String,
                installedPath: String? = nil, hostAppPath: String? = nil) {
        self.kind = kind; self.pane = pane; self.enabled = enabled; self.active = active
        self.teamIdentifier = teamIdentifier; self.bundleIdentifier = bundleIdentifier
        self.version = version; self.name = name; self.state = state
        self.installedPath = installedPath; self.hostAppPath = hostAppPath
    }
}

/// A third-party kernel extension: loaded (kmutil) and/or installed under /Library/Extensions.
public struct KernelExtensionRecord: Equatable, Codable {
    public var bundleIdentifier: String
    public var version: String?
    public var loaded: Bool
    public var path: String?

    public init(bundleIdentifier: String, version: String? = nil, loaded: Bool, path: String? = nil) {
        self.bundleIdentifier = bundleIdentifier; self.version = version; self.loaded = loaded; self.path = path
    }
}

/// Tolerant parser for `systemextensionsctl list` (macOS 27, captured live):
///
///     3 extension(s)
///     --- com.apple.system_extension.network_extension (Go to 'System Settings > General > Login Items & Extensions > Network Extensions' to modify these system extension(s))
///     enabled⇥active⇥teamID⇥bundleID (version)⇥name⇥[state]
///     ⇥*⇥VBG97UB4TA⇥com.example.filter (4.3.1/4.3.1)⇥Filter⇥[activated waiting for user]
public enum SystemExtensionParser {
    public static func parse(_ text: String) -> (records: [SystemExtensionRecord], warnings: [String]) {
        var records: [SystemExtensionRecord] = []
        var warnings: [String] = []
        var kind = "unknown"
        var pane: String?
        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let line = String(rawLine)
            if line.hasPrefix("---") {
                let header = line.dropFirst(3).trimmingCharacters(in: .whitespaces)
                let identifier = header.split(separator: " ", maxSplits: 1).first.map(String.init) ?? header
                kind = identifier.replacingOccurrences(of: "com.apple.system_extension.", with: "")
                if let start = header.range(of: "Login Items & Extensions > "),
                   let end = header.range(of: "'", range: start.upperBound..<header.endIndex) {
                    pane = String(header[start.upperBound..<end.lowerBound])
                } else {
                    pane = nil
                }
                continue
            }
            if line.hasPrefix("enabled\t") || line.hasSuffix("extension(s)") { continue }
            let cols = line.split(separator: "\t", omittingEmptySubsequences: false).map(String.init)
            guard cols.count >= 6 else {
                warnings.append("systemextensionsctl: unparsed line: \(line)")
                continue
            }
            var bundleID = cols[3]
            var version: String?
            if let open = bundleID.range(of: " ("), bundleID.hasSuffix(")") {
                version = String(bundleID[open.upperBound..<bundleID.index(before: bundleID.endIndex)])
                bundleID = String(bundleID[..<open.lowerBound])
            }
            records.append(SystemExtensionRecord(
                kind: kind, pane: pane,
                enabled: cols[0].trimmingCharacters(in: .whitespaces) == "*",
                active: cols[1].trimmingCharacters(in: .whitespaces) == "*",
                teamIdentifier: cols[2].isEmpty ? nil : cols[2],
                bundleIdentifier: bundleID, version: version, name: cols[4],
                state: cols[5...].joined(separator: "\t")))
        }
        return (records, warnings)
    }
}

/// `kmutil showloaded --list-only`: "Index Refs Address Size Wired Name (Version) UUID <Linked Against>".
/// Only non-Apple names are returned — Apple's kernel components are the OS.
public enum KernelExtensionParser {
    public static func parseLoaded(_ text: String) -> [KernelExtensionRecord] {
        var records: [KernelExtensionRecord] = []
        for rawLine in text.split(separator: "\n") {
            let tokens = rawLine.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard tokens.count >= 6, Int(tokens[0]) != nil else { continue }
            let name = tokens[5]
            guard name.contains("."), !name.hasPrefix("com.apple.") else { continue }
            var version: String?
            if tokens.count > 6, tokens[6].hasPrefix("("), tokens[6].hasSuffix(")") {
                version = String(tokens[6].dropFirst().dropLast())
            }
            records.append(KernelExtensionRecord(bundleIdentifier: name, version: version, loaded: true))
        }
        return records
    }
}

/// Read-only scan of system extensions (systemextensionsctl + the installed
/// copies under /Library/SystemExtensions + the host app in /Applications)
/// and third-party kernel extensions (kmutil + /Library/Extensions).
public struct SystemExtensionScanner {
    public var runner: CommandRunner
    public var fileManager: FileManager
    public var extensionsRoot: String
    public var legacyKextDirectory: String
    public var applicationDirectories: [String]
    public var timeout: TimeInterval = 30

    public struct Result {
        public var extensions: [SystemExtensionRecord]
        public var kexts: [KernelExtensionRecord]
        public var warnings: [String]
        public var checks: [String]
        /// Item-contributing sources that did not answer.
        public var failed: [String]
    }

    public init(runner: CommandRunner, fileManager: FileManager = .default, home: String = NSHomeDirectory(),
                extensionsRoot: String = "/Library/SystemExtensions",
                legacyKextDirectory: String = "/Library/Extensions",
                applicationDirectories: [String]? = nil) {
        self.runner = runner
        self.fileManager = fileManager
        self.extensionsRoot = extensionsRoot
        self.legacyKextDirectory = legacyKextDirectory
        self.applicationDirectories = applicationDirectories ?? ["/Applications", home + "/Applications"]
    }

    public func scan() -> Result {
        var warnings: [String] = []
        var checks: [String] = []
        var failed: [String] = []

        // 1. systemextensionsctl list
        var extensions: [SystemExtensionRecord] = []
        let listed = runner.run(command: "/usr/bin/systemextensionsctl", arguments: ["list"], timeout: timeout)
        if listed.exitCode == 0 {
            let (records, parseWarnings) = SystemExtensionParser.parse(listed.stdout)
            extensions = records
            warnings.append(contentsOf: parseWarnings.prefix(10))
            checks.append("systemextensionsctl list: ok (\(records.count) extensions, "
                + "\(records.filter { $0.enabled }.count) enabled)")
        } else {
            warnings.append("systemextensionsctl list failed (exit \(listed.exitCode)) — system extensions not scanned")
            checks.append("systemextensionsctl list: FAILED (exit \(listed.exitCode))")
            failed.append("systemextensionsctl")
        }

        // 2. installed copies: /Library/SystemExtensions/<uuid>/<bundleID>.(systemextension|dext)
        var installed: [String: String] = [:]
        if let uuids = try? fileManager.contentsOfDirectory(atPath: extensionsRoot) {
            for uuid in uuids where !uuid.hasPrefix(".") {
                let dir = extensionsRoot + "/" + uuid
                for entry in (try? fileManager.contentsOfDirectory(atPath: dir)) ?? [] {
                    let id = (entry as NSString).deletingPathExtension
                    installed[id] = dir + "/" + entry
                }
            }
        }
        // 3. host app: <App>.app/Contents/Library/SystemExtensions/<bundleID>.<ext>
        var apps: [String] = []
        for appDir in applicationDirectories {
            for entry in (try? fileManager.contentsOfDirectory(atPath: appDir)) ?? [] where entry.hasSuffix(".app") {
                apps.append(appDir + "/" + entry)
            }
        }
        for index in extensions.indices {
            let id = extensions[index].bundleIdentifier
            extensions[index].installedPath = installed[id]
            let ext = installed[id].map { ($0 as NSString).pathExtension } ?? "systemextension"
            for app in apps {
                let candidate = app + "/Contents/Library/SystemExtensions/" + id + "." + ext
                if fileManager.fileExists(atPath: candidate) {
                    extensions[index].hostAppPath = app
                    break
                }
            }
            if extensions[index].hostAppPath == nil {
                // Spotlight as the fallback: the host app may live elsewhere.
                let found = runner.run(command: "/usr/bin/mdfind",
                                       arguments: ["kMDItemCFBundleIdentifier == '\(id)'"], timeout: 15)
                if found.exitCode == 0,
                   let hit = found.stdout.split(separator: "\n").map(String.init)
                       .first(where: { $0.contains(".app/Contents/Library/SystemExtensions/") }),
                   let app = AppContextResolver.enclosingAppBundle(path: hit) {
                    extensions[index].hostAppPath = app
                }
            }
        }

        // 4. kernel extensions: loaded (kmutil) + installed (/Library/Extensions)
        var kexts: [KernelExtensionRecord] = []
        let loaded = runner.run(command: "/usr/bin/kmutil", arguments: ["showloaded", "--list-only"], timeout: timeout)
        if loaded.exitCode == 0 {
            kexts = KernelExtensionParser.parseLoaded(loaded.stdout)
            checks.append("kmutil showloaded: ok (\(kexts.count) third-party kexts loaded)")
        } else {
            warnings.append("kmutil showloaded failed (exit \(loaded.exitCode)) — loaded kexts unknown")
            checks.append("kmutil showloaded: FAILED (exit \(loaded.exitCode))")
            failed.append("kmutil")
        }
        for entry in (try? fileManager.contentsOfDirectory(atPath: legacyKextDirectory)) ?? [] where entry.hasSuffix(".kext") {
            let path = legacyKextDirectory + "/" + entry
            let info = try? PlistReader.readDictionary(fromFile: path + "/Contents/Info.plist", fileManager: fileManager)
            let id = (info?["CFBundleIdentifier"] as? String) ?? (entry as NSString).deletingPathExtension
            let version = info?["CFBundleShortVersionString"] as? String ?? info?["CFBundleVersion"] as? String
            if let index = kexts.firstIndex(where: { $0.bundleIdentifier == id }) {
                kexts[index].path = path
                if kexts[index].version == nil { kexts[index].version = version }
            } else {
                kexts.append(KernelExtensionRecord(bundleIdentifier: id, version: version, loaded: false, path: path))
            }
        }
        return Result(extensions: extensions, kexts: kexts, warnings: warnings, checks: checks, failed: failed)
    }
}
