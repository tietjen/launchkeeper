import Foundation

// V0.8.2 — what apps leave behind after they are gone: preferences, caches,
// support folders, saved state, containers. This is user data, so the bar is
// higher than anywhere else in launchkeeper: an entry counts only when its
// name IS a bundle identifier, and the app counts as gone only when three
// independent sources agree — LaunchServices, Spotlight and a walk of the
// application folders — and nothing running or installed claims the id. A
// source that cannot answer makes the verdict "unknown", never "gone".

/// One place apps leave data, named by bundle id.
public struct LeftoverLocation: Sendable {
    /// Directory relative to the user's home ("Library/Caches") or absolute ("/Library/Caches").
    public var directory: String
    /// Suffix the entry carries after the bundle id (".plist", ".savedState", "").
    public var suffix: String
    public var kind: String

    public var isSystem: Bool { directory.hasPrefix("/") }
}

public enum AppLeftoverLocations {
    public static let all: [LeftoverLocation] = [
        .init(directory: "Library/Application Support", suffix: "", kind: "application-support"),
        .init(directory: "Library/Caches", suffix: "", kind: "caches"),
        .init(directory: "Library/Preferences", suffix: ".plist", kind: "preferences"),
        .init(directory: "Library/Saved Application State", suffix: ".savedState", kind: "saved-state"),
        .init(directory: "Library/HTTPStorages", suffix: "", kind: "http-storage"),
        .init(directory: "Library/HTTPStorages", suffix: ".binarycookies", kind: "http-cookies"),
        .init(directory: "Library/WebKit", suffix: "", kind: "webkit"),
        .init(directory: "Library/Logs", suffix: "", kind: "logs"),
        .init(directory: "Library/Cookies", suffix: ".binarycookies", kind: "cookies"),
        .init(directory: "Library/Containers", suffix: "", kind: "container"),
        .init(directory: "Library/Application Scripts", suffix: "", kind: "application-scripts"),
        .init(directory: "/Library/Application Support", suffix: "", kind: "application-support"),
        .init(directory: "/Library/Caches", suffix: "", kind: "caches"),
        .init(directory: "/Library/Preferences", suffix: ".plist", kind: "preferences"),
        .init(directory: "/Library/Logs", suffix: "", kind: "logs"),
    ]

    /// Reverse-DNS with at least three parts: "com.vendor.app". Folder names
    /// like "Google" or "Adobe" never qualify — they are not provably one app's.
    public static func isBundleIdentifier(_ name: String) -> Bool {
        let parts = name.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count >= 3, name.count <= 155 else { return false }
        return parts.allSatisfy { part in
            !part.isEmpty && part.unicodeScalars.allSatisfy {
                CharacterSet.alphanumerics.contains($0) || $0 == "-" || $0 == "_"
            }
        }
    }

    /// Never a leftover, whatever the sources say (live 2026-09-26: the
    /// first report listed org.cups.printers — the system's printer setup).
    /// Apple anywhere in the id, group containers, CUPS, and names whose
    /// parts are file-name debris ("warp.log.old.0", "main.kts.compiled.cache").
    public static func isExcluded(_ id: String) -> Bool {
        let lower = id.lowercased()
        if lower.contains("com.apple") || lower.hasPrefix("systemgroup.") || lower.hasPrefix("group.")
            || lower.hasPrefix("org.cups.") || lower.hasPrefix("org.sparkle-project.") { return true }
        // "MN5S649TXM.ZitiPacketTunnel.group": a Team-ID-scoped app group,
        // shared by a vendor's apps — not one app's (live: Ziti, Things).
        if let first = id.split(separator: ".").first, first.count == 10,
           first.allSatisfy({ ($0.isUppercase || $0.isNumber) && $0.isASCII }) { return true }
        let debris: Set<String> = ["log", "old", "cache", "db", "json", "txt", "plist", "tmp", "bak", "lock", "pid"]
        return lower.split(separator: ".").contains { part in
            debris.contains(String(part)) || part.allSatisfy(\.isNumber)
        }
    }

    /// Preference keys only GUI apps write (window frames, panels, Sparkle).
    static let appPreferenceKeyPrefixes = ["NSWindow Frame", "NSSplitView Subview Frames", "NSToolbar Configuration",
                                           "NSNavLastRootDirectory", "NSNavPanelExpandedSize", "NSStatusItem Preferred Position",
                                           "NSOSPLastRootDirectory", "SUEnableAutomaticChecks", "SULastCheckTime",
                                           "SUHasLaunchedBefore", "NSFullScreenMenuItemEverywhere"]
}

public struct LeftoverPath: Codable, Equatable, Sendable {
    /// Logical absolute path.
    public var path: String
    public var kind: String
    public var bytes: UInt64
    public var needsRoot: Bool

    public init(path: String, kind: String, bytes: UInt64, needsRoot: Bool) {
        self.path = path; self.kind = kind; self.bytes = bytes; self.needsRoot = needsRoot
    }
}

public enum AppPresence: Equatable, Sendable {
    case present(String)
    case unknown(String)
    /// The sources find no app — but nothing shows it ever WAS an app
    /// (a CLI tool's cache, a framework's defaults domain).
    case noAppEvidence
    case gone([String])

    public var label: String {
        switch self {
        case .present: return "present"
        case .unknown: return "unknown"
        case .noAppEvidence: return "no-app-evidence"
        case .gone: return "gone"
        }
    }
}

public struct AppLeftoverCandidate: Sendable {
    public var bundleIdentifier: String
    public var paths: [LeftoverPath]
    public var presence: AppPresence
    /// What shows it was an app: a sandbox container, saved window state …
    public var appEvidence: [String]
    public var totalBytes: UInt64 { paths.reduce(0) { $0 + $1.bytes } }

    public init(bundleIdentifier: String, paths: [LeftoverPath], presence: AppPresence, appEvidence: [String]) {
        self.bundleIdentifier = bundleIdentifier; self.paths = paths
        self.presence = presence; self.appEvidence = appEvidence
    }
}

/// The three sources — injectable, so tests never ask the real system.
public struct AppPresenceSources {
    /// Bundle ids of every app found by walking the application folders,
    /// plus running apps and registered extensions.
    public var installed: Set<String>
    /// LaunchServices: a path when an app with this id is registered.
    public var launchServices: (String) -> String?
    /// Spotlight: true = found, false = not found, nil = could not answer.
    public var spotlight: (String) -> Bool?

    public init(installed: Set<String>, launchServices: @escaping (String) -> String?,
                spotlight: @escaping (String) -> Bool?) {
        self.installed = installed
        self.launchServices = launchServices
        self.spotlight = spotlight
    }

    public func presence(of id: String) -> AppPresence {
        let lower = id.lowercased()
        if lower.hasPrefix("com.apple.") { return .present("Apple") }
        let installedLower = installed.map { $0.lowercased() }
        if installedLower.contains(lower) { return .present("installed app or extension with this id") }
        // The helper / extension / preference domain of an installed app:
        // com.vendor.app.helper while com.vendor.app is there.
        if let owner = installed.sorted().first(where: { lower.hasPrefix($0.lowercased() + ".") }) {
            return .present("belongs to installed \(owner)")
        }
        // Same vendor still installed: com.microsoft.office next to
        // com.microsoft.Word is shared vendor data, not a leftover.
        let vendor = lower.split(separator: ".").prefix(2).joined(separator: ".") + "."
        if let sibling = installed.sorted().first(where: { $0.lowercased().hasPrefix(vendor) }) {
            return .unknown("vendor still has installed apps (\(sibling)) — its data may be shared")
        }
        if let path = launchServices(id) { return .present("LaunchServices: \(path)") }
        switch spotlight(id) {
        case .some(true): return .present("Spotlight finds an app with this id")
        case .none: return .unknown("Spotlight did not answer — no verdict without it")
        case .some(false): break
        }
        return .gone(["no app in the application folders", "LaunchServices: not registered",
                      "Spotlight: no app with this id", "not running"])
    }
}

public struct AppLeftoverScanner {
    public var disk: DiskView
    /// Logical home ("/Users/alice").
    public var home: String
    public var locations: [LeftoverLocation]

    public init(disk: DiskView = DiskView(), home: String = NSHomeDirectory(),
                locations: [LeftoverLocation] = AppLeftoverLocations.all) {
        self.disk = disk
        self.home = home
        self.locations = locations
    }

    func directory(_ location: LeftoverLocation) -> String {
        location.isSystem ? location.directory : home + "/" + location.directory
    }

    /// Every bundle-id-named entry in the leftover locations, grouped by id.
    public func candidates() -> [String: [LeftoverPath]] {
        var found: [String: [LeftoverPath]] = [:]
        for location in locations {
            let dir = directory(location)
            guard let names = try? disk.fileManager.contentsOfDirectory(atPath: disk.disk(dir)) else { continue }
            for name in names where !name.hasPrefix(".") {
                guard name.hasSuffix(location.suffix) else { continue }
                let id = String(name.dropLast(location.suffix.count))
                // ".plist" entries also end in "" — keep suffix-less kinds from
                // claiming "x.plist" as an id with a "plist" part.
                if location.suffix.isEmpty, ["plist", "savedState", "binarycookies"]
                    .contains((name as NSString).pathExtension) { continue }
                guard AppLeftoverLocations.isBundleIdentifier(id), !AppLeftoverLocations.isExcluded(id) else { continue }
                let path = dir + "/" + name
                guard let type = disk.type(path), type == .typeDirectory || type == .typeRegular else { continue }
                found[id, default: []].append(LeftoverPath(path: path, kind: location.kind, bytes: size(path),
                                                           needsRoot: location.isSystem))
            }
        }
        return found
    }

    func size(_ path: String) -> UInt64 {
        let fm = disk.fileManager
        let full = disk.disk(path)
        guard let attributes = try? fm.attributesOfItem(atPath: full) else { return 0 }
        if attributes[.type] as? FileAttributeType != .typeDirectory {
            return attributes[.size] as? UInt64 ?? 0
        }
        var total: UInt64 = 0
        let enumerator = fm.enumerator(atPath: full)
        while let entry = enumerator?.nextObject() as? String {
            if let size = (try? fm.attributesOfItem(atPath: full + "/" + entry))?[.size] as? UInt64 { total += size }
        }
        return total
    }

    /// Positive signs the id belonged to an app: only apps get sandbox
    /// containers / application scripts, saved window state, WebKit data,
    /// or preferences with window frames and Sparkle keys.
    public func appEvidence(_ paths: [LeftoverPath]) -> [String] {
        var evidence: [String] = []
        for path in paths {
            switch path.kind {
            case "container": evidence.append("sandbox container")
            case "application-scripts": evidence.append("application scripts folder")
            case "saved-state": evidence.append("saved window state")
            case "webkit": evidence.append("WebKit data")
            case "preferences":
                if let keys = (try? PlistReader.readDictionary(fromFile: disk.disk(path.path),
                                                               fileManager: disk.fileManager))?.keys,
                   let key = keys.sorted().first(where: { key in
                       AppLeftoverLocations.appPreferenceKeyPrefixes.contains { key.hasPrefix($0) } }) {
                    evidence.append("preferences hold \"\(key)\"")
                }
            default: break
            }
        }
        return Array(Set(evidence)).sorted()
    }

    /// The verdict for one id: the sources' presence, then — for "gone" —
    /// the requirement that something shows it was an app at all.
    public func verdict(_ id: String, paths: [LeftoverPath], sources: AppPresenceSources) -> AppLeftoverCandidate {
        let evidence = appEvidence(paths)
        var presence = sources.presence(of: id)
        if case .gone = presence, evidence.isEmpty { presence = .noAppEvidence }
        return AppLeftoverCandidate(bundleIdentifier: id, paths: paths.sorted { $0.path < $1.path },
                                    presence: presence, appEvidence: evidence)
    }

    public func scan(sources: AppPresenceSources) -> [AppLeftoverCandidate] {
        candidates().map { verdict($0.key, paths: $0.value, sources: sources) }
            .sorted { $0.bundleIdentifier < $1.bundleIdentifier }
    }
}

/// The Foundation-side sources: a walk of the application folders (Info.plist
/// of every app, two levels deep, plus login items and helpers inside them),
/// registered extensions and Spotlight via the runner. LaunchServices and the
/// running apps come from NSWorkspace in the CLI (AppKit stays out of the kit).
public enum SystemAppPresence {
    public static let applicationFolders = ["/Applications", "/Applications/Utilities", "/System/Applications",
                                            "/System/Applications/Utilities"]

    public static func installedBundleIdentifiers(home: String, fileManager: FileManager = .default) -> Set<String> {
        var ids = Set<String>()
        func record(_ app: String) {
            if let id = (try? PlistReader.readDictionary(fromFile: app + "/Contents/Info.plist",
                                                         fileManager: fileManager))?["CFBundleIdentifier"] as? String {
                ids.insert(id)
            }
            for inner in ["Contents/Library/LoginItems", "Contents/Helpers", "Contents/Applications"] {
                for name in (try? fileManager.contentsOfDirectory(atPath: app + "/" + inner)) ?? [] where name.hasSuffix(".app") {
                    record(app + "/" + inner + "/" + name)
                }
            }
        }
        for folder in applicationFolders + [home + "/Applications"] {
            for name in (try? fileManager.contentsOfDirectory(atPath: folder)) ?? [] {
                let path = folder + "/" + name
                if name.hasSuffix(".app") { record(path); continue }
                // Vendor folders: /Applications/Microsoft Office/…app
                var isDir: ObjCBool = false
                guard fileManager.fileExists(atPath: path, isDirectory: &isDir), isDir.boolValue else { continue }
                for inner in (try? fileManager.contentsOfDirectory(atPath: path)) ?? [] where inner.hasSuffix(".app") {
                    record(path + "/" + inner)
                }
            }
        }
        return ids
    }

    /// Registered app extensions (`pluginkit -mA`, identifiers only).
    public static func extensionIdentifiers(runner: CommandRunner) -> Set<String> {
        let result = runner.run(command: "/usr/bin/pluginkit", arguments: ["-mAvv"], timeout: 30)
        guard result.exitCode == 0 else { return [] }
        return Set(PluginKitParser.parse(result.stdout).records.map(\.identifier))
    }

    /// Spotlight: an app bundle with this id anywhere indexed. The id passed
    /// the bundle-id syntax check, so it cannot break out of the quotes.
    public static func spotlight(runner: CommandRunner) -> (String) -> Bool? {
        { id in
            guard AppLeftoverLocations.isBundleIdentifier(id) else { return nil }
            let result = runner.run(command: "/usr/bin/mdfind",
                                    arguments: ["kMDItemCFBundleIdentifier == '\(id)'"], timeout: 20)
            guard result.exitCode == 0 else { return nil }
            return !result.stdout.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
        }
    }
}
