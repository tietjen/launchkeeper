import Foundation

/// V0.4 app correlation: every item learns its PARENT APPLICATION.
///
/// Sources, in authority order:
/// 1. The item's absolute executable or path living inside an `.app` bundle
///    (deepest ancestor) — read straight from the file system.
/// 2. Spotlight (`mdfind kMDItemCFBundleIdentifier == '<id>'`) — consulted
///    ONLY when the bundle path is provably gone, to answer "is the app
///    installed anywhere else?" Both are read-only; the scan pipeline stays
///    write-free.
///
/// The resolver fills `parentApplication`, `appPresent`, `bundleIdentifier`,
/// `teamIdentifier` and the `app-gone-confirmed` metadata flag that
/// OrphanDetector consumes as an independent second source. Absence of a
/// bundle ID, a failed or timed-out mdfind, and relative paths all degrade to
/// "unknown" — never to a guessed answer (same rule as the whole scanner:
/// unknown stays unknown).

public struct AppContextResolver {
    public var fileManager: FileManager
    public var runner: CommandRunner
    /// mdfind budget: a healthy index answers in ms; a long wait means the
    /// Spotlight daemon is wedged, not that the query is complex.
    public var spotlightTimeout: TimeInterval = 15

    private var spotlightCache: [String: (exitCode: Int32, matches: [String])] = [:]
    /// One entry per DISTINCT bundle id queried — the doctor check and the
    /// tests both assert on this, so a cache is observable, not just fast.
    public private(set) var spotlightQueries: [String] = []
    public private(set) var spotlightAvailable: Bool?

    public init(fileManager: FileManager = .default, runner: CommandRunner = SystemCommandRunner()) {
        self.fileManager = fileManager
        self.runner = runner
    }

    public mutating func apply(to items: inout [BackgroundItem]) {
        for index in items.indices {
            resolve(&items[index])
        }
    }

    private mutating func resolve(_ item: inout BackgroundItem) {
        // Deepest .app ancestor of the executable, else of the backing file.
        // Relative fragments stay unresolvable by design — they belong to a
        // bundle whose location the source did not pin down.
        let bundle = Self.enclosingAppBundle(path: item.executable)
            ?? Self.enclosingAppBundle(path: item.path)
        guard let bundle else {
            // No derivable bundle: BTM-derived parentApplication (if any) stays
            // as the correlator probed it. No bundle id, no Spotlight call —
            // an id that is the item's own is not the parent's, and guessing
            // would manufacture evidence.
            return
        }

        let bundleName = (bundle as NSString).lastPathComponent
            .replacingOccurrences(of: ".app", with: "")
        var infoName: String?
        var infoBundleID: String?
        var infoTeam: String?
        if let info = try? PlistReader.readDictionary(fromFile: bundle + "/Contents/Info.plist") {
            infoName = (info["CFBundleDisplayName"] as? String)
                ?? (info["CFBundleName"] as? String)
            infoBundleID = info["CFBundleIdentifier"] as? String
            infoTeam = info["CFBundleTeamIdentifier"] as? String
        }

        let exists = fileManager.fileExists(atPath: bundle)
        item.parentApplication = infoName ?? bundleName
        item.appPresent = exists
        item.bundleIdentifier = item.bundleIdentifier ?? infoBundleID
        item.teamIdentifier = item.teamIdentifier ?? infoTeam
        item.metadata["app-bundle"] = bundle
        item.sources.append(SourceEvidence(
            kind: .plist, detail: "app bundle: \(bundle)", confidence: exists ? .high : .medium))

        guard !exists else {
            item.metadata["app-gone-confirmed"] = "present"
            return
        }

        // Bundle gone. If a bundle id is known, Spotlight is the independent
        // second source: "is anything registered under this id, anywhere?"
        guard let bundleID = item.bundleIdentifier, !bundleID.isEmpty else {
            item.metadata["app-gone-confirmed"] = "unknown"
            return
        }
        let (exitCode, matches) = spotlightLookup(bundleID)
        if exitCode == -2 {
            // Timed out: the index is wedged, the answer is unknown — not "gone".
            item.metadata["app-gone-confirmed"] = "unknown"
        } else if exitCode != 0 {
            item.metadata["app-gone-confirmed"] = "unknown"
        } else if matches.isEmpty {
            item.metadata["app-gone-confirmed"] = "missing"
        } else {
            // Installed at a different location — the app exists, only its
            // former home is gone. NOT an orphan signal.
            item.appPresent = true
            item.metadata["app-gone-confirmed"] = "relocated"
            item.metadata["app-spotlight"] = matches.first ?? ""
        }
    }

    private mutating func spotlightLookup(_ bundleID: String) -> (exitCode: Int32, matches: [String]) {
        if let cached = spotlightCache[bundleID] { return cached }
        spotlightQueries.append(bundleID)
        let predicate = "kMDItemCFBundleIdentifier == '\(bundleID)'"
        let result = runner.run(command: "/usr/bin/mdfind", arguments: [predicate],
                                timeout: spotlightTimeout)
        spotlightAvailable = (result.exitCode == -2) ? false
            : ((spotlightAvailable ?? true) && result.exitCode == 0)
        let matches = result.stdout.split(separator: "\n")
            .map { String($0).trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        let outcome = (result.exitCode, matches)
        spotlightCache[bundleID] = outcome
        return outcome
    }

    /// Deepest ancestor of an ABSOLUTE path that is an `.app` bundle.
    /// String-based (no probing): the caller checks existence separately.
    /// A path that IS a bundle returns itself; `my.appdir` does not match
    /// (suffix must be exactly `.app`), and relative paths return nil.
    public static func enclosingAppBundle(path: String?) -> String? {
        guard let path, path.hasPrefix("/") else { return nil }
        if path.hasSuffix(".app") { return path }
        var candidate = (path as NSString).deletingLastPathComponent
        while !candidate.isEmpty && candidate != "/" {
            if candidate.hasSuffix(".app") { return candidate }
            candidate = (candidate as NSString).deletingLastPathComponent
        }
        return nil
    }
}