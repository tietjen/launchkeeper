import Foundation

// V0.9 — `launchkeeper watch`: say it when something new may start
// automatically. What BlockBlock/KnockKnock do and Autoruns does not. The
// watcher itself is plain logic — scan, compare by stable key (the V0.6.1
// diff), keep the last complete inventory as baseline — so it is testable
// without FSEvents; the triggers live in FileSystemTriggers.

public struct WatchEvent: Codable, Equatable, Sendable {
    public enum Kind: String, Codable, Sendable {
        /// First complete inventory — the reference from now on.
        case baseline
        case added, removed, changed
        /// A scan was incomplete (BTM timeout …) — nothing compared, nothing reported.
        case skipped
    }
    public var timestamp: String
    public var kind: Kind
    public var key: String?
    public var displayName: String?
    public var category: String?
    public var path: String?
    public var changes: [InventoryDiff.Change]
    /// What set this scan off ("fsevents: /Library/LaunchAgents/x.plist", "interval").
    public var trigger: String
    public var note: String?

    /// One line for the terminal / a notification.
    public var summary: String {
        switch kind {
        case .baseline, .skipped:
            return "\(kind.rawValue): \(note ?? "")"
        case .added:
            return "NEW \(category ?? "?"): \(displayName ?? key ?? "?")" + (path.map { " — \($0)" } ?? "")
        case .removed:
            return "GONE \(category ?? "?"): \(displayName ?? key ?? "?")"
        case .changed:
            let fields = changes.map { "\($0.field) \($0.before) → \($0.after)" }.joined(separator: "; ")
            return "CHANGED \(category ?? "?"): \(displayName ?? key ?? "?") — \(fields)"
        }
    }
}

public final class InventoryWatcher: @unchecked Sendable {
    public let scan: () -> ScanReport
    public let includeAll: Bool
    public let includeState: Bool
    public private(set) var baseline: [BackgroundItem]?
    private let now: () -> Date

    public init(includeAll: Bool = false, includeState: Bool = false, now: @escaping () -> Date = Date.init,
                scan: @escaping () -> ScanReport) {
        self.scan = scan
        self.includeAll = includeAll
        self.includeState = includeState
        self.now = now
    }

    /// One round: scan, compare with the baseline, move the baseline on.
    /// Not reentrant — the caller serialises ticks (one scan at a time).
    public func tick(trigger: String) -> [WatchEvent] {
        let stamp = ISO8601DateFormatter().string(from: now())
        let report = scan()
        guard report.incompleteLayers.isEmpty else {
            // A missing layer would show all its entries as "removed" — the
            // V0.6.1 lesson. Keep the old baseline and say why.
            return [WatchEvent(timestamp: stamp, kind: .skipped, changes: [], trigger: trigger,
                               note: "scan incomplete (\(report.incompleteLayers.joined(separator: ", "))) — not compared")]
        }
        guard let previous = baseline else {
            baseline = report.items
            let shown = includeAll ? report.items.count : report.items.filter { !ListFilter.isAppleInternal($0) }.count
            return [WatchEvent(timestamp: stamp, kind: .baseline, changes: [], trigger: trigger,
                               note: "\(shown) entries — changes from here on are reported")]
        }
        baseline = report.items
        let diff = InventoryDiff.compare(before: previous, after: report.items, includeState: includeState,
                                         beforeLabel: "baseline", afterLabel: "now").filtered(includeAll: includeAll)
        func event(_ kind: WatchEvent.Kind, _ entry: InventoryDiff.Entry) -> WatchEvent {
            WatchEvent(timestamp: stamp, kind: kind, key: entry.key, displayName: entry.displayName,
                       category: entry.category, path: entry.path, changes: entry.changes, trigger: trigger, note: nil)
        }
        // A listening process is runtime state, not autostart configuration:
        // it comes and goes with the app (live: "NEW network: firefox").
        // Its firewall rule stays in; the process only with --state.
        func configuration(_ entry: InventoryDiff.Entry) -> Bool {
            includeState || entry.type != ItemType.listener.rawValue
        }
        return diff.added.filter(configuration).map { event(.added, $0) }
            + diff.removed.filter(configuration).map { event(.removed, $0) }
            + diff.changed.filter(configuration).map { event(.changed, $0) }
    }
}

/// Which file-system changes can mean a new autostart entry. FSEvents
/// reports every write below a watched root — /Library/Preferences and
/// /Applications are busy — so only these paths set off a scan.
public struct WatchPaths: Sendable {
    public var home: String

    public init(home: String = NSHomeDirectory()) { self.home = home }

    /// Directories whose DIRECT entries are autostart sources.
    public var directEntryRoots: [String] {
        [home + "/Library/LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons",
         "/Library/PrivilegedHelperTools", "/Library/StartupItems", "/Library/SystemExtensions",
         "/private/etc/paths.d", "/private/etc/manpaths.d", "/Library/Security/SecurityAgentPlugins",
         "/Applications", home + "/Applications"]
    }

    /// Single files that are autostart sources.
    public var files: [String] {
        [home + "/Library/Preferences/com.apple.loginwindow.plist",
         "/Library/Preferences/com.apple.loginwindow.plist",
         "/private/etc/crontab", "/private/etc/rc.local", "/private/etc/zshrc", "/private/etc/profile",
         home + "/.zshrc", home + "/.zprofile", home + "/.zshenv", home + "/.zlogin", home + "/.bash_profile",
         home + "/.bashrc", home + "/.profile"]
    }

    /// What FSEvents is asked to watch (existing parents only).
    public var streamRoots: [String] {
        var roots = Set(directEntryRoots)
        for file in files { roots.insert((file as NSString).deletingLastPathComponent) }
        return roots.sorted()
    }

    /// /etc → /private/etc: FSEvents reports resolved paths.
    static func normalized(_ path: String) -> String {
        for top in ["/etc", "/var", "/tmp"] where path == top || path.hasPrefix(top + "/") { return "/private" + path }
        return path
    }

    /// Does this reported path concern an autostart source?
    public func isRelevant(_ reported: String) -> Bool {
        let path = Self.normalized(reported.hasSuffix("/") ? String(reported.dropLast()) : reported)
        if files.map(Self.normalized).contains(path) { return true }
        for root in directEntryRoots.map(Self.normalized) {
            // The root itself, or a direct entry — not deep inside an app
            // bundle that updates itself.
            if path == root { return true }
            if path.hasPrefix(root + "/"), !path.dropFirst(root.count + 1).contains("/") { return true }
        }
        return false
    }
}
