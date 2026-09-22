import Foundation

/// Declarative row filter for `launchkeeper list`. All conditions AND together.
public struct ListFilter {
    public var orphansOnly = false
    public var runningOnly = false
    public var disabledOnly = false
    public var userOnly = false
    public var systemOnly = false
    /// true = keep Apple-internal noise (default view hides it).
    public var includeAll = false
    /// V0.5: only this Autoruns-style category.
    public var category: ItemCategory?

    public init() {}

    public func apply(to items: [BackgroundItem]) -> [BackgroundItem] {
        // Explicit narrowing flags (--orphans/--running/--disabled) mean the user
        // wants the raw view; transient-noise suppression then applies to Apple
        // internals only. --all disables suppression entirely.
        let narrowing = orphansOnly || runningOnly || disabledOnly
        return items.filter { item in
            if orphansOnly && !item.orphaned { return false }
            if runningOnly && !item.running { return false }
            if disabledOnly && item.enabled { return false }
            if userOnly && item.domain == .system { return false }
            if systemOnly && item.domain == .user { return false }
            if let category {
                // The scheduled view is everything that runs on a timer,
                // launchd timers (launch items with a schedule) included.
                if category == .scheduled {
                    if item.category != .scheduled && item.metadata["schedule"] == nil { return false }
                } else if item.category != category {
                    return false
                }
            }
            if !includeAll {
                if Self.isAppleInternal(item) { return false }
                if !narrowing, Self.isTransientNoise(item) { return false }
            }
            return true
        }
    }

    /// launchd seen but no plist, no BTM, not user-disabled => transient
    /// runtime bookkeeping, not a persistent configuration entry.
    static func isTransientNoise(_ item: BackgroundItem) -> Bool {
        item.launchdPresent && !item.plistPresent && !item.btmPresent && item.enabled
    }

    /// Apple-internal bookkeeping: reverse-DNS com.apple label and no evidence
    /// of user-installed backing. Shown only with --all; never offered for
    /// management (system components are read-only by design).
    static func isAppleInternal(_ item: BackgroundItem) -> Bool {
        let appleLabel = item.label.map {
            $0.hasPrefix("com.apple.") || $0.hasPrefix("application.com.apple.")
        } ?? false
        let appleName = item.displayName.hasPrefix("com.apple.")
            || item.displayName.hasPrefix("application.com.apple.")
        guard appleLabel || appleName else { return false }
        // A user-owned plist next to it means it's a genuine third-party finding.
        if item.plistPresent, item.owner != "root" { return false }
        return item.codeSignatureStatus == nil || item.codeSignatureStatus == "apple-system"
    }
}
