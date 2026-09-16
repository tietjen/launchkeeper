import Foundation

/// One argv-level step, planned as pure data. A plan is displayable (dry-run),
/// testable and executable — the executor cannot invent commands on its own.
public struct PlannedCommand: Codable, Equatable {
    public let command: String
    public let arguments: [String]
    public let description: String

    public init(command: String, arguments: [String], description: String) {
        self.command = command
        self.arguments = arguments
        self.description = description
    }

    /// Flat form used as audit/executed marker. Same keying as the runner seam.
    public var display: String { ([command] + arguments).joined(separator: " ") }
}

/// Builds argv lists for `launchctl` state changes. V0.2 mechanics are
/// launchctl-only: disable/enable never touch files on disk (that stays V0.3
/// and out of this module).
public enum RemediationPlanner {

    /// Audit/display target, e.g. "gui/501/com.example.script" or
    /// "system/de.btmctl.scratch".
    public static func displayTarget(for item: BackgroundItem, uid: Int) -> String {
        guard let label = item.label else { return item.key }
        return (item.domain == .user ? "gui/\(uid)" : "system") + "/" + label
    }

    /// Domain argument for launchctl ("gui/<uid>" | "system").
    public static func domainTarget(for item: BackgroundItem, uid: Int) -> String {
        item.domain == .user ? "gui/\(uid)" : "system"
    }

    /// Every command list is built through this single funnel, so the
    /// sudo-prefix rule lives in exactly one place.
    private static func launchctl(_ arguments: [String], needsSudo: Bool, description: String) -> PlannedCommand {
        if needsSudo {
            return PlannedCommand(command: "/usr/bin/sudo",
                                  arguments: ["launchctl"] + arguments,
                                  description: description + " — via sudo (interactive password)")
        }
        return PlannedCommand(command: "/bin/launchctl", arguments: arguments, description: description)
    }

    public static func plan(operation: RemediationOperation, item: BackgroundItem,
                            uid: Int, now: Bool = false) -> [PlannedCommand] {
        guard let label = item.label else { return [] }
        let serviceTarget = displayTarget(for: item, uid: uid)
        let domainTarget = domainTarget(for: item, uid: uid)
        let needsSudo = item.domain != .user
        var commands: [PlannedCommand] = []

        switch operation {
        case .disable:
            // Order matters: override first, THEN unload. Reversed, a
            // KeepAlive job would respawn before the disable takes effect.
            commands.append(launchctl(["disable", serviceTarget], needsSudo: needsSudo,
                                      description: "persistently disable (visible in print-disabled)"))
            if item.loaded {
                commands.append(launchctl(["bootout", serviceTarget], needsSudo: needsSudo,
                                          description: "unload now (after override, so keepAlive cannot reload)"))
            }
        case .enable:
            commands.append(launchctl(["enable", serviceTarget], needsSudo: needsSudo,
                                      description: "remove the disable override"))
            // Reload only when --now and a backing plist exists to bootstrap from.
            if now, let path = item.path, path.hasSuffix(".plist"), path.hasPrefix("/") {
                commands.append(launchctl(["bootstrap", domainTarget, path], needsSudo: needsSudo,
                                          description: "reload immediately (--now)"))
            }
        case .backup, .restore:
            break // handled by BackupService
        }
        return commands
    }

    /// Undo hint shown next to every plan (reversibility over minimalism).
    public static func undoHint(for operation: RemediationOperation, item: BackgroundItem) -> String? {
        switch operation {
        case .disable: return "btmctl enable \(item.id)"
        case .enable: return "btmctl disable \(item.id)"
        case .backup, .restore: return nil
        }
    }
}