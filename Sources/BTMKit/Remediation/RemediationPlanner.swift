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

/// Builds argv lists for remediation. V0.2 was launchctl state only; V0.3
/// adds the `remove` plan — one gated file deletion, still argv-only (never a
/// shell, `--` guards option injection) and only ever for a path the gate has
/// already pinned inside the launch directories.
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

    /// File operations go through a second funnel: the same single-place sudo
    /// rule, argv arrays only, and `--` before the path so a weird filename can
    /// never be read as options. The path itself is never user input — it was
    /// resolved from the scan and pinned by the gate.
    private static func fileRemoval(path: String, needsSudo: Bool, description: String) -> PlannedCommand {
        if needsSudo {
            return PlannedCommand(command: "/usr/bin/sudo",
                                  arguments: ["rm", "--", path],
                                  description: description + " — via sudo (interactive password)")
        }
        return PlannedCommand(command: "/bin/rm", arguments: ["--", path], description: description)
    }

    public static func plan(operation: RemediationOperation, item: BackgroundItem,
                            uid: Int, now: Bool = false) -> [PlannedCommand] {
        guard item.label != nil else { return [] }
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
        case .remove:
            // Order: unload first, delete second — the file is never pulled out
            // from under a loaded job. No disable-override step: that is what
            // `disable` is for, and stacking an override here would only leave
            // a stale print-disabled entry behind.
            if item.loaded {
                commands.append(launchctl(["bootout", serviceTarget], needsSudo: needsSudo,
                                          description: "unload the job before its file goes"))
            }
            if let path = item.path, path.hasPrefix("/"), path.hasSuffix(".plist") {
                commands.append(fileRemoval(path: path, needsSudo: needsSudo,
                                            description: "delete the orphaned backing plist "
                                                       + "(--apply always snapshots the launch dirs first)"))
            }
            // A disable override belongs to the removed file, not to whatever
            // label may come next — drop it, or print-disabled keeps a dangling
            // entry forever (inert, but a cleaner state is a safer state).
            if !item.enabled {
                commands.append(launchctl(["enable", serviceTarget], needsSudo: needsSudo,
                                          description: "drop the stale disable override (leaves no dangling entry)"))
            }
        case .backup, .restore:
            break // handled by BackupService
        }
        return commands
    }

    /// Undo hint shown next to every plan (reversibility over minimalism).
    /// Addressed by LABEL, never by display id: the id is positional and stable
    /// only within one scan run — a hint the user executes later would resolve
    /// to a different entry (and for `remove` the hint IS the recovery path).
    private static func hintAddress(_ item: BackgroundItem) -> String {
        item.label ?? item.id
    }

    public static func undoHint(for operation: RemediationOperation, item: BackgroundItem) -> String? {
        let target = hintAddress(item)
        switch operation {
        case .disable: return "btmctl enable \(target)"
        case .enable: return "btmctl disable \(target)"
        // Real undo for a deletion: restore the pre-remove snapshot, then
        // reactivate (only meaningful if there was something to reactivate).
        case .remove: return "btmctl restore <pre-remove backup> && btmctl enable \(target) --now"
        case .backup, .restore: return nil
        }
    }
}