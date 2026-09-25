import Foundation

/// Fills `BackgroundItem.control` — the control matrix as data. It asks the
/// SAME gate the mutating commands consult, so what the inventory promises
/// is exactly what `disable`/`enable`/`remove` will do. Read-only.
public struct ControlAnalyzer {
    public var fileManager: FileManager
    /// Allowlisted launch directories, for the `remove` locks.
    public var launchDirs: [String]

    public init(fileManager: FileManager = .default, launchDirs: [String]) {
        self.fileManager = fileManager
        self.launchDirs = launchDirs
    }

    public func apply(to items: inout [BackgroundItem]) {
        for index in items.indices {
            items[index].control = evaluate(items[index])
        }
    }

    public func evaluate(_ item: BackgroundItem) -> Controllability {
        // System extensions, kexts and helpers without a launchd job (V0.5.5):
        // what launchkeeper can do is show them and say where the switch is.
        switch item.type {
        case .systemExtension:
            let target = [item.teamIdentifier, item.bundleIdentifier].compactMap { $0 }.joined(separator: " ")
            let pane = item.metadata["sysext-pane"] ?? "Extensions"
            return Controllability(level: .displayOnly, actions: [],
                reason: "system extension — deactivate via its host app or `systemextensionsctl uninstall "
                    + "\(target)` (SIP rules apply); System Settings › General › Login Items & Extensions › \(pane)")
        case .kernelExtension:
            return Controllability(level: .displayOnly, actions: [],
                reason: "kernel extension — unload/remove via the vendor's uninstaller; on Apple silicon "
                    + "third-party kexts need Reduced Security")
        case .privilegedHelper where !item.launchdPresent && !item.plistPresent:
            return Controllability(level: .displayOnly, actions: [],
                reason: "privileged helper without a launchd job — nothing to disable; deleting helper "
                    + "binaries comes with V0.8 cleanup")
        // V0.5.6 scheduled / legacy / plugin directories: read-only for now.
        case .cronJob:
            switch RemediationGate.evaluate(operation: .disable, item: item) {
            case .denied(let reason):
                return Controllability(level: .displayOnly, actions: [], reason: reason, mechanism: .cron)
            case .allowed:
                return Controllability(level: .reversible, actions: ["disable", "enable"],
                    reason: "user crontab line — disable comments it out behind a launchkeeper marker, enable "
                        + "takes the marker off; the whole table is snapshotted first", mechanism: .cron)
            }
        case .atJob:
            return Controllability(level: .displayOnly, actions: [],
                reason: "at job — `atrm <job>` removes it; launchkeeper control comes with V0.7")
        case .powerEvent:
            return Controllability(level: .displayOnly, actions: [],
                reason: "scheduled power event — `sudo pmset schedcancel` / the owning app; read-only here")
        case .periodicScript:
            return Controllability(level: .displayOnly, actions: [],
                reason: "periodic(8) script — removal over the gate comes with V0.8 cleanup")
        case .loginHook:
            return Controllability(level: .displayOnly, actions: [],
                reason: "loginwindow hook — `sudo defaults delete \(item.path ?? "com.apple.loginwindow") "
                    + "\(item.metadata["hook-kind"] ?? "LoginHook")` removes it; gate support comes with V0.8")
        case .startupItem:
            return Controllability(level: .displayOnly, actions: [],
                reason: "legacy StartupItem — nothing runs it since OS X 10.10; removal over the gate comes with V0.8")
        case .rcScript, .emondRule:
            return Controllability(level: .displayOnly, actions: [],
                reason: "legacy persistence file — review by hand; removal over the gate comes with V0.8")
        case .plugin:
            return Controllability(level: .displayOnly, actions: [],
                reason: "plugin bundle (\(item.metadata["plugin-kind"] ?? "plugin")) — loaded by location; "
                    + "removal over the gate comes with V0.8")
        case .shellProfile, .pathEntry:
            return Controllability(level: .displayOnly, actions: [],
                reason: "shell startup file — launchkeeper never edits shell files; review it in your editor")
        case .listener:
            let entry = item.metadata["network-entry-label"] ?? item.metadata["network-entry"]
            return Controllability(level: .displayOnly, actions: [],
                reason: "listening process — " + (entry.map { "control its entry `\($0)`" } ?? "no inventory entry starts it")
                    + "; block it: `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --blockapp <path>`")
        case .firewallRule:
            return Controllability(level: .displayOnly, actions: [],
                reason: "Application Firewall rule — `sudo /usr/libexec/ApplicationFirewall/socketfilterfw "
                    + "--remove <path>` / System Settings › Network › Firewall")
        default:
            break
        }
        // App extensions (V0.7): the switch is the user's pluginkit
        // election — flipped through the same gate as everything else.
        if item.controlMechanism == .pluginkit {
            switch RemediationGate.evaluate(operation: .disable, item: item) {
            case .denied(let reason):
                return Controllability(level: .displayOnly, actions: [], reason: reason, mechanism: .pluginkit)
            case .allowed:
                let id = item.metadata["ext-identifier"] ?? item.displayName
                return Controllability(level: .reversible, actions: ["disable", "enable"],
                    reason: "app extension — disable/enable set the pluginkit election (ignore/use) for \(id); "
                        + "per user, nothing on disk changes", mechanism: .pluginkit)
            }
        }
        // Records that only Background Task Management manages (extensions,
        // login items without a launch plist): the switch is in System
        // Settings, launchkeeper shows it and stops there.
        if item.btmPresent, !item.plistPresent, !item.launchdPresent,
           item.metadata["btm-leftover"] != "true" {
            return Controllability(level: .displayOnly, actions: [],
                reason: "managed by Background Task Management — the switch is in "
                    + "System Settings › General › Login Items & Extensions")
        }
        switch RemediationGate.evaluate(operation: .disable, item: item) {
        case .denied(let reason):
            return Controllability(level: .displayOnly, actions: [], reason: reason)
        case .allowed:
            break
        }
        if item.orphaned,
           case .allowed = RemediationGate.evaluateRemove(item: item, fileManager: fileManager,
                                                         launchDirs: launchDirs) {
            return Controllability(level: .removable, actions: ["disable", "enable", "remove"],
                reason: "orphaned launch plist inside the launch directories — remove passes all four locks",
                mechanism: .launchd)
        }
        if !item.plistPresent, item.launchdPresent {
            return Controllability(level: .reversible, actions: ["disable", "enable"],
                reason: "launchd job without a plist on disk — disable unloads it; it vanishes at the next login",
                mechanism: .launchd)
        }
        return Controllability(level: .reversible, actions: ["disable", "enable"],
            reason: "launchd override — disable/enable, undo is one command; remove only once provably orphaned",
            mechanism: .launchd)
    }
}
