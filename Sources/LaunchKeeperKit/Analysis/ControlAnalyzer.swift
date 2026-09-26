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
            // `systemextensionsctl uninstall` refuses while SIP is on (live
            // 2026-09-26) — never offer it as the way. macOS removes a
            // system extension itself when its host app goes to the Trash
            // in the Finder, or through the vendor's uninstaller.
            let pane = item.metadata["sysext-pane"] ?? "Extensions"
            let waiting = (item.metadata["sysext-state"] ?? "").contains("waiting for user")
                ? " It was never approved (waiting for user), so it is not active." : ""
            let way = item.metadata["sysext-host-app"] == "not found"
                ? "its host app is gone — reinstall the app, then move it to the Trash in the Finder (or run the "
                    + "vendor's uninstaller); macOS removes the extension with it"
                : "move its host app to the Trash in the Finder (or run the vendor's uninstaller); macOS removes "
                    + "the extension with it"
            return Controllability(level: .displayOnly, actions: [],
                reason: "system extension — \(way). `systemextensionsctl uninstall` only works with SIP "
                    + "disabled. Switch: System Settings › General › Login Items & Extensions › \(pane).\(waiting)")
        case .kernelExtension:
            return Controllability(level: .displayOnly, actions: [],
                reason: "kernel extension — unload/remove via the vendor's uninstaller; on Apple silicon "
                    + "third-party kexts need Reduced Security")
        case .privilegedHelper where !item.launchdPresent && !item.plistPresent:
            return quarantineControl(item)
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
            switch RemediationGate.evaluate(operation: .disable, item: item) {
            case .denied(let reason):
                return Controllability(level: .displayOnly, actions: [], reason: reason, mechanism: .loginHook)
            case .allowed:
                return Controllability(level: .reversible, actions: ["disable", "enable"],
                    reason: "loginwindow hook — disable parks the script path under "
                        + "\(LoginHookRecord.parkedKey(for: item.metadata["hook-kind"] ?? "LoginHook")) in the same "
                        + "plist (snapshot first\(item.domain == .system ? ", via sudo" : "")), enable puts it back",
                    mechanism: .loginHook)
            }
        case .startupItem:
            return quarantineControl(item)
        case .rcScript, .emondRule:
            return Controllability(level: .displayOnly, actions: [],
                reason: "legacy persistence file — review by hand; removal over the gate comes with V0.8")
        case .plugin:
            return Controllability(level: .displayOnly, actions: [],
                reason: "plugin bundle (\(item.metadata["plugin-kind"] ?? "plugin")) — loaded by location; "
                    + "removal over the gate comes with V0.8")
        case .pathEntry:
            return quarantineControl(item)
        case .shellProfile:
            return Controllability(level: .displayOnly, actions: [],
                reason: "shell startup file — launchkeeper never edits shell files; review it in your editor")
        case .listener where item.controlMechanism != .firewall:
            let entry = item.metadata["network-entry-label"] ?? item.metadata["network-entry"]
            return Controllability(level: .displayOnly, actions: [],
                reason: "listening process — " + (entry.map { "control its entry `\($0)`" } ?? "no inventory entry starts it")
                    + "; no firewall rule yet — add one by hand: `sudo /usr/libexec/ApplicationFirewall/socketfilterfw "
                    + "--blockapp <path>`")
        case .listener, .firewallRule:
            switch RemediationGate.evaluate(operation: .disable, item: item) {
            case .denied(let reason):
                return Controllability(level: .displayOnly, actions: [], reason: reason, mechanism: .firewall)
            case .allowed:
                let entry = item.metadata["network-entry-label"] ?? item.metadata["network-entry"]
                return Controllability(level: .reversible, actions: ["disable", "enable"],
                    reason: "Application Firewall rule — disable blocks incoming connections, enable allows them "
                        + "(socketfilterfw via sudo); the rule itself stays"
                        + (entry.map { "; to stop the process, control its entry `\($0)`" } ?? ""),
                    mechanism: .firewall)
            }
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

    /// V0.8.1 leftover files: `remove` moves them into the quarantine.
    func quarantineControl(_ item: BackgroundItem) -> Controllability {
        switch RemediationGate.evaluate(operation: .remove, item: item) {
        case .denied(let reason):
            return Controllability(level: .displayOnly, actions: [], reason: reason, mechanism: .quarantine)
        case .allowed:
            return Controllability(level: .removable, actions: ["remove"],
                reason: "provable leftover — remove moves it into the quarantine (sudo), "
                    + "`launchkeeper quarantine restore` brings it back", mechanism: .quarantine)
        }
    }
}
