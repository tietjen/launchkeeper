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
                reason: "orphaned launch plist inside the launch directories — remove passes all four locks")
        }
        if !item.plistPresent, item.launchdPresent {
            return Controllability(level: .reversible, actions: ["disable", "enable"],
                reason: "launchd job without a plist on disk — disable unloads it; it vanishes at the next login")
        }
        return Controllability(level: .reversible, actions: ["disable", "enable"],
            reason: "launchd override — disable/enable, undo is one command; remove only once provably orphaned")
    }
}
