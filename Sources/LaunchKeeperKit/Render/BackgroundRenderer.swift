import Foundation

/// The System Settings › General › Login Items & Extensions pane, rebuilt
/// from the inventory, verified against the pane on 2026-09-22:
///
/// - **Open at Login** lists apps registered by themselves — BTM `app`
///   records whose own disposition bit is `enabled` (a login item added in
///   the pane or via the legacy shared-file-list API). BTM records of type
///   `login item` (SMAppService helpers) are NOT listed there; they are
///   components under their app's row in the second section.
/// - **Allow in the Background** shows one row per app or developer; the
///   switch is the components' BTM disposition bit. A launchd disable
///   override (`launchctl disable`) is invisible to the pane — GoogleUpdater
///   read ON there while launchd had it disabled — so it is shown as its own
///   column, never folded into the switch.
/// - A container's own bit is not the switch (48 of 49 read `disabled`
///   on a healthy Mac) — except for app-level registrations without
///   components, where it is exactly that.
///
/// launchkeeper never writes to Background Task Management.
public struct BackgroundView: Codable {
    public enum Toggle: String, Codable { case on, off, mixed, appLevel = "app-level", none }

    public struct Component: Codable, Equatable {
        public var id: String
        public var name: String
        public var label: String?
        public var type: String
        public var category: ItemCategory
        /// The pane's switch for this component: its BTM disposition bit.
        public var btmEnabled: Bool
        /// launchd's `print-disabled` override, which the pane does not show.
        public var launchdDisabled: Bool
        /// Effective state: BTM bit AND no launchd override.
        public var enabled: Bool
        public var running: Bool
        public var orphaned: Bool
        public var leftover: Bool
        public var parentName: String?
    }

    public struct Row: Codable, Equatable {
        public var name: String
        public var kind: BTMContainer.Kind
        public var identifier: String
        public var teamIdentifier: String?
        public var toggle: Toggle
        /// The container's own bit, for the record — the switch only for app-level rows.
        public var rawDisposition: [String]
        public var components: [Component]
    }

    public struct LoginItem: Codable, Equatable {
        public var name: String
        public var identifier: String
        public var bundlePath: String?
    }

    public var loginItems: [LoginItem]
    public var background: [Row]
    public var note: String

    public static let derivationNote =
        "TOGGLE is the components' BTM disposition bit (all enabled = on, all disabled = off, "
        + "mixed otherwise) — exactly what the pane shows. A launchd override (LAUNCHD column) "
        + "is invisible to the pane and shown separately. app-level = the app itself is the "
        + "registration (no components, its own bit says enabled — such apps also appear under "
        + "Open at Login); none = nothing registered. Change the switch in System Settings › "
        + "General › Login Items & Extensions — launchkeeper does not write to Background Task "
        + "Management."

    public static func build(from report: ScanReport) -> BackgroundView {
        func btmEnabled(_ item: BackgroundItem) -> Bool {
            !(item.metadata["btm-disposition"] ?? "").contains("disabled")
        }
        func component(_ item: BackgroundItem) -> Component {
            let bit = btmEnabled(item)
            return Component(id: item.id, name: item.displayName, label: item.label,
                             type: item.metadata["btm-type"] ?? item.type.rawValue,
                             category: item.category, btmEnabled: bit,
                             launchdDisabled: bit && !item.enabled, enabled: bit && item.enabled,
                             running: item.running, orphaned: item.orphaned,
                             leftover: item.metadata["btm-leftover"] == "true",
                             parentName: item.parentApplication)
        }
        let byParent = Dictionary(grouping: report.items.filter { $0.metadata["btm-parent"] != nil },
                                  by: { $0.metadata["btm-parent"]! })
        let byIdentifier = Dictionary(report.items.compactMap { item in
            item.metadata["btm-identifier"].map { ($0, item) } }, uniquingKeysWith: { a, _ in a })

        var rows: [Row] = []
        var login: [LoginItem] = []
        for container in report.btmContainers {
            var members = byParent[container.identifier] ?? []
            for child in container.embedded {
                if let item = byIdentifier[child], !members.contains(where: { $0.key == item.key }) {
                    members.append(item)
                }
            }
            members.sort { $0.displayName.lowercased() < $1.displayName.lowercased() }
            // Unnamed registrations ("Unknown Developer"): the pane shows one row
            // per component, named after the component's executable ("bash").
            if container.unnamed, !members.isEmpty {
                for member in members {
                    let name = member.executable.map { ($0 as NSString).lastPathComponent } ?? member.displayName
                    rows.append(Row(name: name, kind: container.kind, identifier: container.identifier,
                                    teamIdentifier: container.teamIdentifier,
                                    toggle: btmEnabled(member) ? .on : .off,
                                    rawDisposition: container.dispositionTokens,
                                    components: [component(member)]))
                }
                continue
            }
            let ownBit = container.dispositionTokens.contains("enabled")
            let toggle: Toggle
            if members.isEmpty {
                toggle = ownBit ? .appLevel : .none
            } else if members.allSatisfy(btmEnabled) { toggle = .on }
            else if members.allSatisfy({ !btmEnabled($0) }) { toggle = .off }
            else { toggle = .mixed }
            rows.append(Row(name: container.name, kind: container.kind, identifier: container.identifier,
                            teamIdentifier: container.teamIdentifier, toggle: toggle,
                            rawDisposition: container.dispositionTokens,
                            components: members.map(component)))
            if container.kind == .app, ownBit {
                login.append(LoginItem(name: container.name, identifier: container.identifier,
                                       bundlePath: container.bundlePath))
            }
        }
        rows.sort {
            let l = $0.name.lowercased(), r = $1.name.lowercased()
            return l != r ? l < r : $0.kind.rawValue < $1.kind.rawValue
        }
        login.sort { $0.name.lowercased() < $1.name.lowercased() }
        return BackgroundView(loginItems: login, background: rows, note: derivationNote)
    }

    public func renderText() -> String {
        var out: [String] = []
        let apps = background.filter { $0.kind == .app }.count
        let developers = background.count - apps
        out.append("Login Items & Extensions — as System Settings shows them")
        out.append("")
        out.append("Open at Login (\(loginItems.count))")
        if loginItems.isEmpty {
            out.append("  (none)")
        } else {
            out.append("  NAME                              KIND  PATH")
            for item in loginItems {
                out.append("  " + pad(TableRenderer.truncate(item.name, 32), 32) + "  App   " + (item.bundlePath ?? "-"))
            }
        }
        out.append("")
        out.append("Allow in the Background (\(background.count) rows: \(apps) apps, \(developers) developers)")
        out.append("  TOGGLE     KIND       NAME                                TEAM        COMPONENTS")
        for row in background {
            var line = "  " + pad(row.toggle.rawValue, 9) + "  " + pad(row.kind.rawValue, 9) + "  "
                + pad(TableRenderer.truncate(row.name, 34), 34) + "  " + pad(row.teamIdentifier ?? "-", 10) + "  "
                + String(row.components.count)
            if row.components.isEmpty {
                line += row.toggle == .appLevel
                    ? "   (the app itself is registered — on)"
                    : "   (nothing registered — stale row?)"
            }
            out.append(line)
            if !row.components.isEmpty {
                out.append("            ID  NAME                                  TYPE            BTM       LAUNCHD   STATE")
            }
            for c in row.components {
                var flags: [String] = []
                if c.orphaned { flags.append(c.leftover ? "LEFTOVER" : "ORPHAN") }
                let launchd = c.launchdDisabled ? "DISABLED*" : (c.btmEnabled ? "enabled" : "-")
                out.append("            " + pad(c.id, 2) + "  " + pad(TableRenderer.truncate(c.name, 36), 36) + "  "
                           + pad(c.type, 14) + "  " + pad(c.btmEnabled ? "enabled" : "disabled", 8) + "  "
                           + pad(launchd, 9) + "  " + pad(c.running ? "RUNNING" : "-", 7)
                           + (flags.isEmpty ? "" : "  " + flags.joined(separator: " ")))
            }
        }
        if background.contains(where: { $0.components.contains { $0.launchdDisabled } }) {
            out.append("")
            out.append("  * DISABLED in launchd (launchctl override) while BTM still says enabled — the pane shows ON; "
                       + "the job will not run. `launchkeeper enable <label> --apply` lifts the override.")
        }
        out.append("")
        out.append(note)
        return out.joined(separator: "\n")
    }

    private func pad(_ s: String, _ n: Int) -> String {
        s.count >= n ? s : s + String(repeating: " ", count: n - s.count)
    }
}
