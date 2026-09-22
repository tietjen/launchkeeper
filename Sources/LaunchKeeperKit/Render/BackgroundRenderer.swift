import Foundation

/// The System Settings › General › Login Items & Extensions pane, rebuilt
/// from the inventory: "Open at Login" (login items) and "Allow in the
/// Background" (one row per app or developer, its components beneath).
///
/// The switch state is DERIVED from the components' enabled state — the
/// container's own BTM disposition bit is not the switch (it reads
/// `disabled` for 48 of 49 containers on a healthy Mac). launchkeeper never
/// writes to Background Task Management; the switch lives in System Settings.
public struct BackgroundView: Codable {
    /// `on`/`off`/`mixed` from the components; `appLevel` when the app itself
    /// is the registration (no components, the container's own bit says
    /// enabled — the SMAppService shape); `none` when nothing is registered.
    public enum Toggle: String, Codable { case on, off, mixed, appLevel = "app-level", none }

    public struct Component: Codable, Equatable {
        public var id: String
        public var name: String
        public var label: String?
        public var type: String
        public var category: ItemCategory
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
        /// The container's own bit, for the record — not the switch.
        public var rawDisposition: [String]
        public var components: [Component]
    }

    public var loginItems: [Component]
    public var background: [Row]
    public var note: String

    public static let derivationNote =
        "TOGGLE is derived from the components (all enabled = on, all disabled = off, "
        + "mixed otherwise). app-level = the app itself is the registration (no "
        + "components, its own bit says enabled); none = nothing registered. Apart from "
        + "app-level rows the container's own BTM bit is not the switch. Change it in "
        + "System Settings › General › Login Items & Extensions — launchkeeper does not "
        + "write to Background Task Management."

    public static func build(from report: ScanReport) -> BackgroundView {
        func component(_ item: BackgroundItem) -> Component {
            Component(id: item.id, name: item.displayName, label: item.label,
                      type: item.metadata["btm-type"] ?? item.type.rawValue,
                      category: item.category, enabled: item.enabled, running: item.running,
                      orphaned: item.orphaned, leftover: item.metadata["btm-leftover"] == "true",
                      parentName: item.parentApplication)
        }
        let byParent = Dictionary(grouping: report.items.filter { $0.metadata["btm-parent"] != nil },
                                  by: { $0.metadata["btm-parent"]! })
        let byIdentifier = Dictionary(report.items.compactMap { item in
            item.metadata["btm-identifier"].map { ($0, item) } }, uniquingKeysWith: { a, _ in a })

        var rows: [Row] = []
        for container in report.btmContainers {
            var members = byParent[container.identifier] ?? []
            for child in container.embedded {
                if let item = byIdentifier[child], !members.contains(where: { $0.key == item.key }) {
                    members.append(item)
                }
            }
            members.sort { $0.displayName.lowercased() < $1.displayName.lowercased() }
            let toggle: Toggle
            if members.isEmpty {
                toggle = container.dispositionTokens.contains("enabled") ? .appLevel : .none
            } else if members.allSatisfy({ $0.enabled }) { toggle = .on }
            else if members.allSatisfy({ !$0.enabled }) { toggle = .off }
            else { toggle = .mixed }
            rows.append(Row(name: container.name, kind: container.kind, identifier: container.identifier,
                            teamIdentifier: container.teamIdentifier, toggle: toggle,
                            rawDisposition: container.dispositionTokens,
                            components: members.map(component)))
        }
        rows.sort {
            let l = $0.name.lowercased(), r = $1.name.lowercased()
            return l != r ? l < r : $0.kind.rawValue < $1.kind.rawValue
        }
        // "Open at Login" lists login items only; an app's "background app
        // refresh" registration is a component under its own row above.
        let login = report.items.filter { $0.metadata["btm-type"] == "login item" }
            .sorted { $0.displayName.lowercased() < $1.displayName.lowercased() }
            .map(component)
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
            out.append("  ID  ENABLED  STATE    NAME                              APP")
            for c in loginItems {
                out.append("  " + pad(c.id, 2) + "  " + pad(c.enabled ? "yes" : "no", 7) + "  "
                           + pad(c.running ? "RUNNING" : "-", 7) + "  " + pad(c.name, 32) + "  " + (c.parentName ?? "-"))
            }
        }
        out.append("")
        out.append("Allow in the Background (\(background.count) rows: \(apps) apps, \(developers) developers)")
        out.append("  TOGGLE  KIND       NAME                                TEAM        COMPONENTS")
        for row in background {
            var line = "  " + pad(row.toggle.rawValue, 6) + "  " + pad(row.kind.rawValue, 9) + "  "
                + pad(TableRenderer.truncate(row.name, 34), 34) + "  " + pad(row.teamIdentifier ?? "-", 10) + "  "
                + String(row.components.count)
            if row.components.isEmpty {
                line += row.toggle == .appLevel
                    ? "   (the app itself is registered — on)"
                    : "   (nothing registered — stale row?)"
            }
            out.append(line)
            for c in row.components {
                var flags: [String] = []
                if c.orphaned { flags.append(c.leftover ? "LEFTOVER" : "ORPHAN") }
                out.append("            " + pad(c.id, 2) + "  " + pad(TableRenderer.truncate(c.name, 36), 36) + "  "
                           + pad(c.type, 14) + "  " + pad(c.enabled ? "enabled" : "disabled", 8) + "  "
                           + pad(c.running ? "RUNNING" : "-", 7) + (flags.isEmpty ? "" : "  " + flags.joined(separator: " ")))
            }
        }
        out.append("")
        out.append(note)
        return out.joined(separator: "\n")
    }

    private func pad(_ s: String, _ n: Int) -> String {
        s.count >= n ? s : s + String(repeating: " ", count: n - s.count)
    }
}
