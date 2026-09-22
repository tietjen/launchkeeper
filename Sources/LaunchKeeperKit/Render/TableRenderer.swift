import Foundation

/// Plain-text table renderers. Column width is computed from content; NAME is
/// truncated at 44 chars. Stable output = testable output.
public enum TableRenderer {
    public enum Mode { case table, orphans }

    public static func render(_ items: [BackgroundItem], mode: Mode) -> String {
        guard !items.isEmpty else { return "no entries match the given filters" }

        let header: [String]
        var rows: [[String]] = []

        switch mode {
        case .table:
            // The APP column appears only when at least one item resolved a
            // parent application — a column of dashes would be noise
            // (Rausch-Unterdrückung is policy, not aesthetics).
            let showApp = items.contains { $0.parentApplication != nil }
            header = showApp
                ? ["ID", "DOMAIN", "TYPE", "STATE", "SIG", "NAME", "APP", "FLAGS"]
                : ["ID", "DOMAIN", "TYPE", "STATE", "SIG", "NAME", "FLAGS"]
            rows = items.map { item in
                var cells = [item.id, item.domain.rawValue, item.type.rawValue,
                             stateText(item), item.codeSignatureStatus ?? "-",
                             truncate(item.displayName, 44)]
                if showApp { cells.append(truncate(item.parentApplication ?? "-", 20)) }
                cells.append(flagsText(item))
                return cells
            }
        case .orphans:
            header = ["ID", "NAME", "STATE", "CONF", "REASON"]
            rows = items.map { item in
                [item.id, truncate(orphanName(item), 40), stateText(item),
                 item.orphanConfidence?.rawValue ?? "-",
                 truncate(item.orphanReasons.joined(separator: "; "), 60)]
            }
        }

        var widths = header.map(\.count)
        for row in rows {
            for (i, cell) in row.enumerated() {
                widths[i] = max(widths[i], cell.count)
            }
        }

        func line(_ cells: [String]) -> String {
            cells.enumerated()
                .map { (i, cell) in cell.padding(toLength: widths[i], withPad: " ", startingAt: 0) }
                .joined(separator: "  ")
                .trimmingCharacters(in: .whitespaces)
        }

        var out = line(header)
        out += "\n" + String(repeating: "-", count: header.enumerated()
            .map { widths[$0.offset] + 2 }.reduce(0, +))
        for row in rows { out += "\n" + line(row) }
        return out
    }

    static func stateText(_ item: BackgroundItem) -> String {
        if item.running { return "RUNNING" }
        if item.loaded { return "LOADED" }
        return "-"
    }

    static func flagsText(_ item: BackgroundItem) -> String {
        var flags: [String] = []
        if item.orphaned { flags.append(item.metadata["btm-leftover"] == "true" ? "LEFTOVER" : "ORPHAN") }
        if !item.enabled { flags.append("DISABLED") }
        let short: [String: String] = [
            "temp-or-hidden-path": "TEMP/PATH",
            "shell-interpreter-service": "SHELL",
            "unsigned-executable": "UNSIGNED",
            "user-writable-daemon-binary": "USER-WRITABLE",
            "downloads-executable": "DOWNLOADS",
        ]
        flags.append(contentsOf: item.riskFlags.compactMap { short[$0] ?? $0 })
        return flags.joined(separator: " ")
    }

    static func orphanName(_ item: BackgroundItem) -> String {
        var name = item.displayName
        if let exec = item.executable, !item.displayName.contains((exec as NSString).lastPathComponent) {
            name += " [" + exec + "]"
        }
        return name
    }

    static func truncate(_ s: String, _ limit: Int) -> String {
        s.count <= limit ? s : String(s.prefix(limit - 1)) + "…"
    }
}

/// Detail block for `launchkeeper inspect <id>`. Includes read-only follow-up
/// commands the USER may run — launchkeeper itself never executes them.
public enum InspectRenderer {
    public static func render(_ item: BackgroundItem, uid: Int) -> String {
        var lines: [String] = []
        lines.append("[\(item.id)] \(item.displayName)")
        lines.append("  type:      \(item.type.rawValue)")
        lines.append("  domain:    \(item.domain.rawValue)")
        lines.append("  state:     \(TableRenderer.stateText(item))"
            + (item.pid.map { " (pid \($0))" } ?? ""))
        lines.append("  enabled:   \(item.enabled)")
        lines.append("  category:  \(item.category.rawValue)")
        if let control = item.control {
            let actions = control.actions.isEmpty ? "" : " (" + control.actions.joined(separator: ", ") + ")"
            lines.append("  control:   \(control.level.rawValue)\(actions) — \(control.reason)")
        }
        if let origin = item.provenance {
            lines.append("  origin:    \(origin.kind.rawValue)" + (origin.detail.map { " (\($0))" } ?? ""))
        }

        if let path = item.path { lines.append("  path:      \(path)") }
        if let exec = item.executable {
            lines.append("  exec:      \(exec)"
                + (item.arguments.isEmpty ? "" : " " + item.arguments.joined(separator: " ")))
        }
        if let label = item.label {
            let domainTarget = RemediationPlanner.domainTarget(for: item, uid: uid)
            lines.append("  launchd:   \(label) (loaded: \(item.loaded), \(domainTarget))")
        }
        if let parent = item.parentApplication {
            lines.append("  parent:    \(parent) (bundle present: \(item.appPresent.map(String.init) ?? "unknown"))")
        }
        if let dev = item.developer { lines.append("  developer: \(dev)") }
        if let team = item.teamIdentifier { lines.append("  team:      \(team)") }
        if let bundle = item.bundleIdentifier { lines.append("  bundle:    \(bundle)") }
        if let sig = item.codeSignatureStatus { lines.append("  signature: \(sig)") }

        if !item.sources.isEmpty {
            lines.append("  sources:")
            for src in item.sources {
                lines.append("    \(src.kind.rawValue)(\(src.confidence.rawValue)): \(src.detail)")
            }
        }
        if !item.metadata.isEmpty {
            lines.append("  metadata:")
            for key in item.metadata.keys.sorted() {
                lines.append("    \(key): \(item.metadata[key]!)")
            }
        }
        let flags = TableRenderer.flagsText(item)
        if !flags.isEmpty { lines.append("  flags:     \(flags)") }
        if !item.orphanReasons.isEmpty {
            lines.append("  reasons:")
            for reason in item.orphanReasons { lines.append("    - \(reason)") }
        }

        lines.append("  next steps (read-only, run these yourself):")
        if item.label != nil {
            lines.append("    launchctl print \(RemediationPlanner.displayTarget(for: item, uid: uid))")
        }
        if let path = item.path, path.hasPrefix("/") {
            lines.append("    ls -lO '\(path)'")
        }
        // Reversible remediation hint (V0.2, gated). Deliberately absent for
        // Apple-owned and /System-backed entries — the gate refuses those.
        if let label = item.label, !label.hasPrefix("com.apple."),
           !(item.path ?? "").hasPrefix("/System"),
           !(item.executable.map { PathUtils.canonicalize($0).hasPrefix("/System") } ?? false) {
            let hint = item.enabled ? "launchkeeper disable \(item.id)" : "launchkeeper enable \(item.id)"
            lines.append("    \(hint) — reversible override (dry-run first, --apply executes)")
        }
        return lines.joined(separator: "\n")
    }
}

/// JSON output: stable keys, sorted, pretty-printed.
public enum JSONRenderer {
    public static func encode(_ value: some Encodable) throws -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        let data = try encoder.encode(value)
        return String(decoding: data, as: UTF8.self)
    }
}
