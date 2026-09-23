import Foundation

// V0.6.1 — `list --csv` / `list --markdown`: the inventory for spreadsheets
// and reports. Same rows as the table, more columns, nothing interpreted.

public enum ExportRenderer {
    public static let columns = ["id", "key", "category", "type", "domain", "state", "enabled", "signature", "team",
                                 "name", "app", "path", "executable", "origin", "package", "installed", "flags",
                                 "orphan_reasons", "control"]

    static func cells(_ item: BackgroundItem) -> [String] {
        [item.id, item.key, item.category.rawValue, item.type.rawValue, item.domain.rawValue,
         TableRenderer.stateText(item), item.enabled ? "true" : "false", item.codeSignatureStatus ?? "",
         item.metadata["signature-team"] ?? "", item.displayName, item.parentApplication ?? "",
         item.path ?? "", item.executable ?? "", item.provenance?.kind.rawValue ?? "",
         item.provenance?.packageIdentifier ?? "", item.provenance?.installedAt ?? "",
         TableRenderer.flagsText(item), item.orphanReasons.joined(separator: "; "),
         item.control?.level.rawValue ?? ""]
    }

    static func csvField(_ text: String) -> String {
        guard text.contains(where: { $0 == "," || $0 == "\"" || $0 == "\n" || $0 == "\r" }) else { return text }
        return "\"" + text.replacingOccurrences(of: "\"", with: "\"\"") + "\""
    }

    public static func csv(_ items: [BackgroundItem]) -> String {
        var lines = [columns.joined(separator: ",")]
        for item in items { lines.append(cells(item).map(csvField).joined(separator: ",")) }
        return lines.joined(separator: "\n")
    }

    static func markdownCell(_ text: String) -> String {
        text.replacingOccurrences(of: "|", with: "\\|").replacingOccurrences(of: "\n", with: " ")
    }

    public static func markdown(_ items: [BackgroundItem]) -> String {
        let header = ["ID", "Category", "Type", "Domain", "State", "Signature", "Name", "App", "Origin", "Path", "Flags"]
        var lines = ["| " + header.joined(separator: " | ") + " |",
                     "|" + header.map { _ in " --- " }.joined(separator: "|") + "|"]
        for item in items {
            let origin = item.provenance.map { $0.kind.rawValue + ($0.packageIdentifier.map { " (\($0))" } ?? "") } ?? ""
            let row = [item.id, item.category.rawValue, item.type.rawValue, item.domain.rawValue,
                       TableRenderer.stateText(item), item.codeSignatureStatus ?? "-", item.displayName,
                       item.parentApplication ?? "", origin, item.path.map { "`\($0)`" } ?? "", TableRenderer.flagsText(item)]
            lines.append("| " + row.map(markdownCell).joined(separator: " | ") + " |")
        }
        return lines.joined(separator: "\n")
    }
}
