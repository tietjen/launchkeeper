import Foundation

// V0.6.0 — `launchkeeper receipts`: the package receipts behind the
// inventory. One row per receipt: version, install date, how many of its
// files are still on disk, and the entries it accounts for.

public struct ReceiptsView: Codable, Equatable {
    public struct Row: Codable, Equatable {
        public var id: String
        public var version: String?
        public var installedAt: String?
        public var fileCount: Int
        public var missingFiles: Int
        /// Inventory items attributed to this receipt (display name).
        public var items: [String]
        public var apple: Bool
        /// Paths only this package owns — without shared folders
        /// (`/Applications`, `/Library` …), paths other receipts list too, and
        /// AppleDouble entries. Optional so older JSON still decodes.
        ///
        /// Why: `fileCount`/`missingFiles` count every listed path. A receipt
        /// whose app was dragged to the Trash still has "1 present" — the
        /// `/Applications` folder itself (live: ai.abacus.abacusai, 15,245
        /// listed, the one present was /Applications). Judged by its own
        /// files, such a package is gone, not "partially installed".
        public var ownFileCount: Int?
        /// Own paths that are no longer on disk.
        public var ownMissingFiles: Int?
    }
    public var rows: [Row]
    public var indexed: Bool


    public static func build(from report: ScanReport, fileManager: FileManager = .default,
                             includeApple: Bool = false) -> ReceiptsView {
        guard let index = report.receiptIndex else { return ReceiptsView(rows: [], indexed: false) }
        var itemsByPackage: [String: [String]] = [:]
        for item in report.items {
            if let id = item.provenance?.packageIdentifier {
                itemsByPackage[id, default: []].append(item.displayName)
            }
        }
        var rows: [Row] = []
        for receipt in index.receipts.values where includeApple || !receipt.isApple {
            var missing = 0, own = 0, ownMissing = 0
            for path in receipt.files {
                let exists = fileManager.fileExists(atPath: path)
                if !exists { missing += 1 }
                let appleDouble = (path as NSString).lastPathComponent.hasPrefix("._")
                guard !appleDouble, !ReceiptIndex.isSharedRoot(path), !index.shared.contains(path) else { continue }
                own += 1
                if !exists { ownMissing += 1 }
            }
            rows.append(Row(id: receipt.id, version: receipt.version,
                            installedAt: receipt.installTime.map(ProvenanceResolver.dayString),
                            fileCount: receipt.files.count, missingFiles: missing,
                            items: (itemsByPackage[receipt.id] ?? []).sorted(), apple: receipt.isApple,
                            ownFileCount: own, ownMissingFiles: ownMissing))
        }
        // Newest first; ties by id.
        rows.sort { a, b in
            if a.installedAt != b.installedAt { return (a.installedAt ?? "") > (b.installedAt ?? "") }
            return a.id < b.id
        }
        return ReceiptsView(rows: rows, indexed: true)
    }

    public func renderText() -> String {
        guard indexed else { return "package receipts not indexed — pkgutil did not answer (see doctor)" }
        if rows.isEmpty { return "no package receipts" }
        let header = ["PACKAGE", "VERSION", "INSTALLED", "FILES", "MISSING", "ENTRIES"]
        let body = rows.map { row -> [String] in
            [row.id, row.version ?? "-", row.installedAt ?? "-", String(row.fileCount),
             row.missingFiles == 0 ? "-" : String(row.missingFiles),
             row.items.isEmpty ? "-" : row.items.joined(separator: ", ")]
        }
        let widths = (0..<header.count).map { col in
            min(max(header[col].count, body.map { $0[col].count }.max() ?? 0), col == 0 ? 52 : (col == 5 ? 60 : 24))
        }
        func pad(_ text: String, _ width: Int) -> String {
            let clipped = text.count > width ? String(text.prefix(width - 1)) + "…" : text
            return clipped.padding(toLength: width, withPad: " ", startingAt: 0)
        }
        var lines = [zip(header, widths).map { pad($0, $1) }.joined(separator: "  ")]
        lines.append(String(repeating: "-", count: widths.reduce(0, +) + 2 * (widths.count - 1)))
        for row in body { lines.append(zip(row, widths).map { pad($0, $1) }.joined(separator: "  ")) }
        let missing = rows.filter { $0.missingFiles > 0 }.count
        lines.append("")
        lines.append("\(rows.count) receipts, \(missing) with missing files, "
            + "\(rows.filter { !$0.items.isEmpty }.count) behind inventory entries")
        if missing > 0 {
            lines.append("take a package away (dry-run first): launchkeeper uninstall <package id>")
        }
        return lines.joined(separator: "\n")
    }
}
