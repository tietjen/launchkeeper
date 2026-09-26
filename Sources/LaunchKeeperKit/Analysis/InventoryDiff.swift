import Foundation

// V0.6.1 — `launchkeeper diff`: what changed between a snapshot and now (or
// between two snapshots). Compares by key. Configuration fields only by
// default — a process that happens to be running is not a change in what
// is set up to run; `--state` adds loaded/running.

public struct InventoryDiff: Codable, Equatable {
    public struct Change: Codable, Equatable, Sendable {
        public var field: String
        public var before: String
        public var after: String
    }
    public struct Entry: Codable, Equatable {
        public var key: String
        public var displayName: String
        public var category: String
        public var type: String
        public var path: String?
        public var appleInternal: Bool
        public var changes: [Change]
    }
    public var added: [Entry]
    public var removed: [Entry]
    public var changed: [Entry]
    public var before: String
    public var after: String

    public var isEmpty: Bool { added.isEmpty && removed.isEmpty && changed.isEmpty }

    /// The fields a diff looks at, in display order.
    static func fields(of item: BackgroundItem, includeState: Bool) -> [(String, String)] {
        var out: [(String, String)] = [
            ("category", item.category.rawValue),
            ("type", item.type.rawValue),
            ("enabled", item.enabled ? "true" : "false"),
            ("path", item.path ?? "-"),
            ("executable", item.executable ?? "-"),
            ("signature", item.codeSignatureStatus ?? "-"),
            ("team", item.metadata["signature-team"] ?? "-"),
            ("orphaned", item.orphaned ? "true" : "false"),
            ("origin", item.provenance.map { $0.kind.rawValue + ($0.packageIdentifier.map { " " + $0 } ?? "") } ?? "-"),
            ("control", item.control?.level.rawValue ?? "-"),
        ]
        for key in ["schedule", "listening", "firewall", "helper-clients", "sysext-state", "ext-election",
                    "shell-launch-hints", "shell-sources", "auth-login-mechanism", "btm-disposition"] {
            if let value = item.metadata[key] { out.append((key, value)) }
        }
        if includeState {
            out.append(("loaded", item.loaded ? "true" : "false"))
            out.append(("running", item.running ? "true" : "false"))
        }
        return out
    }

    static func entry(_ item: BackgroundItem, changes: [Change] = []) -> Entry {
        Entry(key: item.key, displayName: item.displayName, category: item.category.rawValue, type: item.type.rawValue,
              path: item.path, appleInternal: ListFilter.isAppleInternal(item), changes: changes)
    }

    public static func compare(before: [BackgroundItem], after: [BackgroundItem], includeState: Bool = false,
                               beforeLabel: String, afterLabel: String) -> InventoryDiff {
        let beforeByKey = Dictionary(before.map { ($0.key, $0) }, uniquingKeysWith: { a, _ in a })
        let afterByKey = Dictionary(after.map { ($0.key, $0) }, uniquingKeysWith: { a, _ in a })
        var diff = InventoryDiff(added: [], removed: [], changed: [], before: beforeLabel, after: afterLabel)
        for item in after where beforeByKey[item.key] == nil { diff.added.append(entry(item)) }
        for item in before where afterByKey[item.key] == nil { diff.removed.append(entry(item)) }
        for item in after {
            guard let old = beforeByKey[item.key] else { continue }
            let oldFields = Dictionary(fields(of: old, includeState: includeState), uniquingKeysWith: { a, _ in a })
            var changes: [Change] = []
            for (field, value) in fields(of: item, includeState: includeState) {
                let previous = oldFields[field] ?? "-"
                if previous != value { changes.append(Change(field: field, before: previous, after: value)) }
            }
            for (field, previous) in oldFields where fields(of: item, includeState: includeState).first(where: { $0.0 == field }) == nil {
                changes.append(Change(field: field, before: previous, after: "-"))
            }
            if !changes.isEmpty { diff.changed.append(entry(item, changes: changes)) }
        }
        let byName: (Entry, Entry) -> Bool = { $0.displayName.lowercased() < $1.displayName.lowercased() }
        diff.added.sort(by: byName); diff.removed.sort(by: byName); diff.changed.sort(by: byName)
        return diff
    }

    /// Apple-internal rows hidden unless `includeAll`, like `list`.
    public func filtered(includeAll: Bool) -> InventoryDiff {
        guard !includeAll else { return self }
        var copy = self
        copy.added = added.filter { !$0.appleInternal }
        copy.removed = removed.filter { !$0.appleInternal }
        copy.changed = changed.filter { !$0.appleInternal }
        return copy
    }

    public func renderText() -> String {
        var lines = ["diff: \(before) → \(after)"]
        if isEmpty {
            lines.append("no changes")
            return lines.joined(separator: "\n")
        }
        func describe(_ entry: Entry) -> String {
            "\(entry.displayName) [\(entry.category)/\(entry.type)]" + (entry.path.map { " " + $0 } ?? "")
        }
        for entry in added { lines.append("+ " + describe(entry)) }
        for entry in removed { lines.append("- " + describe(entry)) }
        for entry in changed {
            lines.append("~ " + describe(entry))
            for change in entry.changes { lines.append("    \(change.field): \(change.before) → \(change.after)") }
        }
        lines.append("")
        lines.append("\(added.count) added, \(removed.count) removed, \(changed.count) changed")
        return lines.joined(separator: "\n")
    }
}
