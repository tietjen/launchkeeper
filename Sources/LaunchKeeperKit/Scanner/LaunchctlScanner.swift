import Foundation

/// Tolerant parser for `launchctl print <domain>` and `launchctl print-disabled <domain>`.
///
/// Observed shapes (macOS 26.6.2, captured live):
///   services = {
///              61675      -  com.apple.diskimagesiod.10000001-...
///                  0   (pe)  com.apple.lskdd
///               30475   (pe) com.apple.syncdefaultsd
///   }
///   "com.searchco.updater.agent" => disabled        (inside print-disabled)
public enum LaunchctlParser {
    /// Parses service lines from a `launchctl print` dump.
    /// A line is a service when it has exactly 3 whitespace-separated tokens inside
    /// a `services = {` region and the last token looks like a reverse-DNS label.
    public static func parsePrint(_ text: String, domainKind: String) -> [LaunchdServiceRecord] {
        var records: [LaunchdServiceRecord] = []
        var inServices = false
        for line in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("services = {") { inServices = true; continue }
            guard inServices else { continue }
            if trimmed == "}" { inServices = false; continue }
            let tokens = trimmed.split(whereSeparator: { $0 == " " || $0 == "\t" })
            guard tokens.count == 3 else { continue }
            let label = String(tokens[2])
            guard label.contains("."), label != "}" else { continue }
            let pidToken = String(tokens[0])
            let pid = Int(pidToken).flatMap { $0 > 0 ? $0 : nil }
            records.append(LaunchdServiceRecord(
                label: label, domainKind: domainKind,
                pid: pid, stateToken: String(tokens[1])
            ))
        }
        return records
    }

    /// Parses `print-disabled` output: `"label" => enabled|disabled`.
    /// Keys may carry a Team-ID prefix ("ABCDE12345.com.example.browser-helper").
    public static func parseDisabled(_ text: String) -> [String: Bool] {
        var result: [String: Bool] = [:]
        for line in text.split(separator: "\n") {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("\""), trimmed.contains("=>") else { continue }
            guard let quoteEnd = trimmed.dropFirst().firstIndex(of: "\"") else { continue }
            let label = String(trimmed[trimmed.index(after: trimmed.startIndex)..<quoteEnd])
            let rest = trimmed[trimmed.index(quoteEnd, offsetBy: 2)...]
            if rest.contains("disabled") { result[label] = false }
            else if rest.contains("enabled") { result[label] = true }
        }
        return result
    }

    /// True for instantiable services with a per-instance suffix (UUID/PID-like).
    /// These are launchd bookkeeping, not persistent configuration — excluded from
    /// the default inventory to keep the signal usable.
    public static func isInstanceService(_ label: String) -> Bool {
        guard label.hasPrefix("com.apple.") else { return false }
        let parts = label.split(separator: ".")
        guard let last = parts.last, parts.count > 2 else { return false }
        let uuidLike = last.count >= 8 && last.contains(where: { $0 == "-" })
        let hexLike = last.count >= 8 && last.allSatisfy { $0.isHexDigit }
        let longNumeric = last.count >= 8 && last.allSatisfy { $0.isNumber }
        return uuidLike || hexLike || longNumeric
    }
}