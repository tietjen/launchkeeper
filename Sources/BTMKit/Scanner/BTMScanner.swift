import Foundation

/// Tolerant line-oriented parser for `sfltool dumpbtm` (macOS 26 format, captured live):
///
///   Records for UID -2 : FFFFEEEE-...
///    #2:
///                 UUID: 602CB5E1-...
///                 Name: automount-guard.sh
///                 Type: legacy daemon (0x10010)
///           Disposition: [disabled, allowed, not notified] (0x2)
///            Identifier: 16.de.example.automount-guard
///                   URL: file:///Library/LaunchDaemons/de.example.automount-guard.plist
///         Executable Path: /usr/local/bin/automount-guard.sh
///              Generation: 1
///     Embedded Item Identifiers:
///       #1: 16.com.apple.PackageKit.DeferredInstallFixup
///
/// Unknown keys are preserved; a malformed line never aborts the parse.
public enum BTMDumpParser {
    public static func parse(_ text: String) -> (records: [BTMRecord], warnings: [String]) {
        var records: [BTMRecord] = []
        var warnings: [String] = []
        var currentUID = -2
        var fields: [String: String] = [:]
        var trailing: [String] = []
        var inRecord = false

        func flush() {
            if inRecord, !fields.isEmpty {
                records.append(BTMRecord(sectionUID: currentUID, fields: fields, trailingBlock: trailing))
            }
            fields = [:]; trailing = []; inRecord = false
        }

        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = String(rawLine)
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { continue }

            if trimmed.hasPrefix("Records for UID ") {
                flush()
                let rest = trimmed.dropFirst("Records for UID ".count)
                if let space = rest.firstIndex(of: " ") {
                    currentUID = Int(rest[rest.startIndex..<space]) ?? -2
                } else {
                    currentUID = Int(rest) ?? -2
                }
                continue
            }
            if trimmed == "Items:" || trimmed.hasPrefix("====") { continue }

            // Embedded child entries: indented "#N: value".
            if trimmed.hasPrefix("#"), trimmed.contains(": "), inRecord, !fields.isEmpty {
                if let value = trimmed.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
                    .last.map(String.init), value != trimmed {
                    trailing.append(value)
                    continue
                }
            }

            // Record header: "#N:" with nothing meaningful after the colon.
            if trimmed.hasPrefix("#") {
                let afterHash = trimmed.dropFirst()
                if let colon = afterHash.firstIndex(of: ":") {
                    let numberPart = afterHash[afterHash.startIndex..<colon]
                    if numberPart.allSatisfy({ $0.isNumber }),
                       afterHash[afterHash.index(after: colon)...].trimmingCharacters(in: .whitespaces).isEmpty {
                        flush()
                        inRecord = true
                        continue
                    }
                }
                warnings.append("unparsed line: \(trimmed)")
                continue
            }

            // Field line: "      Key: value" — key = letters and spaces before the colon.
            guard let colon = trimmed.firstIndex(of: ":") else {
                if inRecord { warnings.append("unparsed line: \(trimmed)") }
                continue
            }
            let key = String(trimmed[trimmed.startIndex..<colon]).trimmingCharacters(in: .whitespaces)
            let value = String(trimmed[trimmed.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty, key.count <= 40,
                  key.allSatisfy({ $0.isLetter || $0 == " " }),
                  !value.isEmpty, value != "true", value != "false" else {
                // Known list-style keys carry data or are structural noise.
                if key == "Assoc. Bundle IDs", inRecord, !value.isEmpty {
                    fields[key] = value   // real data: associated app bundle ids
                    continue
                }
                if key == "Embedded Item Identifiers", inRecord { continue }
                if key == "ServiceManagement migrated" || key == "LaunchServices registered" { continue }
                if inRecord, !value.isEmpty { warnings.append("unparsed line: \(trimmed)") }
                continue
            }
            guard inRecord else { continue }
            fields[key] = value
        }
        flush()
        return (records, warnings)
    }
}