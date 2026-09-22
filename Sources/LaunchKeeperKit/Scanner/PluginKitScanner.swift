import Foundation

/// One registered app extension as `pluginkit -mAvv` reports it.
public struct AppExtensionRecord: Equatable, Codable {
    /// The user election tag at the start of the line (`man pluginkit`).
    public enum Election: String, Codable {
        case use          // "+" the user elected to use the plug-in
        case ignore       // "-" the user elected to ignore it
        case debug        // "!" elected for debugger use
        case superseded   // "=" superseded by another plug-in
        case unknown      // "?" unknown election state
        case none         // no tag: no user election, the default state

        init(tag: String) {
            switch tag {
            case "+": self = .use
            case "-": self = .ignore
            case "!": self = .debug
            case "=": self = .superseded
            case "?": self = .unknown
            default: self = .none
            }
        }
    }

    public var identifier: String
    public var version: String
    public var election: Election
    public var path: String?
    public var uuid: String?
    public var sdk: String?            // the extension point, e.g. com.apple.quicklook.preview
    public var parentBundle: String?
    public var displayName: String?
    public var shortName: String?
    public var parentName: String?
    public var platform: String?

    public init(identifier: String, version: String, election: Election, path: String? = nil,
                uuid: String? = nil, sdk: String? = nil, parentBundle: String? = nil,
                displayName: String? = nil, shortName: String? = nil, parentName: String? = nil,
                platform: String? = nil) {
        self.identifier = identifier; self.version = version; self.election = election
        self.path = path; self.uuid = uuid; self.sdk = sdk; self.parentBundle = parentBundle
        self.displayName = displayName; self.shortName = shortName; self.parentName = parentName
        self.platform = platform
    }

    /// Ignored by the user → not enabled. Everything else runs when its host asks.
    public var enabled: Bool { election != .ignore }
}

/// Tolerant parser for `pluginkit -mAvv` (macOS 26/27, captured live):
///
///     +    com.example.app.ShareExt(1.2)
///                     Path = /Applications/Example.app/Contents/PlugIns/ShareExt.appex
///                     UUID = 22361EB9-…
///                Timestamp = 2026-09-22 05:55:01 +0000
///                      SDK = com.apple.share-services
///            Parent Bundle = /Applications/Example.app
///             Display Name = ShareExt
///
/// A header is "<tag><spaces><identifier>(<version>)"; `-A` lists every
/// version of an identifier, so the same identifier may recur.
public enum PluginKitParser {
    // The version may itself be parenthesised — "com.apple.fskit.exfat((null))" —
    // so the version group allows one level of nested parentheses.
    private static let header = try! NSRegularExpression(
        pattern: #"^([+\-!=?]?)\s+(\S+?)\(((?:\([^()]*\)|[^()])*)\)\s*$"#)

    public static func parse(_ text: String) -> (records: [AppExtensionRecord], warnings: [String]) {
        var records: [AppExtensionRecord] = []
        var warnings: [String] = []
        var current: AppExtensionRecord?

        func flush() {
            if let record = current { records.append(record) }
            current = nil
        }

        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = String(rawLine)
            if line.trimmingCharacters(in: .whitespaces).isEmpty { flush(); continue }
            let range = NSRange(line.startIndex..., in: line)
            if let match = header.firstMatch(in: line, range: range) {
                flush()
                let tag = String(line[Range(match.range(at: 1), in: line)!])
                let identifier = String(line[Range(match.range(at: 2), in: line)!])
                let version = String(line[Range(match.range(at: 3), in: line)!])
                current = AppExtensionRecord(identifier: identifier, version: version,
                                             election: AppExtensionRecord.Election(tag: tag))
                continue
            }
            guard current != nil, let eq = line.range(of: " = ") else {
                if current != nil { warnings.append("pluginkit: unparsed line: \(line.trimmingCharacters(in: .whitespaces))") }
                continue
            }
            let key = line[..<eq.lowerBound].trimmingCharacters(in: .whitespaces)
            let value = String(line[eq.upperBound...]).trimmingCharacters(in: .whitespaces)
            switch key {
            case "Path": current?.path = value
            case "UUID": current?.uuid = value
            case "SDK": current?.sdk = value
            case "Parent Bundle": current?.parentBundle = value
            case "Display Name": current?.displayName = value
            case "Short Name": current?.shortName = value
            case "Parent Name": current?.parentName = value
            case "Platform": current?.platform = value
            case "Timestamp": break
            default: break   // unknown keys are tolerated, not reported
            }
        }
        flush()
        return (records, warnings)
    }
}

/// Runs `pluginkit -mAvv` through the runner seam (read-only; pluginkit's
/// `-e` election changes are deliberately NOT here — they belong to V0.7).
public struct PluginKitScanner {
    public var runner: CommandRunner
    public var timeout: TimeInterval = 30

    public init(runner: CommandRunner) { self.runner = runner }

    public func scan() -> (records: [AppExtensionRecord], warnings: [String], exitCode: Int32) {
        let result = runner.run(command: "/usr/bin/pluginkit", arguments: ["-mAvv"], timeout: timeout)
        guard result.exitCode == 0 else {
            return ([], ["pluginkit -mAvv failed (exit \(result.exitCode)) — app extensions not scanned"], result.exitCode)
        }
        let (records, warnings) = PluginKitParser.parse(result.stdout)
        return (records, warnings, 0)
    }
}
