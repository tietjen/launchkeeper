import Foundation

// V0.5.7 — H "Shell startup": the files every interactive shell runs, what
// they source, and the lines that start things. Display only: launchkeeper
// never edits a shell file, and never prints a line of one — a startup file
// is where people export tokens. Findings are line numbers and keywords.

public struct ShellStartupRecord: Equatable, Sendable {
    public var kind: String              // profile / sourced / paths
    public var path: String
    public var domain: ItemDomain
    public var size: Int
    public var modified: String?
    public var lines: Int
    /// Resolved absolute paths this file sources (depth 1).
    public var sourced: [String]
    /// `source` targets that still contain a variable — not probed.
    public var unresolved: [String]
    public var missingSources: [String]
    /// "line 116: launchctl" — the keyword, never the line.
    public var hints: [String]
    public var sourcedBy: String?
    public init(kind: String, path: String, domain: ItemDomain, size: Int = 0, modified: String? = nil, lines: Int = 0,
                sourced: [String] = [], unresolved: [String] = [], missingSources: [String] = [],
                hints: [String] = [], sourcedBy: String? = nil) {
        self.kind = kind; self.path = path; self.domain = domain; self.size = size; self.modified = modified
        self.lines = lines; self.sourced = sourced; self.unresolved = unresolved; self.missingSources = missingSources
        self.hints = hints; self.sourcedBy = sourcedBy
    }
}

public enum ShellFileParser {
    private static let sourceLine = try! NSRegularExpression(pattern: #"^\s*(?:source|\.)\s+(\S+)"#)
    /// Keyword → pattern. Trailing `&` means a background job (`&&` does not).
    static let hintPatterns: [(String, NSRegularExpression)] = [
        ("launchctl", try! NSRegularExpression(pattern: #"\blaunchctl\b"#)),
        ("nohup", try! NSRegularExpression(pattern: #"\bnohup\b"#)),
        ("background job (&)", try! NSRegularExpression(pattern: #"[^&]&\s*$"#)),
        ("osascript", try! NSRegularExpression(pattern: #"\bosascript\b"#)),
        ("open -a/-b", try! NSRegularExpression(pattern: #"\bopen\s+-[abg]\b"#)),
        ("curl|wget piped to a shell", try! NSRegularExpression(pattern: #"\b(?:curl|wget)\b.*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b"#)),
        ("eval of a command substitution", try! NSRegularExpression(pattern: #"\beval\s+"?\$\("#)),
        ("crontab", try! NSRegularExpression(pattern: #"\bcrontab\b"#)),
        ("defaults write", try! NSRegularExpression(pattern: #"\bdefaults\s+write\b"#)),
    ]

    public struct Parsed: Equatable {
        public var sourced: [String] = []
        public var unresolved: [String] = []
        public var hints: [String] = []
        public var lines = 0
    }

    public static func parse(_ text: String, home: String, baseDirectory: String) -> Parsed {
        var parsed = Parsed()
        let lines = text.components(separatedBy: "\n")
        parsed.lines = lines.count
        for (index, line) in lines.enumerated() {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
            let range = NSRange(line.startIndex..., in: line)
            if let m = sourceLine.firstMatch(in: line, range: range), let r = Range(m.range(at: 1), in: line) {
                var target = String(line[r]).trimmingCharacters(in: CharacterSet(charactersIn: "\"'"))
                if target.hasPrefix("~/") { target = home + target.dropFirst() }
                target = target.replacingOccurrences(of: "${HOME}", with: home).replacingOccurrences(of: "$HOME", with: home)
                if target.contains("$") {
                    parsed.unresolved.append(target)
                } else {
                    parsed.sourced.append(target.hasPrefix("/") ? target : baseDirectory + "/" + target)
                }
            }
            // Aliases and comments define nothing that runs at startup.
            if trimmed.hasPrefix("alias ") { continue }
            for (keyword, pattern) in hintPatterns where pattern.firstMatch(in: line, range: range) != nil {
                parsed.hints.append("line \(index + 1): \(keyword)")
            }
        }
        return parsed
    }
}

public struct ShellStartupScanner {
    public struct Result {
        public var files: [ShellStartupRecord] = []
        public var warnings: [String] = []
        public var checks: [String] = []
        public init() {}
    }

    let fileManager: FileManager
    let home: String
    let userFiles: [String]
    let systemFiles: [String]
    let pathsDirectories: [String]

    public static let defaultUserFiles = [".zshenv", ".zprofile", ".zshrc", ".zlogin", ".zlogout",
                                          ".bash_profile", ".bash_login", ".bashrc", ".bash_logout", ".profile"]
    public static let defaultSystemFiles = ["/etc/zshenv", "/etc/zprofile", "/etc/zshrc", "/etc/zlogin", "/etc/zlogout",
                                            "/etc/zshrc_Apple_Terminal", "/etc/profile", "/etc/bashrc", "/etc/bashrc_Apple_Terminal"]

    public init(fileManager: FileManager = .default, home: String = NSHomeDirectory(),
                userFiles: [String]? = nil, systemFiles: [String]? = nil,
                pathsDirectories: [String] = ["/etc/paths.d", "/etc/manpaths.d"]) {
        self.fileManager = fileManager; self.home = home
        self.userFiles = userFiles ?? Self.defaultUserFiles.map { home + "/" + $0 }
        self.systemFiles = systemFiles ?? Self.defaultSystemFiles
        self.pathsDirectories = pathsDirectories
    }

    private func record(kind: String, path: String, domain: ItemDomain, sourcedBy: String? = nil) -> ShellStartupRecord? {
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { return nil }
        let attrs = try? fileManager.attributesOfItem(atPath: path)
        let parsed = ShellFileParser.parse(text, home: home, baseDirectory: (path as NSString).deletingLastPathComponent)
        var modified: String?
        if let date = attrs?[.modificationDate] as? Date {
            modified = ISO8601DateFormatter().string(from: date)
        }
        return ShellStartupRecord(kind: kind, path: path, domain: domain,
                                  size: (attrs?[.size] as? Int) ?? text.utf8.count, modified: modified,
                                  lines: parsed.lines, sourced: parsed.sourced, unresolved: parsed.unresolved,
                                  missingSources: parsed.sourced.filter { !fileManager.fileExists(atPath: $0) },
                                  hints: parsed.hints, sourcedBy: sourcedBy)
    }

    public func scan() -> Result {
        var result = Result()
        var seen = Set<String>()
        var files: [ShellStartupRecord] = []
        for (list, domain) in [(userFiles, ItemDomain.user), (systemFiles, ItemDomain.system)] {
            for path in list where fileManager.fileExists(atPath: path) {
                guard let record = record(kind: "profile", path: path, domain: domain) else {
                    result.warnings.append("shell startup file unreadable: \(path)")
                    continue
                }
                seen.insert(path)
                files.append(record)
            }
        }
        // Depth 1: what the profiles source, when it exists.
        var sourcedRecords: [ShellStartupRecord] = []
        for profile in files {
            for target in profile.sourced where !seen.contains(target) && fileManager.fileExists(atPath: target) {
                seen.insert(target)
                if let record = record(kind: "sourced", path: target, domain: profile.domain, sourcedBy: profile.path) {
                    sourcedRecords.append(record)
                }
            }
        }
        result.checks.append("shell startup: \(files.count) files, \(sourcedRecords.count) sourced, "
            + "\(files.reduce(0) { $0 + $1.hints.count }) launch hints")
        files.append(contentsOf: sourcedRecords)

        var pathEntries = 0
        for dir in pathsDirectories {
            guard let names = try? fileManager.contentsOfDirectory(atPath: dir) else { continue }
            for name in names.sorted() where !name.hasPrefix(".") {
                let path = dir + "/" + name
                guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
                let entries = text.components(separatedBy: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
                    .filter { !$0.isEmpty }
                // Runtime mounts (/var/run/…, Apple's cryptexes) come and go by design.
                let missing = entries.filter {
                    !$0.hasPrefix("/var/run/") && !$0.hasPrefix("/private/var/run/") && !fileManager.fileExists(atPath: $0)
                }
                files.append(ShellStartupRecord(kind: "paths", path: path, domain: .system, size: text.utf8.count,
                                                lines: entries.count, sourced: entries, missingSources: missing))
                pathEntries += 1
            }
        }
        result.checks.append("paths.d/manpaths.d: \(pathEntries) files")
        result.files = files
        return result
    }
}
