import Foundation

// V0.5.6 — F "Scheduled": cron, at, periodic and pmset power events. launchd
// timers (StartInterval / StartCalendarInterval) stay launch items and carry
// their schedule as metadata; the `scheduled` category view includes them.

public struct CronEntry: Equatable, Sendable {
    public var user: String
    /// "crontab" for the user's own table, else the file path.
    public var source: String
    public var line: Int
    public var schedule: String
    public var command: String
    public init(user: String, source: String, line: Int, schedule: String, command: String) {
        self.user = user; self.source = source; self.line = line; self.schedule = schedule; self.command = command
    }
}

public struct AtJob: Equatable, Sendable {
    public var id: String
    public var when: String
    public var queue: String
    public var owner: String
    public init(id: String, when: String, queue: String, owner: String) {
        self.id = id; self.when = when; self.queue = queue; self.owner = owner
    }
}

public struct PowerEvent: Equatable, Sendable {
    public var index: Int
    public var kind: String          // wake, poweron, sleep, shutdown, restart, wakeorpoweron
    public var when: String
    public var owner: String
    public var userVisible: Bool
    public init(index: Int, kind: String, when: String, owner: String, userVisible: Bool) {
        self.index = index; self.kind = kind; self.when = when; self.owner = owner; self.userVisible = userVisible
    }
}

public struct PeriodicScript: Equatable, Sendable {
    public var period: String        // daily / weekly / monthly / <other dir name>
    public var path: String
    public var name: String
    public init(period: String, path: String, name: String) {
        self.period = period; self.path = path; self.name = name
    }
}

public enum CronParser {
    /// Parses crontab text. Comments, blank lines and VAR=value assignments
    /// are skipped. `@reboot`-style specials keep the token as schedule.
    /// `systemTable` = /etc/crontab layout with a user column after the
    /// five time fields.
    public static func parse(_ text: String, user: String, source: String, systemTable: Bool = false) -> [CronEntry] {
        var entries: [CronEntry] = []
        for (index, raw) in text.components(separatedBy: "\n").enumerated() {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            let tokens = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard let first = tokens.first else { continue }
            if first.hasPrefix("@") {
                var rest = Array(tokens.dropFirst())
                var owner = user
                if systemTable, let u = rest.first { owner = u; rest = Array(rest.dropFirst()) }
                guard !rest.isEmpty else { continue }
                entries.append(CronEntry(user: owner, source: source, line: index + 1,
                                         schedule: first, command: rest.joined(separator: " ")))
                continue
            }
            // VAR=value (no spaces before '=' in the first token)
            if tokens.count >= 1, first.contains("="), !first.hasPrefix("*"), first.first?.isNumber == false { continue }
            let fieldCount = systemTable ? 6 : 5
            guard tokens.count > fieldCount else { continue }
            let schedule = tokens[0..<5].joined(separator: " ")
            let owner = systemTable ? tokens[5] : user
            let command = tokens[fieldCount...].joined(separator: " ")
            entries.append(CronEntry(user: owner, source: source, line: index + 1, schedule: schedule, command: command))
        }
        return entries
    }
}

public enum AtqParser {
    /// `atq` output: an optional header line naming Owner/Queue/Job, then
    /// "<date words> <owner> <queue> <job#>". Parsed leniently from the end.
    public static func parse(_ text: String) -> [AtJob] {
        var jobs: [AtJob] = []
        for raw in text.components(separatedBy: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.contains("Owner") || line.contains("Job") && line.contains("Queue") { continue }
            let tokens = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard tokens.count >= 4, let id = tokens.last else { continue }
            let queue = tokens[tokens.count - 2]
            let owner = tokens[tokens.count - 3]
            let when = tokens[0..<(tokens.count - 3)].joined(separator: " ")
            jobs.append(AtJob(id: id, when: when, queue: queue, owner: owner))
        }
        return jobs
    }
}

public enum PmsetScheduleParser {
    private static let line = try! NSRegularExpression(
        pattern: #"^\s*\[(\d+)\]\s+(\S+) at (\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}) by '([^']*)'(.*)$"#)

    public static func parse(_ text: String) -> [PowerEvent] {
        var events: [PowerEvent] = []
        for raw in text.components(separatedBy: "\n") {
            let range = NSRange(raw.startIndex..., in: raw)
            guard let m = line.firstMatch(in: raw, range: range) else { continue }
            func g(_ i: Int) -> String { String(raw[Range(m.range(at: i), in: raw)!]) }
            events.append(PowerEvent(index: Int(g(1)) ?? 0, kind: g(2), when: g(3), owner: g(4),
                                     userVisible: g(5).contains("User visible: true")))
        }
        return events
    }
}

public struct ScheduledScanner {
    public struct Result {
        public var cron: [CronEntry] = []
        public var atJobs: [AtJob] = []
        public var powerEvents: [PowerEvent] = []
        public var periodic: [PeriodicScript] = []
        public var warnings: [String] = []
        public var checks: [String] = []
        /// Layers that contribute items and failed: "crontab", "atq", "pmset".
        public var failed: [String] = []
        public init() {}
    }

    let runner: CommandRunner
    let fileManager: FileManager
    let userName: String
    let systemCrontab: String
    let periodicRoots: [String]

    public init(runner: CommandRunner, fileManager: FileManager = .default,
                userName: String = NSUserName(), systemCrontab: String = "/etc/crontab",
                periodicRoots: [String] = ["/etc/periodic", "/usr/local/etc/periodic"]) {
        self.runner = runner; self.fileManager = fileManager; self.userName = userName
        self.systemCrontab = systemCrontab; self.periodicRoots = periodicRoots
    }

    public func scan() -> Result {
        var result = Result()

        // User crontab. "no crontab for <user>" is the common, healthy answer.
        let crontab = runner.run(command: "/usr/bin/crontab", arguments: ["-l"])
        if crontab.exitCode == 0 {
            result.cron = CronParser.parse(crontab.stdout, user: userName, source: "crontab")
            result.checks.append("crontab: ok (\(result.cron.count) entries)")
        } else if crontab.stderr.contains("no crontab for") || crontab.stdout.contains("no crontab for") {
            result.checks.append("crontab: none for \(userName)")
        } else {
            result.warnings.append("cron not scanned: crontab -l exit \(crontab.exitCode): "
                + crontab.stderr.trimmingCharacters(in: .whitespacesAndNewlines))
            result.checks.append("crontab: FAILED (exit \(crontab.exitCode))")
            result.failed.append("crontab")
        }
        // System table (absent on a stock macOS; present = worth a look).
        if fileManager.fileExists(atPath: systemCrontab),
           let text = try? String(contentsOfFile: systemCrontab, encoding: .utf8) {
            let entries = CronParser.parse(text, user: "root", source: systemCrontab, systemTable: true)
            result.cron.append(contentsOf: entries)
            result.checks.append("\(systemCrontab): \(entries.count) entries")
        }

        // at queue.
        let atq = runner.run(command: "/usr/bin/atq", arguments: [])
        if atq.exitCode == 0 {
            result.atJobs = AtqParser.parse(atq.stdout)
            result.checks.append("atq: ok (\(result.atJobs.count) jobs)")
        } else {
            result.warnings.append("at jobs not scanned: atq exit \(atq.exitCode): "
                + atq.stderr.trimmingCharacters(in: .whitespacesAndNewlines))
            result.checks.append("atq: FAILED (exit \(atq.exitCode))")
            result.failed.append("atq")
        }

        // Scheduled power events.
        let pmset = runner.run(command: "/usr/bin/pmset", arguments: ["-g", "sched"])
        if pmset.exitCode == 0 {
            result.powerEvents = PmsetScheduleParser.parse(pmset.stdout)
            let thirdParty = result.powerEvents.filter { !$0.owner.hasPrefix("com.apple.") }.count
            result.checks.append("pmset sched: ok (\(result.powerEvents.count) events, \(thirdParty) third-party)")
        } else {
            result.warnings.append("power events not scanned: pmset -g sched exit \(pmset.exitCode): "
                + pmset.stderr.trimmingCharacters(in: .whitespacesAndNewlines))
            result.checks.append("pmset sched: FAILED (exit \(pmset.exitCode))")
            result.failed.append("pmset")
        }

        // periodic(8) scripts: <root>/<period>/<script>.
        var scripts: [PeriodicScript] = []
        for root in periodicRoots {
            guard let periods = try? fileManager.contentsOfDirectory(atPath: root) else { continue }
            for period in periods.sorted() {
                let dir = root + "/" + period
                var isDir: ObjCBool = false
                guard fileManager.fileExists(atPath: dir, isDirectory: &isDir), isDir.boolValue,
                      let names = try? fileManager.contentsOfDirectory(atPath: dir) else { continue }
                for name in names.sorted() where !name.hasPrefix(".") {
                    let path = dir + "/" + name
                    guard fileManager.fileExists(atPath: path, isDirectory: &isDir), !isDir.boolValue else { continue }
                    scripts.append(PeriodicScript(period: period, path: path, name: name))
                }
            }
        }
        result.periodic = scripts
        result.checks.append("periodic: \(scripts.count) scripts")
        return result
    }
}
