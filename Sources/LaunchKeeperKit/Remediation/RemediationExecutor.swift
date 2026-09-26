import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Injectable world for remediation runs (tests point it at temp homes).
public struct RemediationEnvironment {
    public var runner: CommandRunner
    public var fileManager: FileManager
    public var home: String
    public var uid: Int
    /// Allowlisted launch directories. `remove`, `backup` and `restore` share
    /// this exact list — one definition, one gate. Defaults mirror
    /// BackupEnvironment so engine and CLI can never drift apart.
    public var launchDirs: [String]
    /// Prefixes whose file operations route through the interactive sudo seam.
    public var systemDirPrefixes: [String]
    public var backupsRoot: String
    /// V0.7: where crontab / loginwindow snapshots go.
    public var configSnapshotsRoot: String
    /// Passed through to the resolution scan (tests: temp loginwindow plists).
    public var legacyScanner: LegacyScanner?
    /// V0.9.5: the caller's Background Task Management dump cache, reused by
    /// the resolution scan — the app would otherwise pay a cold dump (minutes)
    /// for every action.
    public var btmCache: BTMDumpCache?
    /// V0.8.1: where `remove` moves leftover files, and the disk it sees.
    public var quarantineRoot: String
    public var disk: DiskView

    public init(runner: CommandRunner = SystemCommandRunner(),
                fileManager: FileManager = .default,
                home: String = NSHomeDirectory(),
                uid: Int = -1,
                launchDirs: [String]? = nil,
                systemDirPrefixes: [String]? = nil,
                backupsRoot: String? = nil,
                configSnapshotsRoot: String? = nil,
                legacyScanner: LegacyScanner? = nil,
                quarantineRoot: String? = nil, disk: DiskView? = nil, btmCache: BTMDumpCache? = nil) {
        let defaults = BackupEnvironment(fileManager: fileManager, home: home)
        self.runner = runner
        self.fileManager = fileManager
        self.home = home
        self.uid = uid >= 0 ? uid : Int(getuid())
        self.launchDirs = launchDirs ?? defaults.launchDirs
        self.systemDirPrefixes = systemDirPrefixes ?? defaults.systemDirPrefixes
        self.backupsRoot = backupsRoot ?? defaults.backupsRoot
        self.configSnapshotsRoot = configSnapshotsRoot ?? LaunchKeeperPaths.configSnapshots(home: home)
        self.legacyScanner = legacyScanner
        self.quarantineRoot = quarantineRoot ?? LaunchKeeperPaths.quarantine(home: home)
        self.disk = disk ?? DiskView(fileManager: fileManager)
        self.btmCache = btmCache
    }
}

public enum RemediationStatus: Equatable {
    case planned
    case appliedOk
    case appliedFailed(String)
    case refused(String)
}

public struct RemediationResult {
    public var operation: RemediationOperation
    /// Audit target; for unresolved needles this is the raw (display-only) input.
    public var target: String
    public var status: RemediationStatus
    public var messages: [String]
    public var plan: [PlannedCommand]
    public var executed: [String]
    public var undoHint: String?

    public var auditStatus: String {
        switch status {
        case .planned: return "planned"
        case .appliedOk: return "applied-ok"
        case .appliedFailed(let detail): return "applied-fail(\(detail))"
        case .refused(let reason): return "refused(\(reason))"
        }
    }
}

/// Executes PlannedCommands through the runner seam and verifies afterwards.
/// Trust rule: exit codes alone prove nothing — after a mutation the executor
/// re-reads launchd state (print / print-disabled) — and, since V0.3 for
/// `remove`, the file system — and only reports success when the change is
/// actually visible. A `rm` that exits 0 having deleted nothing is caught.
public struct RemediationExecutor {
    public var runner: CommandRunner
    public var uid: Int
    public var fileManager: FileManager
    /// Budget for a piped step (launchctl, rm): seconds are plenty.
    public var stepTimeout: TimeInterval
    /// Budget for a step that talks to the user — the sudo password prompt.
    /// A human is typing (and sudo retries three times on its own); the
    /// piped 20 s budget cut the prompt off mid-thought (V0.4.2).
    public var interactiveTimeout: TimeInterval

    public init(runner: CommandRunner, uid: Int, fileManager: FileManager = .default,
                stepTimeout: TimeInterval = 20, interactiveTimeout: TimeInterval = 180) {
        self.runner = runner
        self.uid = uid
        self.fileManager = fileManager
        self.stepTimeout = stepTimeout
        self.interactiveTimeout = interactiveTimeout
    }

    /// `expectation` is what a config source must read back as afterwards
    /// (V0.7: the edited crontab) — verification compares against it.
    public func execute(_ plan: [PlannedCommand], operation: RemediationOperation,
                        item: BackgroundItem, expectation: String? = nil)
        -> (status: RemediationStatus, executed: [String], messages: [String]) {
        var executed: [String] = []
        var messages: [String] = []

        for command in plan {
            let exitCode: Int32
            if command.command == "/usr/bin/sudo" {
                // sudo prints its password prompt on the tty — piped capture
                // would swallow it. Inherited stdio only.
                exitCode = runner.runInteractive(command: command.command,
                                                 arguments: command.arguments,
                                                 timeout: interactiveTimeout)
            } else {
                exitCode = runner.run(command: command.command,
                                      arguments: command.arguments,
                                      timeout: stepTimeout).exitCode
            }
            executed.append(command.display)
            if exitCode != 0 {
                messages.append("stopped at: \(command.display) (exit \(exitCode))")
                return (.appliedFailed("exit \(exitCode)"), executed, messages)
            }
        }

        if let failure = verify(operation: operation, item: item, executed: executed, expectation: expectation) {
            messages.append("executed, but verification failed: \(failure)")
            return (.appliedFailed(failure), executed, messages)
        }
        switch item.controlMechanism {
        case .pluginkit:
            messages.append("verified: election visible in pluginkit")
        case .cron:
            messages.append("verified: crontab -l reads back exactly the edited table")
        case .firewall:
            messages.append("verified: socketfilterfw --listapps shows the rule as \(operation == .disable ? "block" : "allow")")
        case .loginHook:
            messages.append(operation == .disable ? "verified: defaults shows the hook parked, the live key gone"
                                                  : "verified: defaults shows the hook live again")
        default:
            messages.append(operation == .remove
                            ? "verified: file gone and launchd state consistent"
                            : "verified: state change visible in launchd")
        }
        return (.appliedOk, executed, messages)
    }

    /// Verification reads only — never writes.
    private func verify(operation: RemediationOperation, item: BackgroundItem,
                        executed: [String], expectation: String?) -> String? {
        switch item.controlMechanism {
        case .pluginkit:
            return verifyPluginKit(operation: operation, item: item)
        case .cron:
            guard let expectation else { return "no expected crontab to verify against" }
            let installed = runner.run(command: "/usr/bin/crontab", arguments: ["-l"], timeout: stepTimeout)
            guard installed.exitCode == 0 else { return "crontab -l failed (exit \(installed.exitCode))" }
            return CronEditor.sameTable(installed.stdout, expectation)
                ? nil : "the installed crontab differs from the edited table"
        case .loginHook:
            return verifyLoginHook(operation: operation, item: item, script: expectation)
        case .firewall:
            return verifyFirewall(operation: operation, item: item)
        case .quarantine:
            return "quarantine moves are run and verified by the cleanup engine"
        case .launchd, nil:
            break
        }
        guard let label = item.label else { return "no label to verify" }
        let domainTarget = RemediationPlanner.domainTarget(for: item, uid: uid)

        let disabled = LaunchctlParser.parseDisabled(
            runner.run(command: "/bin/launchctl",
                       arguments: ["print-disabled", domainTarget]).stdout)

        switch operation {
        case .disable:
            switch disabled[label] {
            case .some(true): return "print-disabled still shows '\(label)' as enabled"
            case .none: return "no disable override visible after disable"
            case .some(false): break
            }
            if executed.contains(where: { $0.contains("bootout") }) {
                let printOut = runner.run(command: "/bin/launchctl",
                                          arguments: ["print", domainTarget]).stdout
                if LaunchctlParser.parsePrint(printOut, domainKind: domainTarget)
                    .contains(where: { $0.label == label }) {
                    return "service still loaded after bootout"
                }
            }
            return nil
        case .enable:
            if disabled[label] == false {
                return "print-disabled still shows '\(label)' as disabled"
            }
            if executed.contains(where: { $0.contains("bootstrap") }) {
                let printOut = runner.run(command: "/bin/launchctl",
                                          arguments: ["print", domainTarget]).stdout
                if !LaunchctlParser.parsePrint(printOut, domainKind: domainTarget)
                    .contains(where: { $0.label == label }) {
                    return "service not present again after bootstrap"
                }
            }
            return nil
        case .remove:
            // Verification reads the real world: `rm` can exit 0 having deleted
            // nothing (missing file, permission denied, silent fake). A delete
            // counts as done only when the file is gone AND launchd agrees.
            var problems: [String] = []
            if let path = item.path, fileManager.fileExists(atPath: path) {
                problems.append("file still exists: \(path)")
            }
            if item.loaded, executed.contains(where: { $0.contains("bootout") }) {
                let printOut = runner.run(command: "/bin/launchctl",
                                          arguments: ["print", domainTarget]).stdout
                if LaunchctlParser.parsePrint(printOut, domainKind: domainTarget)
                    .contains(where: { $0.label == label }) {
                    problems.append("service still loaded after bootout")
                }
            }
            if !item.enabled, disabled[label] == false {
                problems.append("disable override still present after removal")
            }
            return problems.isEmpty ? nil : problems.joined(separator: "; ")
        case .backup, .restore:
            return nil
        }
    }
}

extension RemediationExecutor {
    /// The rule list is readable without root — the same read the scan does.
    func verifyFirewall(operation: RemediationOperation, item: BackgroundItem) -> String? {
        guard let path = item.metadata["firewall-path"] else { return "no firewall rule to verify" }
        let list = runner.run(command: RemediationPlanner.socketfilterfw, arguments: ["--listapps"], timeout: stepTimeout)
        guard list.exitCode == 0 else { return "socketfilterfw --listapps failed (exit \(list.exitCode))" }
        guard let rule = FirewallListParser.parse(list.stdout).first(where: { $0.path == path }) else {
            return "no firewall rule for \(path) anymore"
        }
        let expected = operation == .disable ? "block" : "allow"
        return rule.action == expected ? nil : "the rule still says \(rule.action) (expected \(expected))"
    }

    /// Reads both keys back through `defaults` (cfprefsd's view, which is
    /// what loginwindow sees): the live key must be gone and the parked one
    /// hold the script after disable — and the other way round after enable.
    func verifyLoginHook(operation: RemediationOperation, item: BackgroundItem, script: String?) -> String? {
        guard let path = item.path, let kind = item.metadata["hook-kind"], let script else {
            return "no hook evidence to verify"
        }
        let domainArgument = path.hasSuffix(".plist") ? String(path.dropLast(6)) : path
        func read(_ key: String) -> String? {
            let result = runner.run(command: "/usr/bin/defaults", arguments: ["read", domainArgument, key],
                                    timeout: stepTimeout)
            return result.exitCode == 0 ? result.stdout.trimmingCharacters(in: .whitespacesAndNewlines) : nil
        }
        let parked = LoginHookRecord.parkedKey(for: kind)
        let (gone, holds) = operation == .disable ? (kind, parked) : (parked, kind)
        if read(gone) != nil { return "\(gone) is still set" }
        guard read(holds) == script else { return "\(holds) does not hold the script path" }
        return nil
    }

    /// Re-reads the election of every registered version of the identifier —
    /// `-e` applies to all of them, so all of them must show the new state.
    func verifyPluginKit(operation: RemediationOperation, item: BackgroundItem) -> String? {
        guard let identifier = item.metadata["ext-identifier"] else { return "no pluginkit identifier to verify" }
        let result = runner.run(command: "/usr/bin/pluginkit", arguments: ["-mAvv", "-i", identifier],
                                timeout: stepTimeout)
        guard result.exitCode == 0 else { return "pluginkit -m failed (exit \(result.exitCode))" }
        let records = PluginKitParser.parse(result.stdout).records.filter { $0.identifier == identifier }
        guard !records.isEmpty else { return "pluginkit no longer lists '\(identifier)'" }
        let expected: AppExtensionRecord.Election = operation == .disable ? .ignore : .use
        let wrong = records.filter { $0.election != expected }
        guard wrong.isEmpty else {
            return "pluginkit still shows '\(identifier)' as "
                + Set(wrong.map(\.election.rawValue)).sorted().joined(separator: "/")
                + " (expected \(expected.rawValue))"
        }
        return nil
    }
}

/// Thin orchestrator: scan -> resolve -> gate -> plan -> (dry-run | execute),
/// with an audit line for EVERY path, including refusals and dry-runs.
public struct RemediationEngine {
    public var environment: RemediationEnvironment
    public var audit: AuditLog

    public init(environment: RemediationEnvironment = RemediationEnvironment(),
                audit: AuditLog? = nil) {
        self.environment = environment
        self.audit = audit ?? AuditLog(directory: LaunchKeeperPaths.logs(home: environment.home))
    }

    /// The scan every remediation resolves against: the SAME item set `list`
    /// prints. Display ids are positional per scan run, so a scan with fewer
    /// items renumbers everything — until V0.4.3 the BTM layer was skipped
    /// here, and `remove 54` could hit a different entry than `list` had shown
    /// as 54. BTM-only leftovers also resolve now and get an honest refusal
    /// instead of "no match". Signatures stay off: they never change the set.
    public static let defaultScanOptions = ScanOptions(includeUser: true, includeSystem: true,
                                                       scanBTM: true, scanSignatures: false)

    /// `scanOptions` is injectable so tests can keep the scan hermetic
    /// (user-domain only, no real system reads).
    public func run(operation: RemediationOperation, target needle: String,
                    apply: Bool, now: Bool = false,
                    scanOptions: ScanOptions = RemediationEngine.defaultScanOptions) -> RemediationResult {
        // Remediation READS the scan (target resolution needs live loaded/enabled
        // state and the full id space) but never extends it.
        let scanEnv = ScanEnvironment(runner: environment.runner,
                                      fileManager: environment.fileManager,
                                      home: environment.home, uid: environment.uid,
                                      legacyScanner: environment.legacyScanner,
                                      btmCache: environment.btmCache)
        let report = ScanCoordinator(environment: scanEnv).perform(options: scanOptions)

        func finish(_ status: RemediationStatus, target: String, messages: [String],
                    plan: [PlannedCommand] = [], executed: [String] = [],
                    undo: String? = nil) -> RemediationResult {
            let result = RemediationResult(operation: operation, target: target,
                                           status: status, messages: messages,
                                           plan: plan, executed: executed, undoHint: undo)
            audit.append(operation: operation.rawValue, target: target, status: result.auditStatus)
            return result
        }

        // Positional ids are only meaningful against the COMPLETE inventory.
        // A missing layer (BTM timed out, launchctl print failed) renumbers
        // everything — a number typed from an earlier, complete `list` would
        // hit a different entry. Refuse numbers then; labels still resolve.
        let trimmedNeedle = needle.trimmingCharacters(in: .whitespaces)
        if !report.incompleteLayers.isEmpty, !trimmedNeedle.isEmpty,
           trimmedNeedle.allSatisfy({ $0.isNumber }) {
            let layers = report.incompleteLayers.joined(separator: ", ")
            return finish(.refused("inventory incomplete — numeric ids unreliable"), target: trimmedNeedle,
                          messages: ["inventory incomplete (\(layers)) — display ids are positional and "
                                     + "would not match `list`; address the entry by label or name "
                                     + "fragment instead, or run again once the scan completes"])
        }

        switch TargetResolver.resolve(needle, in: report.items) {
        case .none(let needle):
            return finish(.refused("no match: \(needle)"), target: needle,
                          messages: ["no entry matches '\(needle)' — start with `launchkeeper list`"])
        case .ambiguous(let needle, let candidates):
            return finish(.refused("ambiguous: \(needle)"), target: needle,
                          messages: ["ambiguous '\(needle)' (\(candidates.count) matches):"] + candidates)
        case .unique(let item):
            var target = RemediationPlanner.displayTarget(for: item, uid: environment.uid)
            // A deletion audit line must say WHICH file — target carries the path.
            if operation == .remove, let path = item.path { target += " \(path)" }
            let undo = RemediationPlanner.undoHint(for: operation, item: item)

            switch RemediationGate.evaluate(operation: operation, item: item) {
            case .denied(let reason):
                return finish(.refused(reason), target: target,
                              messages: ["refused: \(reason)",
                                         "this is a hard gate — no flag bypasses it"],
                              undo: undo)
            case .allowed:
                var messages: [String] = []

                // Leftover files (V0.8.1): moved into the quarantine by the
                // cleanup engine — the same store `uninstall` uses.
                if item.controlMechanism == .quarantine {
                    let cleanup = CleanupEngine(environment: CleanupEnvironment(
                        runner: environment.runner, disk: environment.disk, home: environment.home,
                        quarantineRoot: environment.quarantineRoot), audit: audit)
                    let moved = cleanup.quarantineItem(item, apply: apply)
                    return finish(moved.status, target: target, messages: moved.messages, plan: moved.plan,
                                  executed: moved.executed, undo: moved.undoHint)
                }

                // Config-file switches (V0.7): the plan depends on the source
                // as it reads NOW, and --apply snapshots it before the write.
                if let prepare = configPreparer(for: item) {
                    switch prepare(operation, item, apply, undo) {
                    case .failure(let refusal):
                        return finish(.refused(refusal.reason), target: target,
                                      messages: ["refused: \(refusal.reason)"], undo: undo)
                    case .success(let prepared):
                        guard apply else {
                            return finish(.planned, target: target,
                                          messages: prepared.messages + ["dry-run: nothing executed (add --apply to execute)"],
                                          plan: prepared.plan, undo: prepared.undo)
                        }
                        if let snapshot = prepared.snapshot {
                            audit.append(operation: "snapshot", target: snapshot.name,
                                         status: "pre-\(operation.rawValue)")
                        }
                        let executor = RemediationExecutor(runner: environment.runner, uid: environment.uid,
                                                           fileManager: environment.fileManager)
                        let outcome = executor.execute(prepared.plan, operation: operation, item: item,
                                                       expectation: prepared.expectation)
                        return finish(outcome.status, target: target, messages: prepared.messages + outcome.messages,
                                      plan: prepared.plan, executed: outcome.executed, undo: prepared.undo)
                    }
                }

                // Remove-specific half of the gate + the runtime precondition.
                // Refused here means: not a launch plist, outside the four
                // directories, symlink escape, not orphaned, or file already
                // gone. No flag on any command reaches past this point.
                if operation == .remove {
                    switch removePreflight(item) {
                    case .denied(let reason):
                        return finish(.refused(reason), target: target,
                                      messages: ["refused: \(reason)",
                                                 "this is a hard gate — no flag bypasses it"],
                                      undo: undo)
                    case .allowed:
                        break
                    }
                }

                let plan = RemediationPlanner.plan(operation: operation, item: item,
                                                   uid: environment.uid, now: now,
                                                   systemDirPrefixes: environment.systemDirPrefixes)
                messages.append(contentsOf: RemediationPlanner.notes(for: operation, item: item))
                guard apply else {
                    if operation == .remove {
                        messages.append("dry-run: a full launch-dir backup would be created first, "
                                        + "then this plan runs — add --apply")
                    } else {
                        messages.append("dry-run: nothing executed (add --apply to execute)")
                    }
                    return finish(.planned, target: target, messages: messages,
                                  plan: plan, undo: undo)
                }

                // Backup BEFORE the first delete: the snapshot is the undo
                // story. If it cannot be written, nothing gets removed —
                // a delete without a restorable snapshot is banned outright.
                var undoText = undo
                if operation == .remove {
                    let backupEnv = BackupEnvironment(launchDirs: environment.launchDirs,
                                                      systemDirPrefixes: environment.systemDirPrefixes,
                                                      backupsRoot: environment.backupsRoot,
                                                      runner: environment.runner,
                                                      fileManager: environment.fileManager,
                                                      home: environment.home, uid: environment.uid)
                    let backups = BackupService(env: backupEnv)
                    guard case .success(let snapshot) = backups.create(label: "pre-remove") else {
                        return finish(.refused("backup failed — nothing deleted"), target: target,
                                      messages: ["refused: could not create the pre-delete backup",
                                                     "removals only run on top of a restorable snapshot"])
                    }
                    audit.append(operation: "backup", target: snapshot.backupName,
                                 status: "pre-remove")
                    // Label, not display id — the hint must resolve correctly
                    // in a LATER scan, and ids are positional per run.
                    undoText = "launchkeeper restore \(snapshot.backupName) && launchkeeper enable \(item.label ?? item.id) --now"
                }

                let executor = RemediationExecutor(runner: environment.runner, uid: environment.uid,
                                                   fileManager: environment.fileManager)
                let outcome = executor.execute(plan, operation: operation, item: item)
                return finish(outcome.status, target: target, messages: messages + outcome.messages,
                              plan: plan, executed: outcome.executed, undo: undoText)
            }
        }
    }

    /// A config-source plan, ready to show (dry-run) or run (--apply).
    struct PreparedConfigPlan {
        var plan: [PlannedCommand]
        var messages: [String]
        var undo: String?
        /// What the source must read back as after the change.
        var expectation: String?
        var snapshot: ConfigSnapshot?
    }

    /// Mechanisms whose plan is built from the config source as it reads
    /// at run time (and snapshotted with --apply); nil = planner-only.
    func configPreparer(for item: BackgroundItem)
        -> ((RemediationOperation, BackgroundItem, Bool, String?) -> Result<PreparedConfigPlan, ControlRefusal>)? {
        switch item.controlMechanism {
        case .cron: return prepareCron
        case .loginHook: return prepareLoginHook
        default: return nil
        }
    }

    /// loginwindow hooks (V0.7): park the value under
    /// `LaunchKeeperDisabled<kind>` in the SAME plist, then delete the live
    /// key — in that order, so no failure can lose the script path. Enable
    /// is the mirror image. `defaults` goes through cfprefsd (a direct file
    /// write would be overwritten by its cache); the system plist via the
    /// interactive sudo seam. The whole plist is snapshotted first.
    func prepareLoginHook(operation: RemediationOperation, item: BackgroundItem, apply: Bool,
                          undo: String?) -> Result<PreparedConfigPlan, ControlRefusal> {
        guard let path = item.path, let kind = item.metadata["hook-kind"] else {
            return .failure(ControlRefusal("hook without source evidence — scan again"))
        }
        let parked = LoginHookRecord.parkedKey(for: kind)
        guard let dict = try? PlistReader.readDictionary(fromFile: path, fileManager: environment.fileManager) else {
            return .failure(ControlRefusal("cannot read \(path) — nothing changed"))
        }
        let live = (dict[kind] as? String).flatMap { $0.isEmpty ? nil : $0 }
        let parkedValue = (dict[parked] as? String).flatMap { $0.isEmpty ? nil : $0 }
        let script: String
        switch operation {
        case .disable:
            guard let value = live else {
                return .failure(ControlRefusal("\(kind) is not set anymore — scan again"))
            }
            guard parkedValue == nil else {
                return .failure(ControlRefusal("\(parked) already holds a value — resolve by hand, "
                    + "launchkeeper never overwrites a parked hook"))
            }
            script = value
        case .enable:
            guard let value = parkedValue else {
                return .failure(ControlRefusal("no parked \(kind) — nothing to enable"))
            }
            guard live == nil else {
                return .failure(ControlRefusal("\(kind) is set again meanwhile — resolve by hand"))
            }
            script = value
        case .remove, .backup, .restore:
            return .failure(ControlRefusal("hooks are disabled or enabled, never removed here"))
        }

        let domainArgument = path.hasSuffix(".plist") ? String(path.dropLast(6)) : path
        let sudo = item.domain == .system
        func defaults(_ arguments: [String], _ description: String) -> PlannedCommand {
            sudo ? PlannedCommand(command: "/usr/bin/sudo", arguments: ["defaults"] + arguments,
                                  description: description + " — via sudo (interactive password)")
                 : PlannedCommand(command: "/usr/bin/defaults", arguments: arguments, description: description)
        }
        let (from, to) = operation == .disable ? (kind, parked) : (parked, kind)
        let plan = [
            defaults(["write", domainArgument, to, "-string", script], "copy the script path to \(to) first"),
            defaults(["delete", domainArgument, from], "then delete \(from) — loginwindow reads only \(kind)"),
        ]
        guard apply else {
            return .success(PreparedConfigPlan(plan: plan,
                messages: ["--apply first saves \(path) as a snapshot"],
                undo: undo, expectation: script, snapshot: nil))
        }
        guard let contents = environment.fileManager.contents(atPath: path) else {
            return .failure(ControlRefusal("cannot read \(path) for the snapshot — nothing changed"))
        }
        let store = ConfigSnapshotStore(root: environment.configSnapshotsRoot, fileManager: environment.fileManager)
        switch store.save(label: "pre-hook-\(operation.rawValue)", fileName: (path as NSString).lastPathComponent,
                          contents: contents, source: path) {
        case .failure(let refusal):
            return .failure(refusal)
        case .success(let snapshot):
            let restore = (sudo ? "sudo " : "") + "defaults import \(RemediationPlanner.shellQuoted(domainArgument)) "
                + RemediationPlanner.shellQuoted(snapshot.file)
            return .success(PreparedConfigPlan(plan: plan, messages: ["snapshot: \(snapshot.file)"],
                undo: (undo.map { $0 + "   " } ?? "") + "(full rollback: \(restore))",
                expectation: script, snapshot: snapshot))
        }
    }

    /// cron (V0.7): read the table as it is NOW (the scan may be minutes old),
    /// edit one line, and — only with --apply — snapshot the whole table and
    /// stage the edited copy next to it. `crontab <file>` installs it as the
    /// user, no sudo; verification reads `crontab -l` back.
    func prepareCron(operation: RemediationOperation, item: BackgroundItem, apply: Bool,
                     undo: String?) -> Result<PreparedConfigPlan, ControlRefusal> {
        let current = environment.runner.run(command: "/usr/bin/crontab", arguments: ["-l"], timeout: 20)
        guard current.exitCode == 0 else {
            return .failure(ControlRefusal("cannot read the crontab (crontab -l exit \(current.exitCode))"))
        }
        let edited: CronEditor.Edit
        switch CronEditor.edit(current.stdout, schedule: item.metadata["cron-schedule"] ?? "",
                               command: item.metadata["cron-command"] ?? "", operation: operation) {
        case .failure(let refusal): return .failure(refusal)
        case .success(let value): edited = value
        }
        var newText = edited.newText
        if !newText.hasSuffix("\n") { newText += "\n" }   // cron skips an unterminated last line
        let change = operation == .disable
            ? "comment out line \(edited.lineNumber) behind `\(CronParser.disabledMarker.trimmingCharacters(in: .whitespaces))`"
            : "take the launchkeeper marker off line \(edited.lineNumber)"
        let describe = "install the edited table — \(change); every other line stays byte-identical"

        guard apply else {
            return .success(PreparedConfigPlan(
                plan: [PlannedCommand(command: "/usr/bin/crontab", arguments: ["<snapshot>/crontab.new"],
                                      description: describe)],
                messages: ["--apply first saves the whole table (crontab -l) as a snapshot"],
                undo: undo, expectation: newText, snapshot: nil))
        }
        let store = ConfigSnapshotStore(root: environment.configSnapshotsRoot, fileManager: environment.fileManager)
        let snapshot: ConfigSnapshot
        switch store.save(label: "pre-cron-\(operation.rawValue)", fileName: "crontab.txt",
                          contents: Data(current.stdout.utf8), source: "crontab -l (\(item.owner))") {
        case .failure(let refusal): return .failure(refusal)
        case .success(let value): snapshot = value
        }
        let staged = snapshot.directory + "/crontab.new"
        guard environment.fileManager.createFile(atPath: staged, contents: Data(newText.utf8)),
              environment.fileManager.contents(atPath: staged) == Data(newText.utf8) else {
            return .failure(ControlRefusal("cannot stage the edited table — nothing changed"))
        }
        return .success(PreparedConfigPlan(
            plan: [PlannedCommand(command: "/usr/bin/crontab", arguments: [staged], description: describe)],
            messages: ["snapshot: \(snapshot.file)"],
            undo: (undo.map { $0 + "   " } ?? "") + "(full rollback: crontab \(RemediationPlanner.shellQuoted(snapshot.file)))",
            expectation: newText, snapshot: snapshot))
    }

    /// The file-level remove rules live in RemediationGate.evaluateRemove (one
    /// non-bypassable gate); this adds the runtime precondition on top: the
    /// backing file must actually be there — nothing else may be "cleaned".
    /// A refusal names the step that DOES help (V0.4.2): a job launchd still
    /// holds from a plist that is already gone is unloaded by `disable`, and
    /// a lone BTM record is nothing this tool can or should touch.
    private func removePreflight(_ item: BackgroundItem) -> GateDecision {
        let hint: String
        if item.loaded, let label = item.label {
            let target = RemediationPlanner.displayTarget(for: item, uid: environment.uid)
            hint = " — launchd still holds the job (\(target)) from a file that no longer "
                + "exists; it vanishes at the next login, or unload it now: "
                + "launchkeeper disable \(label) --apply"
        } else if item.btmPresent {
            hint = " — only a Background Task Management record remains; BTM prunes it "
                + "itself (sfltool has no per-item delete)"
        } else {
            hint = ""
        }
        guard let path = item.path else {
            return .denied(reason: "no backing file — nothing to remove" + hint)
        }
        guard environment.fileManager.fileExists(atPath: path) else {
            return .denied(reason: "backing file is not on disk anymore: \(path)" + hint)
        }
        return RemediationGate.evaluateRemove(item: item,
                                              fileManager: environment.fileManager,
                                              launchDirs: environment.launchDirs)
    }
}