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

    public init(runner: CommandRunner = SystemCommandRunner(),
                fileManager: FileManager = .default,
                home: String = NSHomeDirectory(),
                uid: Int = -1,
                launchDirs: [String]? = nil,
                systemDirPrefixes: [String]? = nil,
                backupsRoot: String? = nil) {
        let defaults = BackupEnvironment(fileManager: fileManager, home: home)
        self.runner = runner
        self.fileManager = fileManager
        self.home = home
        self.uid = uid >= 0 ? uid : Int(getuid())
        self.launchDirs = launchDirs ?? defaults.launchDirs
        self.systemDirPrefixes = systemDirPrefixes ?? defaults.systemDirPrefixes
        self.backupsRoot = backupsRoot ?? defaults.backupsRoot
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
    public var stepTimeout: TimeInterval

    public init(runner: CommandRunner, uid: Int, fileManager: FileManager = .default,
                stepTimeout: TimeInterval = 20) {
        self.runner = runner
        self.uid = uid
        self.fileManager = fileManager
        self.stepTimeout = stepTimeout
    }

    public func execute(_ plan: [PlannedCommand], operation: RemediationOperation,
                        item: BackgroundItem) -> (status: RemediationStatus, executed: [String], messages: [String]) {
        var executed: [String] = []
        var messages: [String] = []

        for command in plan {
            let exitCode: Int32
            if command.command == "/usr/bin/sudo" {
                // sudo prints its password prompt on the tty — piped capture
                // would swallow it. Inherited stdio only.
                exitCode = runner.runInteractive(command: command.command,
                                                 arguments: command.arguments,
                                                 timeout: stepTimeout)
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

        if let failure = verify(operation: operation, item: item, executed: executed) {
            messages.append("executed, but verification failed: \(failure)")
            return (.appliedFailed(failure), executed, messages)
        }
        messages.append(operation == .remove
                        ? "verified: file gone and launchd state consistent"
                        : "verified: state change visible in launchd")
        return (.appliedOk, executed, messages)
    }

    /// Verification reads only — never writes.
    private func verify(operation: RemediationOperation, item: BackgroundItem,
                        executed: [String]) -> String? {
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

/// Thin orchestrator: scan -> resolve -> gate -> plan -> (dry-run | execute),
/// with an audit line for EVERY path, including refusals and dry-runs.
public struct RemediationEngine {
    public var environment: RemediationEnvironment
    public var audit: AuditLog

    public init(environment: RemediationEnvironment = RemediationEnvironment(),
                audit: AuditLog? = nil) {
        self.environment = environment
        self.audit = audit ?? AuditLog(directory: environment.home + "/Library/Logs/btmctl")
    }

    /// `scanOptions` is injectable so tests can keep the scan hermetic
    /// (user-domain only, no real system reads). Defaults to a full two-domain
    /// read without BTM/signature layers.
    public func run(operation: RemediationOperation, target needle: String,
                    apply: Bool, now: Bool = false,
                    scanOptions: ScanOptions = ScanOptions(includeUser: true, includeSystem: true,
                                                           scanBTM: false, scanSignatures: false)) -> RemediationResult {
        // Remediation READS the scan (target resolution needs live loaded/enabled
        // state) but never extends it: BTM and signature layers stay unscanned
        // here — they add seconds and no decision value for a gate.
        let scanEnv = ScanEnvironment(runner: environment.runner,
                                      fileManager: environment.fileManager,
                                      home: environment.home, uid: environment.uid)
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

        switch TargetResolver.resolve(needle, in: report.items) {
        case .none(let needle):
            return finish(.refused("no match: \(needle)"), target: needle,
                          messages: ["no entry matches '\(needle)' — start with `btmctl list`"])
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
                                                   uid: environment.uid, now: now)
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
                    undoText = "btmctl restore \(snapshot.backupName) && btmctl enable \(item.label ?? item.id) --now"
                }

                let executor = RemediationExecutor(runner: environment.runner, uid: environment.uid,
                                                   fileManager: environment.fileManager)
                let outcome = executor.execute(plan, operation: operation, item: item)
                return finish(outcome.status, target: target, messages: outcome.messages,
                              plan: plan, executed: outcome.executed, undo: undoText)
            }
        }
    }

    /// The file-level remove rules live in RemediationGate.evaluateRemove (one
    /// non-bypassable gate); this adds the runtime precondition on top: the
    /// backing file must actually be there — nothing else may be "cleaned".
    private func removePreflight(_ item: BackgroundItem) -> GateDecision {
        guard let path = item.path else {
            return .denied(reason: "no backing file — nothing to remove")
        }
        guard environment.fileManager.fileExists(atPath: path) else {
            return .denied(reason: "backing file is not on disk anymore: \(path)")
        }
        return RemediationGate.evaluateRemove(item: item,
                                              fileManager: environment.fileManager,
                                              launchDirs: environment.launchDirs)
    }
}