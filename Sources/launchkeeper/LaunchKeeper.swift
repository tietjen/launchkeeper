import ArgumentParser
import LaunchKeeperKit
import Foundation

// launchkeeper V0.4 — read-only inventory (now with app correlation) + GATED
// remediation, including the one file-deleting command — kept deliberately
// narrow.
//
// V0.4 adds app context to the READ-ONLY half only: each item learns its
// parent application (deepest .app bundle around its executable/path,
// bundle Info.plist for id/team/name) and, only when that bundle is provably
// gone, a Spotlight lookup answers "is the app installed anywhere else?".
// Spotlight is read-only; the scan pipeline stays write-free, and a wedged
// index degrades to "unknown", never to a guess.
//
// The scan pipeline keeps its write-free design — remediation only READS it
// (target resolution). `remove` deletes exactly ONE orphaned launch .plist
// inside the launch directories, and only after a full launch-dir snapshot
// was written: no backup, no delete. Non-orphaned entries leave via
// `disable` (reversible), never via deletion — that rule is what keeps this
// tool out of rm-wrapper territory. Dry-run is the DEFAULT: mutation requires
// --apply. com.apple.* labels and anything under /System are refused by the
// gate — there is no flag that bypasses it. `sfltool resetbtm` (V0.4b) is
// guarded the same way — no snapshot, no reset — and says in words that its
// snapshot is an audit artifact, not a backup: sfltool has no import.

/// Always the FULL scan: display ids are positional per scan run, so every
/// command that prints or resolves an id must see the same item set. `--user`
/// and `--system` narrow the ROWS, never the scan (V0.4.3 — before, `list
/// --user` renumbered the inventory and its ids meant something else to
/// `disable`/`remove`).
private func runScan() -> ScanReport {
    ScanCoordinator().perform(options: ScanOptions())
}

private func emitWarnings(_ report: ScanReport) {
    guard !report.warnings.isEmpty else { return }
    let text = "warnings:\n" + report.warnings.map { "  - " + $0 }.joined(separator: "\n") + "\n"
    FileHandle.standardError.write(Data(text.utf8))
}

struct ListCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "list",
        abstract: "Show the background-service inventory (read-only).")

    @Flag(name: .customLong("json"), help: "JSON output instead of a table")
    var json = false
    @Flag(name: .customLong("orphans"), help: "show only orphaned entries (reason column)")
    var orphans = false
    @Flag(name: .customLong("running"), help: "show only entries with a live process")
    var running = false
    @Flag(name: .customLong("disabled"), help: "show only disabled entries")
    var disabled = false
    @Flag(name: .customLong("user"), help: "user domain only")
    var user = false
    @Flag(name: .customLong("system"), help: "system domain only")
    var system = false
    @Flag(name: .customLong("all"), help: "include Apple-internal entries")
    var all = false
    @Option(name: .customLong("category"),
            help: ArgumentHelp("only this category: "
                               + ItemCategory.allCases.map(\.rawValue).joined(separator: ", ")))
    var category: String?

    mutating func run() throws {
        let userOnly = user && !system
        let systemOnly = system && !user
        var filter = ListFilter()
        filter.orphansOnly = orphans
        filter.runningOnly = running
        filter.disabledOnly = disabled
        filter.userOnly = userOnly
        filter.systemOnly = systemOnly
        filter.includeAll = all
        if let category {
            guard let parsed = ItemCategory(rawValue: category) else {
                throw ValidationError("unknown category '\(category)' — one of: "
                    + ItemCategory.allCases.map(\.rawValue).joined(separator: ", "))
            }
            filter.category = parsed
        }

        let report = runScan()
        let rows = filter.apply(to: report.items)
        if json {
            print(try JSONRenderer.encode(rows))
        } else {
            print(TableRenderer.render(rows, mode: orphans ? .orphans : .table))
            emitWarnings(report)
        }
    }
}

struct InspectCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "inspect",
        abstract: "Full details for one entry by display id (e.g. 07) or unique name fragment.")

    @Argument(help: "display id, launchd label, name or key fragment")
    var id: String
    @Flag(name: .customLong("json"), help: "JSON output")
    var json = false

    mutating func run() throws {
        let env = ScanEnvironment()
        let report = ScanCoordinator(environment: env).perform()
        let needle = id.trimmingCharacters(in: .whitespaces).lowercased()

        var candidates: [BackgroundItem] = []
        if let n = Int(needle), needle.allSatisfy({ $0.isNumber }) {
            candidates = report.items.filter { $0.id == String(format: "%02d", n) }
        }
        if candidates.isEmpty {
            candidates = report.items.filter {
                $0.displayName.lowercased().contains(needle)
                    || $0.label?.lowercased().contains(needle) == true
                    || $0.key.lowercased().contains(needle)
            }
        }

        switch candidates.count {
        case 0:
            throw ValidationError("no entry matches '\(id)' — start with `launchkeeper list`")
        case 1:
            if json {
                print(try JSONRenderer.encode(candidates[0]))
            } else {
                print(InspectRenderer.render(candidates[0], uid: env.uid))
            }
        default:
            let preview = candidates.prefix(6)
                .map { "[\($0.id)] \($0.displayName)" }
                .joined(separator: "\n  ")
            throw ValidationError("ambiguous '\(id)' — \(candidates.count) matches:\n  \(preview)")
        }
    }
}

struct DoctorCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "doctor",
        abstract: "Environment health check and inventory summary (read-only).")

    @Flag(name: .customLong("json"), help: "machine-readable output (checks, warnings, orphans)")
    var json = false

    private struct DoctorJSON: Codable {
        var checks: [String]
        var warnings: [String]
        var orphanCount: Int
        var orphans: [BackgroundItem]
    }

    mutating func run() throws {
        let report = runScan()
        if json {
            let orphans = report.items.filter { $0.orphaned }
            print(try JSONRenderer.encode(DoctorJSON(
                checks: report.checks, warnings: report.warnings,
                orphanCount: orphans.count, orphans: orphans)))
            return
        }
        print("launchkeeper doctor — read-only checks")
        for check in report.checks {
            print("  . \(check)")
        }
        if report.warnings.isEmpty {
            print("  no warnings")
        } else {
            print("  warnings (\(report.warnings.count)):")
            for warning in report.warnings {
                print("    ! \(warning)")
            }
        }
        let orphans = report.items.filter { $0.orphaned }.count
        if orphans > 0 {
            print("\n\(orphans) orphaned entries — inspect with: launchkeeper list --orphans")
        }
    }
}

struct BackgroundCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "background",
        abstract: """
        The Login Items & Extensions pane, rebuilt from the inventory (read-only).

        "Open at Login" and "Allow in the Background" as System Settings shows
        them: one row per app or developer with its switch state and the
        components beneath. The switch is derived from the components; the
        switch itself lives in System Settings — launchkeeper never writes
        to Background Task Management.
        """)

    @Flag(name: .customLong("json"), help: "machine-readable view")
    var json = false

    mutating func run() throws {
        let report = runScan()
        let view = BackgroundView.build(from: report)
        if json {
            print(try JSONRenderer.encode(view))
        } else {
            print(view.renderText())
            emitWarnings(report)
        }
    }
}

// MARK: - V0.2 remediation commands

/// Engine-backed display + JSON for disable/enable. All decisions already
/// happened in LaunchKeeperKit (gate/plan/executor); this only renders and audits.
private func performRemediation(operation: RemediationOperation, target: String,
                                apply: Bool, now: Bool, json: Bool) throws {
    let engine = RemediationEngine()
    let result = engine.run(operation: operation, target: target, apply: apply, now: now)

    if json {
        struct RemediationJSON: Codable {
            var operation: String
            var target: String
            var status: String
            var applied: [String]
            var planned: [String]
            var notes: [String]
            var undo: String?
            var auditPath: String
        }
        print(try JSONRenderer.encode(RemediationJSON(
            operation: operation.rawValue, target: result.target,
            status: result.auditStatus, applied: result.executed,
            planned: result.plan.map { $0.display }, notes: result.messages,
            undo: result.undoHint, auditPath: engine.audit.url.path)))
    } else {
        switch result.status {
        case .planned:
            print("DRY-RUN — nothing executed (dry-run is the default).")
            print("plan:")
            for (index, command) in result.plan.enumerated() {
                print("  \(index + 1). \(command.display)")
                print("      \(command.description)")
            }
            if let undo = result.undoHint {
                print("\nundo later with: \(undo)")
            }
            print("execute for real with: --apply")
        case .appliedOk:
            print("applied (\(result.executed.count) command(s)), verified after execution:")
            for line in result.executed { print("  ok  \(line)") }
            if let undo = result.undoHint {
                print("undo with: \(undo)")
            }
        case .appliedFailed(let detail):
            print("FAILED (\(detail)) after \(result.executed.count) command(s):")
            for line in result.executed { print("  \(line)") }
            for line in result.messages { print("  \(line)") }
            print("partial state — inspect with: launchkeeper inspect <id>")
        case .refused(let reason):
            print("REFUSED — \(reason)")
            for line in result.messages where !line.hasPrefix("refused:") {
                print("  \(line)")
            }
        }
        print("audit: \(engine.audit.url.path)")
    }

    switch result.status {
    case .appliedFailed, .refused: throw ExitCode(1)
    case .planned, .appliedOk: break
    }
}

struct DisableCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "disable",
        abstract: "Disable one item via a launchctl override (gated, reversible; dry-run by default).")

    @Argument(help: "display id, launchd label, name or key fragment — exactly one target")
    var id: String
    @Flag(name: .customLong("apply"), help: "execute the plan instead of only showing it")
    var apply = false
    @Flag(name: .customLong("json"), help: "machine-readable output")
    var json = false

    mutating func run() throws {
        try performRemediation(operation: .disable, target: id, apply: apply, now: false, json: json)
    }
}

struct EnableCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "enable",
        abstract: "Undo a disable override (dry-run by default). --now also reloads the job.")

    @Argument(help: "display id, launchd label, name or key fragment — exactly one target")
    var id: String
    @Flag(name: .customLong("apply"), help: "execute the plan instead of only showing it")
    var apply = false
    @Flag(name: .customLong("now"), help: "bootstrap the job again after enabling")
    var now = false
    @Flag(name: .customLong("json"), help: "machine-readable output")
    var json = false

    mutating func run() throws {
        try performRemediation(operation: .enable, target: id, apply: apply, now: now, json: json)
    }
}

struct BackupCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "backup",
        abstract: "Snapshot launch-dir plists + disabled-override state (read-only; always safe).")

    @Option(name: .customLong("label"), help: "suffix for the backup directory name")
    var label: String?
    @Flag(name: .customLong("json"), help: "machine-readable output")
    var json = false

    mutating func run() throws {
        let service = BackupService()
        let audit = AuditLog(directory: LaunchKeeperPaths.logs(home: NSHomeDirectory()))
        switch service.create(label: label) {
        case .failure(let message):
            print("backup failed: \(message)")
            throw ExitCode(1)

        case .success(let report):
            audit.append(operation: "backup", target: report.backupName, status: "applied-ok")
            if json {
                struct BackupJSON: Codable {
                    var name: String
                    var directory: String
                    var copied: Int
                    var notes: [String]
                }
                print(try JSONRenderer.encode(BackupJSON(
                    name: report.backupName, directory: report.backupDir,
                    copied: report.copied, notes: report.notes)))
            } else {
                print("snapshot: \(report.backupDir)")
                print("  \(report.copied) plist(s) + disabled-override dumps")
                for note in report.notes { print("  ! \(note)") }
                print("\nrestore with: launchkeeper restore \(report.backupName)")
            }
        }
    }
}

struct RestoreCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "restore",
        abstract: "Copy launch-dir files back from a snapshot (allowlisted dirs; dry-run by default).")

    @Argument(help: "backup name — see ~/Library/Application Support/launchkeeper/backups (btmctl-era snapshots are found too)")
    var name: String
    @Flag(name: .customLong("apply"), help: "actually copy files back")
    var apply = false
    @Flag(name: .customLong("json"), help: "machine-readable output")
    var json = false

    mutating func run() throws {
        // Defense-in-depth: BackupService also guards, but reject early with a
        // clean CLI error instead of a thrown failure.
        guard !name.contains(".."), !name.contains("/"), !name.contains("\\") else {
            throw ValidationError("backup name must not contain path separators")
        }
        let service = BackupService()
        let audit = AuditLog(directory: LaunchKeeperPaths.logs(home: NSHomeDirectory()))

        switch service.restore(name: name, apply: apply) {
        case .failure(let message):
            audit.append(operation: "restore", target: name, status: "refused(\(message))")
            print("restore failed: \(message)")
            throw ExitCode(1)

        case .success(let report):
            audit.append(operation: "restore", target: name, status: report.auditStatus)
            if json {
                struct RestoreJSON: Codable {
                    var name: String
                    var status: String
                    var restored: [String]
                    var unchanged: [String]
                    var planned: [String]
                    var refused: [String]
                    var failed: [String]
                }
                print(try JSONRenderer.encode(RestoreJSON(
                    name: name, status: report.auditStatus, restored: report.restored,
                    unchanged: report.unchanged, planned: report.wouldRestore,
                    refused: report.refused, failed: report.failed)))
            } else if !apply {
                if report.wouldRestore.isEmpty {
                    print("nothing to restore — backup matches current state")
                } else {
                    print("DRY-RUN — nothing copied (\(report.wouldRestore.count) file(s) differ):")
                    for path in report.wouldRestore { print("  would restore: \(path)") }
                    if !report.unchanged.isEmpty {
                        print("  unchanged: \(report.unchanged.count)")
                    }
                    for path in report.refused { print("  REFUSED: \(path)") }
                    for path in report.failed { print("  FAILED: \(path)") }
                    print("\nexecute for real with: --apply")
                }
            } else {
                print("restored \(report.restored.count), unchanged \(report.unchanged.count).")
                for path in report.refused { print("  REFUSED: \(path)") }
                for path in report.failed { print("  FAILED: \(path)") }
                if !report.restored.isEmpty {
                    print("verify: launchkeeper list   (and re-check state for restarts yourself)")
                }
            }
            if apply, !report.refused.isEmpty || !report.failed.isEmpty {
                throw ExitCode(1)
            }
        }
    }
}

struct RemoveCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "remove",
        abstract: """
        Delete one ORPHANED launch .plist (gated).

        Refused unless all locks pass: orphaned only, a .plist inside the
        launch directories, no symlink escape, no Apple or /System target.
        --apply writes a launch-dir backup first — without a restorable
        snapshot nothing is deleted. A working component must be disabled
        instead (reversible).
        """)

    @Argument(help: "display id, launchd label, name or key fragment — exactly one target")
    var id: String
    @Flag(name: .customLong("apply"), help: "execute the plan instead of only showing it")
    var apply = false
    @Flag(name: .customLong("json"), help: "machine-readable output")
    var json = false

    mutating func run() throws {
        try performRemediation(operation: .remove, target: id, apply: apply, now: false, json: json)
    }
}

struct ResetBtmCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "resetbtm",
        abstract: """
        Reset the Background Task Management database (sfltool resetbtm, gated).

        NOT RESTORABLE: sfltool has no import — the pre-reset snapshot is an
        audit artifact (what was destroyed), not a backup. No snapshot, no
        reset; unreadable database, no reset; the end state is verified by a
        post-dump. Registrations re-establish as their apps run again.
        Dry-run by default.
        """)

    @Flag(name: .customLong("apply"), help: "execute the reset instead of only showing it")
    var apply = false
    @Flag(name: .customLong("json"), help: "machine-readable output")
    var json = false

    mutating func run() throws {
        let env = BTMResetEnvironment()
        let service = BTMResetService(env: env)
        let audit = AuditLog(directory: LaunchKeeperPaths.logs(home: NSHomeDirectory()))
        let outcome = service.run(apply: apply)

        let status: String
        switch outcome {
        case .dryRun: status = "planned"
        case .applied: status = "applied-ok"
        case .appliedFailed: status = "applied-fail"
        case .refused(let r): status = "refused(\(r))"
        }
        switch outcome {
        case .applied(_, let after, let snap, _):
            audit.append(operation: "resetbtm", target: "btm-database",
                         status: "applied-ok (after \(after) records, snapshot \(snap))")
        case .appliedFailed(let detail, _, _):
            audit.append(operation: "resetbtm", target: "btm-database",
                         status: "applied-fail(\(detail.prefix(80)))")
        case .refused(let reason):
            audit.append(operation: "resetbtm", target: "btm-database",
                         status: "refused(\(reason.prefix(80)))")
        case .dryRun:
            audit.append(operation: "resetbtm", target: "btm-database", status: "planned")
        }

        if json {
            struct ResetJSON: Codable {
                var operation: String
                var status: String
                var beforeRecords: Int?
                var afterRecords: Int?
                var snapshot: String?
                var notes: [String]
                var auditPath: String
            }
            var before: Int?; var after: Int?; var snap: String?; var notes: [String] = []
            switch outcome {
            case .dryRun(let b, _, let n): (before, after, snap, notes) = (b, nil, nil, n)
            case .applied(let b, let a, let s, let n): (before, after, snap, notes) = (b, a, s, n)
            case .appliedFailed(_, let b, let s): (before, after, snap, notes) = (b, nil, s, [])
            case .refused(let r): (before, after, snap, notes) = (nil, nil, nil, [r])
            }
            print(try JSONRenderer.encode(ResetJSON(operation: "resetbtm", status: status,
                beforeRecords: before, afterRecords: after, snapshot: snap,
                notes: notes, auditPath: audit.url.path)))
        } else {
            switch outcome {
            case .dryRun(let before, let wouldSnapshot, let notes):
                print("DRY-RUN — nothing executed (dry-run is the default).")
                print("current BTM database: \(before) record(s)")
                print("plan:")
                print("  1. audit snapshot → \(env.snapshotsRoot)/\(wouldSnapshot).btmdump.txt")
                print("      + sfltool archive (SharedFileList storage copy)")
                print("  2. /usr/bin/sfltool resetbtm")
                print("  3. verify: sfltool dumpbtm again (exit codes prove nothing)")
                for note in notes { print("\n  \(note)") }
                print("execute for real with: --apply")
            case .applied(let before, let after, let snapshot, let notes):
                print("applied, verified after execution:")
                print("  BTM records: \(before) -> \(after)")
                print("  audit snapshot: \(snapshot)")
                for note in notes { print("  \(note)") }
            case .appliedFailed(let detail, let before, let snapshot):
                print("FAILED after \(before) record(s) were read: \(detail)")
                if let snapshot { print("  audit snapshot: \(snapshot)") }
                print("  \(btmResetIrreversibilityNote)")
                print("partial state — inspect with: sfltool dumpbtm")
            case .refused(let reason):
                print("REFUSED — \(reason)")
            }
            print("audit: \(audit.url.path)")
        }

        switch outcome {
        case .appliedFailed, .refused: throw ExitCode(1)
        case .dryRun, .applied: break
        }
    }

}

@main
struct LaunchKeeper: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "launchkeeper",
        abstract: """
        Background-service inventory + app correlation + gated remediation (V0.5.7).

        Dry-run is the default: disable/enable/remove/restore only show a plan
        unless --apply is given. `remove` deletes only an orphaned launch
        .plist inside the launch directories, and only after a pre-delete
        backup — working components are disabled instead, never deleted.
        com.apple.* labels and /System are refused by construction, no flag
        bypasses the gate.
        """,
        version: "0.5.7",
        subcommands: [ListCommand.self, InspectCommand.self, DoctorCommand.self,
                      BackgroundCommand.self,
                      DisableCommand.self, EnableCommand.self,
                      BackupCommand.self, RestoreCommand.self,
                      RemoveCommand.self, ResetBtmCommand.self],
        defaultSubcommand: ListCommand.self
    )
}