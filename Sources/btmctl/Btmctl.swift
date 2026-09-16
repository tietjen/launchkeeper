import ArgumentParser
import BTMKit
import Foundation

// btmctl V0.2 — read-only inventory + GATED, reversible remediation.
//
// Still true from V0.1: no command deletes or removes files, and the scan
// pipeline keeps its write-free design — remediation only READS it (target
// resolution). What V0.2 adds: launchctl-state overrides (disable/enable) and
// file snapshots (backup/restore). Dry-run is the DEFAULT: mutation requires
// --apply. com.apple.* labels and anything under /System are refused by the
// gate — there is no flag that bypasses it.

private func runScan(userOnly: Bool, systemOnly: Bool) -> ScanReport {
    var options = ScanOptions()
    if userOnly { options.includeSystem = false }
    if systemOnly { options.includeUser = false }
    return ScanCoordinator().perform(options: options)
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

        let report = runScan(userOnly: userOnly, systemOnly: systemOnly)
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
            throw ValidationError("no entry matches '\(id)' — start with `btmctl list`")
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
        let report = runScan(userOnly: false, systemOnly: false)
        if json {
            let orphans = report.items.filter { $0.orphaned }
            print(try JSONRenderer.encode(DoctorJSON(
                checks: report.checks, warnings: report.warnings,
                orphanCount: orphans.count, orphans: orphans)))
            return
        }
        print("btmctl doctor — read-only checks")
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
            print("\n\(orphans) orphaned entries — inspect with: btmctl list --orphans")
        }
    }
}

// MARK: - V0.2 remediation commands

/// Engine-backed display + JSON for disable/enable. All decisions already
/// happened in BTMKit (gate/plan/executor); this only renders and audits.
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
            print("applied (\(result.executed.count) command(s)), verified against launchd:")
            for line in result.executed { print("  ok  \(line)") }
            if let undo = result.undoHint {
                print("undo with: \(undo)")
            }
        case .appliedFailed(let detail):
            print("FAILED (\(detail)) after \(result.executed.count) command(s):")
            for line in result.executed { print("  \(line)") }
            for line in result.messages { print("  \(line)") }
            print("partial state — inspect with: btmctl inspect <id>")
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
        let audit = AuditLog(directory: NSHomeDirectory() + "/Library/Logs/btmctl")
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
                print("\nrestore with: btmctl restore \(report.backupName)")
            }
        }
    }
}

struct RestoreCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "restore",
        abstract: "Copy launch-dir files back from a snapshot (allowlisted dirs; dry-run by default).")

    @Argument(help: "backup name — see ~/Library/Application Support/btmctl/backups")
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
        let audit = AuditLog(directory: NSHomeDirectory() + "/Library/Logs/btmctl")

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
                    print("verify: btmctl list   (and re-check state for restarts yourself)")
                }
            }
            if apply, !report.refused.isEmpty || !report.failed.isEmpty {
                throw ExitCode(1)
            }
        }
    }
}

@main
struct Btmctl: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "btmctl",
        abstract: """
        Background-service inventory + gated remediation (V0.2).

        Dry-run is the default: disable/enable/restore only show a plan unless
        --apply is given. Mechanics stay on launchctl state and file snapshots —
        nothing here deletes files. com.apple.* labels and /System are refused
        by construction, no flag bypasses the gate.
        """,
        version: "0.2.0",
        subcommands: [ListCommand.self, InspectCommand.self, DoctorCommand.self,
                      DisableCommand.self, EnableCommand.self,
                      BackupCommand.self, RestoreCommand.self],
        defaultSubcommand: ListCommand.self
    )
}