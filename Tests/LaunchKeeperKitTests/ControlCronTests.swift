import XCTest
@testable import LaunchKeeperKit

// V0.7.0: user-crontab lines become switchable. `disable` comments one line
// out behind `#launchkeeper-disabled `, `enable` takes the marker off; the
// whole table is snapshotted first and read back afterwards. Hermetic: a
// stateful crontab twin answers `crontab -l` and installs `crontab <file>`.

private let table = """
# m h dom mon dow command
MAILTO=alice
0 3 * * *   /opt/backup/run.sh --nightly
*/15 * * * * /Users/alice/bin/sync --token=abc123 >/dev/null 2>&1
@reboot /usr/local/bin/agent --start

"""

/// Stateful crontab twin. `silentInstall` exits 0 and installs nothing.
final class FakeCrontab: CommandRunner {
    var table: String?
    var silentInstall = false
    private(set) var log: [String] = []

    init(_ table: String?) { self.table = table }

    func run(command: String, arguments: [String], timeout: TimeInterval) -> CommandResult {
        log.append(([command] + arguments).joined(separator: " "))
        switch (command, arguments) {
        case ("/bin/launchctl", ["print", "gui/501"]):
            return CommandResult(exitCode: 0, stdout: "gui/501 = {\nservices = {\n}\n}\n", stderr: "")
        case ("/bin/launchctl", ["print-disabled", "gui/501"]):
            return CommandResult(exitCode: 0, stdout: "", stderr: "")
        case ("/usr/bin/atq", []):
            return CommandResult(exitCode: 0, stdout: "", stderr: "")
        case ("/usr/bin/pmset", ["-g", "sched"]):
            return CommandResult(exitCode: 0, stdout: "", stderr: "")
        case ("/usr/bin/crontab", ["-l"]):
            guard let table else {
                return CommandResult(exitCode: 1, stdout: "", stderr: "crontab: no crontab for alice\n")
            }
            return CommandResult(exitCode: 0, stdout: table, stderr: "")
        case ("/usr/bin/crontab", let args) where args.count == 1 && args[0].hasPrefix("/"):
            guard let data = FileManager.default.contents(atPath: args[0]) else {
                return CommandResult(exitCode: 1, stdout: "", stderr: "crontab: \(args[0]): No such file")
            }
            if !silentInstall { table = String(decoding: data, as: UTF8.self) }
            return CommandResult(exitCode: 0, stdout: "", stderr: "")
        default:
            return CommandResult(exitCode: 127, stdout: "", stderr: "not modeled")
        }
    }

    var installs: [String] { log.filter { $0.hasPrefix("/usr/bin/crontab /") } }
}

final class CronEditorTests: XCTestCase {
    func testDisableCommentsOutExactlyOneLineAndEnableRestoresIt() throws {
        let disabled = try CronEditor.edit(table, schedule: "0 3 * * *", command: "/opt/backup/run.sh --nightly",
                                           operation: .disable).get()
        XCTAssertEqual(disabled.lineNumber, 3)
        let lines = disabled.newText.components(separatedBy: "\n")
        XCTAssertEqual(lines[2], "#launchkeeper-disabled 0 3 * * *   /opt/backup/run.sh --nightly")
        var expected = table.components(separatedBy: "\n")
        expected[2] = lines[2]
        XCTAssertEqual(lines, expected, "every other line stays byte-identical")

        let entries = CronParser.parse(disabled.newText, user: "alice", source: "crontab")
        XCTAssertEqual(entries.count, 3, "a disabled line is still inventoried")
        XCTAssertEqual(entries.first { $0.command == "/opt/backup/run.sh --nightly" }?.disabled, true)

        let enabled = try CronEditor.edit(disabled.newText, schedule: "0 3 * * *",
                                          command: "/opt/backup/run.sh --nightly", operation: .enable).get()
        XCTAssertEqual(enabled.newText, table, "enable restores the original byte for byte")
    }

    func testOrdinaryCommentsAreNeverReadAsDisabledJobs() {
        let text = "# 0 3 * * * /opt/old.sh\n#launchkeeper-disabledX 1 1 * * * /x\n"
        XCTAssertTrue(CronParser.parse(text, user: "alice", source: "crontab").isEmpty)
    }

    func testRefusals() {
        func reason(_ result: Result<CronEditor.Edit, ControlRefusal>) -> String {
            if case .failure(let refusal) = result { return refusal.reason }
            return "allowed"
        }
        XCTAssertTrue(reason(CronEditor.edit(table, schedule: "1 1 * * *", command: "/gone", operation: .disable))
            .contains("no longer contains"))
        XCTAssertTrue(reason(CronEditor.edit(table, schedule: "0 3 * * *", command: "/opt/backup/run.sh --nightly",
                                             operation: .enable)).contains("not disabled"))
        let twice = "0 3 * * * /x\n0 3 * * * /x\n"
        XCTAssertTrue(reason(CronEditor.edit(twice, schedule: "0 3 * * *", command: "/x", operation: .disable))
            .contains("2 times"))
        XCTAssertTrue(reason(CronEditor.edit(table, schedule: "0 3 * * *", command: "/opt/backup/run.sh --nightly",
                                             operation: .remove)).contains("never removed"))
    }

    func testSystemTableEntriesAreNotEditable() {
        var item = BackgroundItem(key: "cron:root:/etc/crontab:/x", displayName: "/x", type: .cronJob,
                                  path: "/etc/crontab", owner: "root", domain: .system, category: .scheduled)
        item.metadata = ["cron-source": "/etc/crontab", "cron-schedule": "0 3 * * *", "cron-command": "/x"]
        XCTAssertEqual(item.controlMechanism, .cron)
        guard case .denied(let reason) = RemediationGate.evaluate(operation: .disable, item: item) else {
            return XCTFail("/etc/crontab is not ours to edit")
        }
        XCTAssertTrue(reason.contains("system cron table"), reason)
        XCTAssertEqual(ControlAnalyzer(launchDirs: []).evaluate(item).level, .displayOnly)
    }
}

final class CronControlEngineTests: XCTestCase {
    private let options = ScanOptions(includeUser: true, includeSystem: false, scanBTM: false,
                                      scanSignatures: false, scanExtensions: false,
                                      scanSystemExtensions: false, scanHelpers: false, scanScheduled: true,
                                      scanLegacy: false, scanPlugins: false, scanShell: false, scanNetwork: false,
                                      scanReceipts: false)

    private func home() throws -> String {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("lk-cron-\(UUID().uuidString)", isDirectory: true).path
        try FileManager.default.createDirectory(atPath: dir + "/Library/LaunchAgents", withIntermediateDirectories: true)
        return dir
    }

    private func engine(_ runner: CommandRunner, home: String) -> RemediationEngine {
        RemediationEngine(environment: RemediationEnvironment(runner: runner, home: home, uid: 501,
                                                              configSnapshotsRoot: home + "/snapshots"),
                          audit: AuditLog(directory: home + "/logs"))
    }

    func testDryRunReadsButNeverInstallsOrSnapshots() throws {
        let home = try home()
        defer { try? FileManager.default.removeItem(atPath: home) }
        let cron = FakeCrontab(table)
        let result = engine(cron, home: home).run(operation: .disable, target: "run.sh", apply: false,
                                                  scanOptions: options)
        XCTAssertEqual(result.status, .planned, "\(result.messages)")
        XCTAssertTrue(result.target.hasPrefix("crontab:"), result.target)
        XCTAssertTrue(result.target.hasSuffix(":line3"), result.target)
        XCTAssertTrue(cron.installs.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: home + "/snapshots"))
        XCTAssertEqual(cron.table, table)
    }

    func testApplySnapshotsInstallsVerifiesAndEnableRestores() throws {
        let home = try home()
        defer { try? FileManager.default.removeItem(atPath: home) }
        let cron = FakeCrontab(table)
        let result = engine(cron, home: home).run(operation: .disable, target: "run.sh", apply: true,
                                                  scanOptions: options)
        XCTAssertEqual(result.status, .appliedOk, "\(result.messages)")
        XCTAssertEqual(cron.installs.count, 1)
        XCTAssertTrue(cron.table?.contains("#launchkeeper-disabled 0 3 * * *") == true)
        XCTAssertTrue(result.messages.contains("verified: crontab -l reads back exactly the edited table"))

        // The snapshot holds the table as it was, with a matching manifest.
        let snapshots = try FileManager.default.contentsOfDirectory(atPath: home + "/snapshots")
        XCTAssertEqual(snapshots.count, 1)
        let saved = try String(contentsOfFile: home + "/snapshots/\(snapshots[0])/crontab.txt", encoding: .utf8)
        XCTAssertEqual(saved, table)
        XCTAssertTrue(result.undoHint?.contains("full rollback: crontab") == true, result.undoHint ?? "-")

        // The audit line names the line, never the command (it carries a token).
        let audit = engine(cron, home: home).audit.readAll()
        XCTAssertTrue(audit.contains("snapshot \(snapshots[0]) pre-disable"), audit)
        XCTAssertFalse(audit.contains("token"), audit)

        // The disabled line is still in the inventory — enable finds it.
        let back = engine(cron, home: home).run(operation: .enable, target: "run.sh", apply: true,
                                                scanOptions: options)
        XCTAssertEqual(back.status, .appliedOk, "\(back.messages)")
        XCTAssertEqual(cron.table, table)
    }

    func testSilentInstallIsCaughtByVerification() throws {
        let home = try home()
        defer { try? FileManager.default.removeItem(atPath: home) }
        let cron = FakeCrontab(table)
        cron.silentInstall = true
        let result = engine(cron, home: home).run(operation: .disable, target: "run.sh", apply: true,
                                                  scanOptions: options)
        guard case .appliedFailed(let detail) = result.status else {
            return XCTFail("exit 0 without effect must fail verification, got \(result.status)")
        }
        XCTAssertTrue(detail.contains("differs"), detail)
    }

    func testTableChangedSinceTheScanIsRefused() throws {
        let home = try home()
        defer { try? FileManager.default.removeItem(atPath: home) }
        // The scan sees the entry; by the time the edit reads the table
        // again, it is gone — the edit must not guess.
        final class ShiftingCrontab: CommandRunner {
            let inner = FakeCrontab(table)
            var reads = 0
            func run(command: String, arguments: [String], timeout: TimeInterval) -> CommandResult {
                if command == "/usr/bin/crontab", arguments == ["-l"] {
                    reads += 1
                    if reads > 1 { inner.table = "@reboot /usr/local/bin/agent --start\n" }
                }
                return inner.run(command: command, arguments: arguments, timeout: timeout)
            }
        }
        let runner = ShiftingCrontab()
        let result = engine(runner, home: home).run(operation: .disable, target: "run.sh", apply: true,
                                                    scanOptions: options)
        guard case .refused(let reason) = result.status else { return XCTFail("\(result.status)") }
        XCTAssertTrue(reason.contains("no longer contains"), reason)
        XCTAssertTrue(runner.inner.installs.isEmpty)
    }

    func testControlMatrixForUserCrontabLines() throws {
        let home = try home()
        defer { try? FileManager.default.removeItem(atPath: home) }
        let report = ScanCoordinator(environment: ScanEnvironment(runner: FakeCrontab(table), home: home, uid: 501))
            .perform(options: options)
        let job = try XCTUnwrap(report.items.first { $0.metadata["cron-command"] == "/opt/backup/run.sh --nightly" })
        XCTAssertEqual(job.control?.level, .reversible)
        XCTAssertEqual(job.control?.mechanism, .cron)
        XCTAssertEqual(job.control?.actions, ["disable", "enable"])
    }
}
