import XCTest
@testable import BTMKit

// V0.4b guarded-resetbtm tests. HERMETIC: the "BTM database" is a stateful
// in-memory double behind the runner seam (dumpbtm/archive/resetbtm all go
// through CommandRunner), snapshot files land in a temp root. The rules:
//   1. dry-run executes NOTHING (no snapshot, no reset, no archive).
//   2. no snapshot, no reset — an unwritable snapshot dir must block the
//      reset, not just warn.
//   3. unreadable database, no reset.
//   4. verify-after-mutate: the post-dump is the verdict; a failed or timed
//      out post-dump makes an applied run an appliedFailed, full stop.
//   5. one pre-dump, used twice: the gate read IS the snapshot content —
//      a wedged dumpbtm costs its full timeout budget, never paid twice.

/// The fake BTM database: `dumpbtm` renders the current records in the real
/// output format (BTMDumpParser must parse it back), `resetbtm` empties it.
final class BTMStoreDouble: CommandRunner {
    private var recordNames: [String]
    var resetCalled = false
    var dumpExitCode: Int32 = 0
    var dumpTimesOut = false
    private(set) var log: [String] = []

    init(records: Int) {
        self.recordNames = (1...records).map { "record-\($0)" }
    }

    private func dumpText() -> String {
        var out = "========================\n"
        out += " Records for UID 501 : 11112222-3333-4444-5555-666677778888\n"
        out += "========================\n\n"
        out += " ServiceManagement migrated: true\n\n"
        out += " Items:\n"
        for (index, name) in recordNames.enumerated() {
            out += "   #\(index + 1):\n"
            out += "                UUID: AAAA\(index + 1)BBBB\n"
            out += "                Name: \(name)\n"
            out += "                Type: launch agent (0x1)\n"
            out += "        Identifier: 501.com.test.\(name)\n"
        }
        return out
    }

    func run(command: String, arguments: [String], timeout: TimeInterval) -> CommandResult {
        let key = ([command] + arguments).joined(separator: " ")
        log.append(key)
        guard command == "/usr/bin/sfltool" else {
            return CommandResult(exitCode: 127, stdout: "", stderr: "not scripted")
        }
        switch arguments.first {
        case "dumpbtm":
            if dumpTimesOut { return CommandResult(exitCode: -2, stdout: "", stderr: "timeout") }
            if dumpExitCode != 0 {
                return CommandResult(exitCode: dumpExitCode, stdout: "", stderr: "db error")
            }
            return CommandResult(exitCode: 0, stdout: dumpText(), stderr: "")
        case "archive":
            return CommandResult(exitCode: 0,
                                 stdout: "SharedFileList storage copied to '/tmp/SFL-archive_test'",
                                 stderr: "")
        case "resetbtm":
            resetCalled = true
            recordNames = []
            return CommandResult(exitCode: 0, stdout: "Database reset.", stderr: "")
        default:
            return CommandResult(exitCode: 1, stdout: "", stderr: "unknown subcommand")
        }
    }

    func runInteractive(command: String, arguments: [String], timeout: TimeInterval) -> Int32 {
        run(command: command, arguments: arguments, timeout: timeout).exitCode
    }
}

final class BTMResetTests: XCTestCase {
    private var fm = FileManager.default
    private var root: String = ""
    private var snapshotsRoot: String = ""

    override func setUp() {
        super.setUp()
        fm = FileManager.default
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("btmctl-reset-\(UUID().uuidString)", isDirectory: true).path
        try? fm.createDirectory(atPath: root, withIntermediateDirectories: true)
        snapshotsRoot = root + "/snapshots"
    }

    override func tearDown() {
        try? fm.removeItem(atPath: root)
        super.tearDown()
    }

    private func service(_ runner: some CommandRunner) -> BTMResetService {
        BTMResetService(env: BTMResetEnvironment(runner: runner, fileManager: fm,
                                                 home: root, snapshotsRoot: snapshotsRoot))
    }

    // MARK: - dry-run

    func testDryRunExecutesNothing() {
        let double = BTMStoreDouble(records: 5)
        let outcome = service(double).run(apply: false)
        guard case .dryRun(let before, let wouldSnapshot, _) = outcome else {
            return XCTFail("expected dryRun, got \(outcome)")
        }
        XCTAssertEqual(before, 5)
        XCTAssertFalse(wouldSnapshot.isEmpty)
        XCTAssertFalse(double.resetCalled, "dry-run must not reset")
        XCTAssertEqual(double.log, ["/usr/bin/sfltool dumpbtm"],
                       "a dry-run reads state, nothing else — actual: \(double.log)")
        XCTAssertFalse(fm.fileExists(atPath: snapshotsRoot),
                       "dry-run must not write a snapshot")
    }

    // MARK: - apply: snapshot -> reset -> verify

    func testApplySnapshotsThenResetsThenVerifies() throws {
        let double = BTMStoreDouble(records: 7)
        let outcome = service(double).run(apply: true)
        guard case .applied(let before, let after, let snapshot, _) = outcome else {
            return XCTFail("expected applied, got \(outcome)")
        }
        XCTAssertEqual(before, 7)
        XCTAssertEqual(after, 0)
        XCTAssertTrue(fm.fileExists(atPath: snapshot), "the audit snapshot must exist")
        let content = try String(contentsOf: URL(fileURLWithPath: snapshot), encoding: .utf8)
        XCTAssertTrue(content.contains("record-7"),
                      "the snapshot must capture the PRE-reset state")
        XCTAssertEqual(double.log,
                       ["/usr/bin/sfltool dumpbtm",      // before: gate AND
                        // snapshot content (one dump, used twice)
                        "/usr/bin/sfltool archive",      // sibling store copy
                        "/usr/bin/sfltool resetbtm",     // the reset
                        "/usr/bin/sfltool dumpbtm"],     // verify
                       "order matters: read, snapshot, reset, verify — "
                       + "actual: \(double.log)")
    }

    func testAppliedOutcomeCarriesIrreversibilityNote() {
        let double = BTMStoreDouble(records: 3)
        if case .applied(_, _, _, let notes) = service(double).run(apply: true) {
            XCTAssertTrue(notes.contains { $0.hasPrefix("NOT RESTORABLE") },
                          "actual: \(notes)")
        } else {
            XCTFail("expected applied")
        }
    }

    // MARK: - no snapshot, no reset

    func testUnwritableSnapshotRootBlocksTheReset() throws {
        // A FILE where the snapshot directory would be: createDirectory fails.
        try Data("x".utf8).write(to: URL(fileURLWithPath: snapshotsRoot))
        let double = BTMStoreDouble(records: 4)
        let outcome = service(double).run(apply: true)
        guard case .refused(let reason) = outcome else {
            return XCTFail("expected refused, got \(outcome)")
        }
        XCTAssertTrue(reason.contains("snapshot"), "actual: \(reason)")
        XCTAssertFalse(double.resetCalled,
                       "an unrecorded reset of a system database is the incident failure mode")
    }

    // MARK: - unreadable database, no reset

    func testUnreadableDatabaseIsRefused() {
        let double = BTMStoreDouble(records: 4)
        double.dumpExitCode = 1
        let outcome = service(double).run(apply: true)
        guard case .refused(let reason) = outcome else {
            return XCTFail("expected refused, got \(outcome)")
        }
        XCTAssertTrue(reason.contains("could not read"), "actual: \(reason)")
        XCTAssertFalse(double.resetCalled)
        XCTAssertEqual(double.log, ["/usr/bin/sfltool dumpbtm"])
    }

    // MARK: - verify-after-mutate

    func testTimedOutPostDumpIsAppliedFailed() {
        // Reset succeeds; the VERIFICATION dump times out — the end state is
        // unknown, and unknown is not success.
        let selective = SelectiveDumpDouble(initialRecords: 4)
        let outcome = service(selective).run(apply: true)
        guard case .appliedFailed(let detail, _, _) = outcome else {
            return XCTFail("expected appliedFailed, got \(outcome)")
        }
        XCTAssertTrue(detail.lowercased().contains("post-dump"), "actual: \(detail)")
        XCTAssertTrue(selective.resetCalled)
    }

    func testFailingPostDumpIsAppliedFailed() {
        let selective = SelectiveDumpDouble(initialRecords: 4, postDumpExitCode: 64)
        let outcome = service(selective).run(apply: true)
        guard case .appliedFailed(let detail, _, _) = outcome else {
            return XCTFail("expected appliedFailed, got \(outcome)")
        }
        XCTAssertTrue(detail.contains("unverified"), "actual: \(detail)")
    }
}

/// dumpbtm #1 (pre) succeeds, dumpbtm #2+ (post) misbehaves as configured.
final class SelectiveDumpDouble: CommandRunner {
    private let inner: BTMStoreDouble
    private var dumpCount = 0
    var postDumpExitCode: Int32
    var resetCalled: Bool { inner.resetCalled }

    init(initialRecords: Int, postDumpExitCode: Int32 = -2) {
        self.inner = BTMStoreDouble(records: initialRecords)
        self.postDumpExitCode = postDumpExitCode
    }

    func run(command: String, arguments: [String], timeout: TimeInterval) -> CommandResult {
        var result = inner.run(command: command, arguments: arguments, timeout: timeout)
        if arguments.first == "dumpbtm" {
            dumpCount += 1
            if dumpCount > 1 {
                result = postDumpExitCode == -2
                    ? CommandResult(exitCode: -2, stdout: "", stderr: "timeout")
                    : CommandResult(exitCode: postDumpExitCode, stdout: "", stderr: "db error")
            }
        }
        return result
    }

    func runInteractive(command: String, arguments: [String], timeout: TimeInterval) -> Int32 {
        inner.run(command: command, arguments: arguments, timeout: timeout).exitCode
    }
}