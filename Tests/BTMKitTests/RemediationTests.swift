import XCTest
@testable import BTMKit

// V0.2 remediation tests. Two fakes make the write paths testable WITHOUT
// ever touching real launchd or real system directories:
//   FakeLaunchd  — stateful launchd twin: prints reflect its current state,
//                  mutations flip it. A flat scripted table cannot express
//                  before/after state change; this can.
//   CopyRunner   — answers the `sudo cp` interactive seam by really copying
//                  inside a temp dir (and records that the seam was used).

final class FakeLaunchd: CommandRunner {
    var services: [String: Int] = [:]          // label -> pid (0 = loaded, not running)
    var disabled: Set<String> = []              // labels with a disable override
    var failBootout = false
    var silentEnable = false                    // exits 0 but does NOT clear the override
    private(set) var log: [String] = []

    private func launchctlArgs(_ command: String, _ arguments: [String]) -> [String]? {
        if command == "/bin/launchctl" { return arguments }
        if command == "/usr/bin/sudo", arguments.first == "launchctl" {
            return Array(arguments.dropFirst())
        }
        return nil
    }

    private func label(from target: String) -> String? {
        // Targets are "gui/501/<label>" (user) or "system/<label>" (system) —
        // the label is always the LAST component.
        let parts = target.split(separator: "/")
        guard parts.count >= 2 else { return nil }
        return String(parts.last!)
    }

    private func handle(_ args: [String]) -> CommandResult {
        switch args.first {
        case "print" where args.count == 2:
            var out = "domain = {\nservices = {\n"
            for (label, pid) in services.sorted(by: { $0.key < $1.key }) {
                out += pid > 0
                    ? "      \(pid)   (pe) \(label)\n"
                    : "        0      -  \(label)\n"
            }
            out += "}\n}\n"
            return CommandResult(exitCode: 0, stdout: out, stderr: "")
        case "print-disabled" where args.count == 2:
            var out = "{\n"
            for label in disabled.sorted() { out += "   \"\(label)\" => disabled\n" }
            out += "}\n"
            return CommandResult(exitCode: 0, stdout: out, stderr: "")
        case "disable" where args.count == 2:
            guard let label = label(from: args[1]) else {
                return CommandResult(exitCode: 1, stdout: "", stderr: "bad target")
            }
            disabled.insert(label)
            return CommandResult(exitCode: 0, stdout: "", stderr: "")
        case "enable" where args.count == 2:
            guard let label = label(from: args[1]) else {
                return CommandResult(exitCode: 1, stdout: "", stderr: "bad target")
            }
            if !silentEnable { disabled.remove(label) }
            return CommandResult(exitCode: 0, stdout: "", stderr: "")
        case "bootout" where args.count == 2:
            guard let label = label(from: args[1]) else {
                return CommandResult(exitCode: 1, stdout: "", stderr: "bad target")
            }
            if failBootout {
                return CommandResult(exitCode: 1, stdout: "", stderr: "Boot-out failed")
            }
            services.removeValue(forKey: label)
            return CommandResult(exitCode: 0, stdout: "", stderr: "")
        case "bootstrap" where args.count == 3:
            let file = (args[2] as NSString).lastPathComponent
            let label = file.hasSuffix(".plist") ? String(file.dropLast(6)) : file
            services[label] = 0
            return CommandResult(exitCode: 0, stdout: "", stderr: "")
        default:
            return CommandResult(exitCode: 127, stdout: "",
                                 stderr: "not modeled: \(args.joined(separator: " "))")
        }
    }

    func run(command: String, arguments: [String], timeout: TimeInterval) -> CommandResult {
        let key = ([command] + arguments).joined(separator: " ")
        log.append(key)
        guard let args = launchctlArgs(command, arguments) else {
            return CommandResult(exitCode: 127, stdout: "", stderr: "not modeled")
        }
        return handle(args)
    }

    func runInteractive(command: String, arguments: [String], timeout: TimeInterval) -> Int32 {
        let key = ([command] + arguments).joined(separator: " ")
        log.append(key)
        guard let args = launchctlArgs(command, arguments) else { return 127 }
        return handle(args).exitCode
    }
}

final class CopyRunner: CommandRunner {
    var fm = FileManager.default
    private(set) var interactiveLog: [String] = []

    func run(command: String, arguments: [String], timeout: TimeInterval) -> CommandResult {
        if command == "/bin/launchctl", arguments.first == "print-disabled" {
            return CommandResult(exitCode: 0, stdout: "{\n}\n", stderr: "")
        }
        return CommandResult(exitCode: 127, stdout: "", stderr: "not modeled")
    }

    func runInteractive(command: String, arguments: [String], timeout: TimeInterval) -> Int32 {
        let key = ([command] + arguments).joined(separator: " ")
        interactiveLog.append(key)
        guard command == "/usr/bin/sudo", arguments.count == 3, arguments[0] == "cp" else {
            return 127
        }
        do {
            if fm.fileExists(atPath: arguments[2]) { try fm.removeItem(atPath: arguments[2]) }
            try fm.copyItem(atPath: arguments[1], toPath: arguments[2])
            return 0
        } catch {
            return 1
        }
    }
}

private func makeUserHome(withPlists names: [String]) throws -> String {
    let dir = FileManager.default.temporaryDirectory
        .appendingPathComponent("btmctl-remediation-tests-\(UUID().uuidString)", isDirectory: true)
    let agents = dir.appendingPathComponent("Library/LaunchAgents", isDirectory: true)
    try FileManager.default.createDirectory(at: agents, withIntermediateDirectories: true)
    for name in names {
        let plist = """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0">
        <dict>
          <key>Label</key><string>\(name)</string>
          <key>ProgramArguments</key><array><string>/bin/bash</string><string>/nonexistent-xyz-dir/gone.sh</string></array>
          <key>RunAtLoad</key><true/>
        </dict>
        </plist>
        """
        try Data(plist.utf8).write(to: agents.appendingPathComponent("\(name).plist"))
    }
    return dir.path
}

// MARK: - Gate

final class RemediationGateTests: XCTestCase {
    private func item(label: String?, path: String? = nil, exec: String? = nil) -> BackgroundItem {
        BackgroundItem(key: label ?? "no-key", displayName: label ?? "no-key",
                       path: path, label: label, executable: exec, domain: .user)
    }

    func testAppleLabelRefused() {
        let decision = RemediationGate.evaluate(operation: .disable, item: item(label: "com.apple.Finder"))
        guard case .denied(let reason) = decision, reason.contains("com.apple.*") else {
            return XCTFail("expected Apple refusal, got \(decision)")
        }
    }

    func testAppleRefusedEvenForEnable() {
        // Reversibility must not become a backdoor into Apple territory.
        let decision = RemediationGate.evaluate(operation: .enable, item: item(label: "com.apple.Finder"))
        guard case .denied = decision else { return XCTFail("expected refusal, got \(decision)") }
    }

    func testSystemPathRefused() {
        let viaExec = RemediationGate.evaluate(
            operation: .disable,
            item: item(label: "de.ghost.tool", exec: "/System/Library/PrivilegedHelperTools/x"))
        guard case .denied(let reason) = viaExec, reason.contains("/System") else {
            return XCTFail("expected /System refusal via executable, got \(viaExec)")
        }
        let viaPath = RemediationGate.evaluate(
            operation: .disable,
            item: item(label: "de.ghost.tool", path: "/System/Library/LaunchDaemons/x.plist"))
        guard case .denied = viaPath else {
            return XCTFail("expected /System refusal via path, got \(viaPath)")
        }
    }

    func testUserScriptAllowed() {
        // /bin/bash is NOT /System territory; gate denies only com.apple.* + /System.
        let decision = RemediationGate.evaluate(
            operation: .disable,
            item: item(label: "com.example.script", exec: "/bin/bash"))
        XCTAssertEqual(decision, .allowed)
    }

    func testNoLabelRefused() {
        let decision = RemediationGate.evaluate(operation: .disable,
                                                item: item(label: nil, exec: "/usr/local/bin/x"))
        guard case .denied = decision else { return XCTFail("expected refusal, got \(decision)") }
    }
}

// MARK: - TargetResolver

final class TargetResolverTests: XCTestCase {
    private var items: [BackgroundItem] {
        [
            BackgroundItem(id: "07", key: "com.example.script", displayName: "com.example.script",
                           label: "com.example.script"),
            BackgroundItem(id: "08", key: "ghost.a", displayName: "Ghost A", label: "de.ghost.a"),
            BackgroundItem(id: "09", key: "ghost.b", displayName: "Ghost B", label: "de.ghost.b"),
        ]
    }

    func testNumericIdMatch() {
        guard case .unique(let item) = TargetResolver.resolve("07", in: items),
              item.key == "com.example.script" else {
            return XCTFail("numeric id must resolve by display id")
        }
    }

    func testUniqueFragment() {
        guard case .unique(let item) = TargetResolver.resolve("script", in: items),
              item.key == "com.example.script" else {
            return XCTFail("unique fragment must resolve")
        }
    }

    func testNoMatch() {
        guard case .none(let needle) = TargetResolver.resolve("nothing-here", in: items) else {
            return XCTFail("expected .none")
        }
        XCTAssertEqual(needle, "nothing-here")
    }

    func testAmbiguousFragment() {
        guard case .ambiguous(let needle, let candidates) = TargetResolver.resolve("ghost", in: items) else {
            return XCTFail("expected .ambiguous")
        }
        XCTAssertEqual(needle, "ghost")
        XCTAssertEqual(candidates.count, 2, "both ghosts must be previewed")
    }
}

// MARK: - Planner

final class RemediationPlannerTests: XCTestCase {
    private func userItem(loaded: Bool) -> BackgroundItem {
        BackgroundItem(key: "com.example.script", displayName: "com.example.script",
                       path: "/Users/test/Library/LaunchAgents/com.example.script.plist",
                       label: "com.example.script",
                       executable: "/bin/bash", domain: .user, loaded: loaded)
    }

    func testUserDisableLoadedTwoCommandsInOrder() {
        let plan = RemediationPlanner.plan(operation: .disable, item: userItem(loaded: true), uid: 501)
        XCTAssertEqual(plan.map(\.display), [
            "/bin/launchctl disable gui/501/com.example.script",
            "/bin/launchctl bootout gui/501/com.example.script",
        ], "override must come BEFORE unload (keepAlive cannot reload)")
    }

    func testUserDisableSkipsBootoutWhenNotLoaded() {
        let plan = RemediationPlanner.plan(operation: .disable, item: userItem(loaded: false), uid: 501)
        XCTAssertEqual(plan.map(\.display), ["/bin/launchctl disable gui/501/com.example.script"])
    }

    func testSystemDaemonGoesThroughSudo() {
        let daemon = BackgroundItem(key: "de.ghost.helper", displayName: "de.ghost.helper",
                                    path: "/Library/LaunchDaemons/de.ghost.helper.plist",
                                    label: "de.ghost.helper",
                                    executable: "/usr/local/bin/helper",
                                    domain: .system, loaded: true)
        let plan = RemediationPlanner.plan(operation: .disable, item: daemon, uid: 501)
        XCTAssertEqual(plan.map(\.display), [
            "/usr/bin/sudo launchctl disable system/de.ghost.helper",
            "/usr/bin/sudo launchctl bootout system/de.ghost.helper",
        ], "system domain = sudo, and sudo owns the whole argv list")
    }

    func testEnableWithoutNowIsSingleCommand() {
        let plan = RemediationPlanner.plan(operation: .enable, item: userItem(loaded: false), uid: 501)
        XCTAssertEqual(plan.map(\.display), ["/bin/launchctl enable gui/501/com.example.script"])
    }

    func testEnableWithNowAddsBootstrap() {
        let plan = RemediationPlanner.plan(operation: .enable, item: userItem(loaded: false),
                                           uid: 501, now: true)
        XCTAssertEqual(plan.map(\.display), [
            "/bin/launchctl enable gui/501/com.example.script",
            "/bin/launchctl bootstrap gui/501 /Users/test/Library/LaunchAgents/com.example.script.plist",
        ])
    }

    func testEnableWithNowButNoPlistSkipsBootstrap() {
        let item = userItem(loaded: false)
        var bare = item
        bare.path = "relative/path"   // no leading /, no .plist
        let plan = RemediationPlanner.plan(operation: .enable, item: bare, uid: 501, now: true)
        XCTAssertEqual(plan.count, 1, "nothing to bootstrap from")
    }
}

// MARK: - Executor

final class RemediationExecutorTests: XCTestCase {
    private func userItem(loaded: Bool, enabled: Bool = true) -> BackgroundItem {
        BackgroundItem(key: "com.example.script", displayName: "com.example.script",
                       path: "/Users/test/Library/LaunchAgents/com.example.script.plist",
                       label: "com.example.script",
                       executable: "/bin/bash", domain: .user,
                       loaded: loaded, enabled: enabled)
    }

    func testDisableHappyPath() {
        let fake = FakeLaunchd()
        fake.services["com.example.script"] = 999
        let executor = RemediationExecutor(runner: fake, uid: 501)
        let plan = RemediationPlanner.plan(operation: .disable, item: userItem(loaded: true), uid: 501)
        let outcome = executor.execute(plan, operation: .disable, item: userItem(loaded: true))
        XCTAssertEqual(outcome.status, .appliedOk)
        XCTAssertTrue(fake.disabled.contains("com.example.script"))
        XCTAssertFalse(fake.services.keys.contains("com.example.script"))
        XCTAssertFalse(fake.log.contains { $0.contains("sudo") },
                       "user domain must never run through sudo")
    }

    func testStopsAtFailingCommandLeavingPartialState() {
        let fake = FakeLaunchd()
        fake.services["com.example.script"] = 999
        fake.failBootout = true
        let executor = RemediationExecutor(runner: fake, uid: 501)
        let item = userItem(loaded: true)
        let outcome = executor.execute(
            RemediationPlanner.plan(operation: .disable, item: item, uid: 501),
            operation: .disable, item: item)
        XCTAssertEqual(outcome.status, .appliedFailed("exit 1"))
        XCTAssertEqual(outcome.executed.count, 2, "second command ran and failed")
        XCTAssertTrue(fake.disabled.contains("com.example.script"),
                      "partial state documented: override applied, unload failed")
        XCTAssertTrue(fake.services.keys.contains("com.example.script"))
    }

    func testSilentFailureCaughtByVerification() {
        // Every command "exits 0" but nothing changes — exit codes prove nothing,
        // the verify-after-mutate read must catch this.
        let runner = ScriptedCommandRunner(defaultResult: CommandResult(exitCode: 0, stdout: "", stderr: ""))
        let executor = RemediationExecutor(runner: runner, uid: 501)
        let item = userItem(loaded: true)
        let outcome = executor.execute(
            RemediationPlanner.plan(operation: .disable, item: item, uid: 501),
            operation: .disable, item: item)
        guard case .appliedFailed(let detail) = outcome.status else {
            return XCTFail("expected appliedFailed, got \(outcome.status)")
        }
        XCTAssertTrue(detail.contains("no disable override visible"), "actual: \(detail)")
    }

    func testEnableWithBootstrapRestoresState() {
        let fake = FakeLaunchd()
        fake.disabled.insert("com.example.script")
        let executor = RemediationExecutor(runner: fake, uid: 501)
        let item = userItem(loaded: false, enabled: false)
        let outcome = executor.execute(
            RemediationPlanner.plan(operation: .enable, item: item, uid: 501, now: true),
            operation: .enable, item: item)
        XCTAssertEqual(outcome.status, .appliedOk)
        XCTAssertFalse(fake.disabled.contains("com.example.script"))
        XCTAssertTrue(fake.services.keys.contains("com.example.script"),
                      "--now must bootstrap the job again")
    }

    func testSystemDisableUsesInteractiveSudoSeam() {
        let fake = FakeLaunchd()
        fake.services["de.ghost.helper"] = 4242
        let executor = RemediationExecutor(runner: fake, uid: 501)
        let daemon = BackgroundItem(key: "de.ghost.helper", displayName: "de.ghost.helper",
                                    path: "/Library/LaunchDaemons/de.ghost.helper.plist",
                                    label: "de.ghost.helper",
                                    executable: "/usr/local/bin/helper",
                                    domain: .system, loaded: true)
        let outcome = executor.execute(
            RemediationPlanner.plan(operation: .disable, item: daemon, uid: 501),
            operation: .disable, item: daemon)
        XCTAssertEqual(outcome.status, .appliedOk)
        XCTAssertTrue(fake.log.contains("/usr/bin/sudo launchctl disable system/de.ghost.helper"),
                      "actual log: \(fake.log)")
        XCTAssertTrue(fake.disabled.contains("de.ghost.helper"))
    }
}

// MARK: - Engine end-to-end (scan -> resolve -> gate -> plan -> execute)

final class RemediationEngineTests: XCTestCase {
    private func makeEngine(home: String, fake: FakeLaunchd) -> RemediationEngine {
        let env = RemediationEnvironment(runner: fake, home: home, uid: 501)
        return RemediationEngine(environment: env,
                                 audit: AuditLog(directory: home + "/logs"))
    }

    private let userOnly = ScanOptions(includeUser: true, includeSystem: false,
                                       scanBTM: false, scanSignatures: false)

    func testDryRunReadsOnly() throws {
        let home = try makeUserHome(withPlists: ["com.example.script"])
        defer { try? FileManager.default.removeItem(atPath: home) }
        let fake = FakeLaunchd()
        fake.services["com.example.script"] = 999
        let engine = makeEngine(home: home, fake: fake)

        let result = engine.run(operation: .disable, target: "com.example.script",
                                apply: false, scanOptions: userOnly)
        XCTAssertEqual(result.status, .planned)
        XCTAssertEqual(result.target, "gui/501/com.example.script",
                       "audit target = resolved service, not the raw needle")
        XCTAssertEqual(result.plan.map(\.display), [
            "/bin/launchctl disable gui/501/com.example.script",
            "/bin/launchctl bootout gui/501/com.example.script",
        ])
        XCTAssertFalse(fake.log.contains { !$0.hasPrefix("/bin/launchctl print") },
                       "dry-run must only read: \(fake.log)")
        let audit = engine.audit.readAll()
        XCTAssertTrue(audit.contains("disable gui/501/com.example.script planned"),
                      "actual audit: \(audit)")
    }

    func testApplyDisableChangesState() throws {
        let home = try makeUserHome(withPlists: ["com.example.script"])
        defer { try? FileManager.default.removeItem(atPath: home) }
        let fake = FakeLaunchd()
        fake.services["com.example.script"] = 999
        let engine = makeEngine(home: home, fake: fake)

        let result = engine.run(operation: .disable, target: "com.example.script",
                                apply: true, scanOptions: userOnly)
        XCTAssertEqual(result.status, .appliedOk)
        XCTAssertTrue(fake.disabled.contains("com.example.script"))
        XCTAssertFalse(fake.services.keys.contains("com.example.script"))
        XCTAssertEqual(result.undoHint, "btmctl enable com.example.script",
                       "reversibility hint must carry the stable label — "
                       + "display ids are positional per scan run and would resolve "
                       + "to a different entry when executed later")
        let audit = engine.audit.readAll()
        XCTAssertTrue(audit.hasSuffix("applied-ok\n"), "actual audit: \(audit)")
    }

    func testAppleFixtureRefusedEndToEnd() throws {
        let home = try makeUserHome(withPlists: ["com.apple.foo"])
        defer { try? FileManager.default.removeItem(atPath: home) }
        let fake = FakeLaunchd()
        let engine = makeEngine(home: home, fake: fake)

        let result = engine.run(operation: .disable, target: "com.apple.foo",
                                apply: true, scanOptions: userOnly)
        guard case .refused(let reason) = result.status, reason.contains("com.apple.*") else {
            return XCTFail("expected Apple refusal end-to-end, got \(result.status)")
        }
        XCTAssertFalse(fake.log.contains { !$0.hasPrefix("/bin/launchctl print") },
                       "refusal must never execute: \(fake.log)")
        XCTAssertTrue(engine.audit.readAll().contains("refused(Apple system component"))
    }

    func testAmbiguousNeedleRefused() throws {
        let home = try makeUserHome(withPlists: ["com.example.ghosta", "com.example.ghostb"])
        defer { try? FileManager.default.removeItem(atPath: home) }
        let engine = makeEngine(home: home, fake: FakeLaunchd())
        let result = engine.run(operation: .disable, target: "ghost", apply: true,
                                scanOptions: userOnly)
        guard case .refused(let reason) = result.status, reason.contains("ambiguous") else {
            return XCTFail("expected ambiguous refusal, got \(result.status)")
        }
    }

    func testEnableRoundTripEndToEnd() throws {
        let home = try makeUserHome(withPlists: ["com.example.script"])
        defer { try? FileManager.default.removeItem(atPath: home) }
        let fake = FakeLaunchd()
        fake.disabled.insert("com.example.script")
        let engine = makeEngine(home: home, fake: fake)

        let result = engine.run(operation: .enable, target: "com.example.script",
                                apply: true, scanOptions: userOnly)
        XCTAssertEqual(result.status, .appliedOk)
        XCTAssertFalse(fake.disabled.contains("com.example.script"),
                       "enable must clear the override end-to-end")
    }
}

// MARK: - AuditLog

final class AuditLogTests: XCTestCase {
    func testFormatLineShape() {
        let line = AuditLog.formatLine(timestamp: Date(timeIntervalSince1970: 0),
                                       operation: "disable",
                                       target: "gui/501/com.example.script",
                                       status: "planned")
        XCTAssertTrue(line.hasPrefix("[1970-01-01T00:00:00Z] btmctl disable gui/501/com.example.script planned"),
                      "actual: \(line)")
    }

    func testAppendCreatesAndExtends() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("btmctl-audit-tests-\(UUID().uuidString)", isDirectory: true)
        defer { try? FileManager.default.removeItem(atPath: dir.path) }
        let log = AuditLog(directory: dir.path)
        XCTAssertNil(log.append(operation: "backup", target: "snapshot-1", status: "applied-ok"))
        XCTAssertNil(log.append(operation: "restore", target: "snapshot-1", status: "planned"))
        let content = log.readAll()
        XCTAssertEqual(content.split(separator: "\n").count, 2)
        XCTAssertTrue(content.contains("backup snapshot-1 applied-ok"))
    }
}

// MARK: - BackupService

final class BackupServiceTests: XCTestCase {
    private struct TestSetup {
        var root: String
        var userDir: String
        var sysDir: String
        var service: BackupService
    }

    private func makeSetup(runner: CommandRunner = CopyRunner()) throws -> TestSetup {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("btmctl-backup-tests-\(UUID().uuidString)", isDirectory: true).path
        let fm = FileManager.default
        let userDir = root + "/user-launch"
        let sysDir = root + "/fake-system"
        try fm.createDirectory(atPath: userDir, withIntermediateDirectories: true)
        try fm.createDirectory(atPath: sysDir, withIntermediateDirectories: true)
        try Data("<plist>user-agent</plist>".utf8).write(to: URL(fileURLWithPath: userDir + "/com.user.agent.plist"))
        try Data("<plist>sys-daemon</plist>".utf8).write(to: URL(fileURLWithPath: sysDir + "/de.sys.helper.plist"))
        let env = BackupEnvironment(launchDirs: [userDir, sysDir],
                                    systemDirPrefixes: [sysDir],
                                    backupsRoot: root + "/backups",
                                    runner: runner,
                                    home: root, uid: 501)
        return TestSetup(root: root, userDir: userDir, sysDir: sysDir,
                         service: BackupService(env: env))
    }

    func testSnapshotRoundTripRestoresDrift() throws {
        let setup = try makeSetup()
        defer { try? FileManager.default.removeItem(atPath: setup.root) }

        guard case .success(let report) = setup.service.create(now: Date()) else {
            return XCTFail("backup create failed")
        }
        XCTAssertEqual(report.copied, 2)
        let fm = FileManager.default
        XCTAssertTrue(fm.fileExists(atPath: report.backupDir + "/manifest.json"))
        XCTAssertTrue(fm.fileExists(atPath: report.backupDir + "/state/print-disabled-gui.txt"))

        // Nothing drifted yet -> dry-run sees no differences.
        if case .success(let clean) = setup.service.restore(name: report.backupName, apply: false) {
            XCTAssertEqual(clean.unchanged.count, 2)
            XCTAssertTrue(clean.wouldRestore.isEmpty)
        } else { return XCTFail("clean restore dry-run failed") }

        // Drift: delete one user file, corrupt one system file.
        try fm.removeItem(atPath: setup.userDir + "/com.user.agent.plist")
        try Data("<plist>TAMPERED</plist>".utf8)
            .write(to: URL(fileURLWithPath: setup.sysDir + "/de.sys.helper.plist"))

        if case .success(let dry) = setup.service.restore(name: report.backupName, apply: false) {
            XCTAssertEqual(Set(dry.wouldRestore),
                           [setup.userDir + "/com.user.agent.plist",
                            setup.sysDir + "/de.sys.helper.plist"])
            XCTAssertTrue(dry.restored.isEmpty, "dry-run copies nothing")
        } else { return XCTFail("drift dry-run failed") }

        guard case .success(let done) = setup.service.restore(name: report.backupName, apply: true) else {
            return XCTFail("apply restore failed")
        }
        XCTAssertEqual(done.restored.count, 2, "actual: \(done.restored) failed: \(done.failed)")
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: setup.userDir + "/com.user.agent.plist")),
                       "<plist>user-agent</plist>".data(using: .utf8))
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: setup.sysDir + "/de.sys.helper.plist")),
                       "<plist>sys-daemon</plist>".data(using: .utf8))
        // System dir must have gone through the interactive sudo seam...
        let runner = try XCTUnwrap((setup.service.env.runner as? CopyRunner))
        XCTAssertTrue(runner.interactiveLog.contains { $0.hasPrefix("/usr/bin/sudo cp") })
        // ...and the user dir NOT:
        XCTAssertFalse(runner.interactiveLog.contains { $0.contains("com.user.agent") })
    }

    /// Builds a hand-crafted backup (manifest + staged files) to drive the
    /// restore guards that a normal `create` can never produce.
    private func writeHandmadeBackup(setup: TestSetup, name: String,
                                     entries: [(rel: String, target: String, content: String)]) throws {
        let fm = FileManager.default
        let dir = setup.root + "/backups/" + name
        var manifestEntries: [ManifestEntry] = []
        for entry in entries {
            let stagedDir = (dir + "/files/" + entry.rel as NSString).deletingLastPathComponent
            try fm.createDirectory(atPath: stagedDir, withIntermediateDirectories: true)
            let data = Data(entry.content.utf8)
            try data.write(to: URL(fileURLWithPath: dir + "/files/" + entry.rel))
            let sha = try XCTUnwrap(BackupCrypto.sha256Hex(data))
            manifestEntries.append(ManifestEntry(rel: entry.rel, target: entry.target,
                                                 sha256: sha, size: data.count, mode: 420, uid: 0))
        }
        let manifest = BackupManifest(createdAt: "2026-09-16T00:00:00Z",
                                      toolVersion: "0.2.0", entries: manifestEntries)
        try JSONEncoder().encode(manifest).write(to: URL(fileURLWithPath: dir + "/manifest.json"))
    }

    func testRestoreNeverWritesSystem() throws {
        let setup = try makeSetup()
        defer { try? FileManager.default.removeItem(atPath: setup.root) }
        try writeHandmadeBackup(setup: setup, name: "evil-1", entries: [
            (rel: "System/Library/LaunchDaemons/x.plist",
             target: "/System/Library/LaunchDaemons/x.plist", content: "payload"),
            // Second entry: target outside the allowlist entirely.
            (rel: "usr/lib/libevil.dylib", target: "/usr/lib/libevil.dylib", content: "payload"),
        ])
        guard case .success(let report) = setup.service.restore(name: "evil-1", apply: true) else {
            return XCTFail("expected success with refusal, not failure")
        }
        XCTAssertEqual(report.refused.count, 2, "actual: \(report.refused)")
        XCTAssertTrue(report.refused[0].contains("/System is never written"))
        XCTAssertTrue(report.refused[1].contains("outside launch-dir allowlist"))
        XCTAssertTrue(report.restored.isEmpty,
                      "both guards must run before any write, even with apply")
    }

    func testRestoreRefusesOutsideAllowlist() throws {
        let setup = try makeSetup()
        defer { try? FileManager.default.removeItem(atPath: setup.root) }
        try writeHandmadeBackup(setup: setup, name: "evil-2", entries: [
            (rel: "etc/evil.plist", target: "/etc/evil.plist", content: "payload"),
        ])
        guard case .success(let report) = setup.service.restore(name: "evil-2", apply: true) else {
            return XCTFail("expected success with refusal")
        }
        XCTAssertEqual(report.refused.count, 1)
        XCTAssertTrue(report.refused[0].contains("outside launch-dir allowlist"))
    }

    func testRestoreDetectsTamperedStaging() throws {
        let setup = try makeSetup()
        defer { try? FileManager.default.removeItem(atPath: setup.root) }
        try writeHandmadeBackup(setup: setup, name: "evil-3", entries: [
            (rel: "user-launch/one.plist", target: setup.userDir + "/one.plist", content: "different"),
        ])
        // Manifest sha was computed over "different"; staged file gets replaced
        // AFTER that — integrity check must catch the mismatch.
        let staged = setup.root + "/backups/evil-3/files/user-launch/one.plist"
        try Data("tampered-after-manifest".utf8).write(to: URL(fileURLWithPath: staged))
        guard case .success(let report) = setup.service.restore(name: "evil-3", apply: true) else {
            return XCTFail("expected success with failure entry")
        }
        XCTAssertEqual(report.failed.count, 1)
        XCTAssertTrue(report.failed[0].contains("INTEGRITY"))
    }

    func testBackupNameInjectionRejected() throws {
        let setup = try makeSetup()
        defer { try? FileManager.default.removeItem(atPath: setup.root) }
        for name in ["../evil", "a/b", "..", "x\\y"] {
            guard case .failure(let error) = setup.service.restore(name: name, apply: true) else {
                return XCTFail("path traversal '\(name)' must be rejected")
            }
            XCTAssertTrue(error.message.contains("path separators"), "actual: \(error.message)")
        }
    }

    func testMissingBackupFails() throws {
        let setup = try makeSetup()
        defer { try? FileManager.default.removeItem(atPath: setup.root) }
        guard case .failure(let error) = setup.service.restore(name: "nope", apply: false) else {
            return XCTFail("unknown backup must fail")
        }
        XCTAssertTrue(error.message.contains("no such backup"))
    }
}