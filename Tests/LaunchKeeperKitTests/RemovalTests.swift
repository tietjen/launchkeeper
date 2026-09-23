import XCTest
@testable import LaunchKeeperKit

// V0.3 remove tests. The deletion path is tested HERMETICALLY: every file
// operation happens inside a temp tree, every launchctl read/write against
// FakeLaunchd. Two rules drive the suite:
//   1. The four gate locks must refuse everything that is not a provably
//      orphaned launch .plist inside the launch dirs — refused BEFORE any
//      command runs, and audited anyway.
//   2. An apply-run that cannot produce a backup snapshot must delete
//      nothing. Exit codes prove nothing: the verify-after-mutate read of the
//      FILE SYSTEM is what catches a `rm` that exits 0 having deleted nothing.

/// Composite double: launchctl conversations delegate to FakeLaunchd; `rm`
/// answers on BOTH seams (plain run + interactive) by really deleting inside
/// the temp tree — because file-system verification reads the real world.
final class RemovalRunner: CommandRunner {
    let launchd: FakeLaunchd
    var fm = FileManager.default
    /// Silent-failure switch: `rm` exits 0 but removes nothing.
    var silentRemove = false
    private(set) var log: [String] = []
    private(set) var interactiveLog: [String] = []

    init(launchd: FakeLaunchd = FakeLaunchd()) {
        self.launchd = launchd
    }

    /// Matches "/bin/rm -- <path>" and "/usr/bin/sudo rm -- <path>".
    private func rmTarget(_ command: String, _ arguments: [String]) -> String? {
        if command == "/bin/rm", arguments.count == 2, arguments[0] == "--" {
            return arguments[1]
        }
        if command == "/usr/bin/sudo", arguments.count == 3,
           arguments[0] == "rm", arguments[1] == "--" {
            return arguments[2]
        }
        return nil
    }

    private func delete(_ path: String) -> Bool {
        if silentRemove { return true }
        guard fm.fileExists(atPath: path) else { return false }
        return (try? fm.removeItem(atPath: path)) != nil
    }

    func run(command: String, arguments: [String], timeout: TimeInterval) -> CommandResult {
        let key = ([command] + arguments).joined(separator: " ")
        log.append(key)
        if let path = rmTarget(command, arguments) {
            return delete(path)
                ? CommandResult(exitCode: 0, stdout: "", stderr: "")
                : CommandResult(exitCode: 1, stdout: "", stderr: "cannot remove \(path)")
        }
        return launchd.run(command: command, arguments: arguments, timeout: timeout)
    }

    func runInteractive(command: String, arguments: [String], timeout: TimeInterval) -> Int32 {
        let key = ([command] + arguments).joined(separator: " ")
        interactiveLog.append(key)
        if let path = rmTarget(command, arguments) {
            return delete(path) ? 0 : 1
        }
        return launchd.runInteractive(command: command, arguments: arguments, timeout: timeout)
    }
}

private func plistBody(label: String, programArguments: [String]) -> String {
    let args = programArguments.map { "<string>\($0)</string>" }.joined()
    return """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0">
    <dict>
      <key>Label</key><string>\(label)</string>
      <key>ProgramArguments</key><array>\(args)</array>
      <key>RunAtLoad</key><true/>
    </dict>
    </plist>
    """
}

/// Temp home whose Library/LaunchAgents holds the given fixture plists.
/// `ghost` labels run a missing script argument (hard orphan signal); the
/// calm fixture runs /bin/sleep (everything present → NOT orphaned).
private func makeRemoveFixture(home: String, entries: [(name: String, args: [String])]) throws {
    let fm = FileManager.default
    let agents = home + "/Library/LaunchAgents"
    try fm.createDirectory(atPath: agents, withIntermediateDirectories: true)
    for entry in entries {
        try Data(plistBody(label: entry.name, programArguments: entry.args)
            .utf8).write(to: URL(fileURLWithPath: agents + "/\(entry.name).plist"))
    }
}

private func tempRoot(_ tag: String) -> String {
    FileManager.default.temporaryDirectory
        .appendingPathComponent("launchkeeper-removal-tests-\(tag)-\(UUID().uuidString)", isDirectory: true).path
}

private let ghostArgs = ["/bin/bash", "/nonexistent-xyz-dir/gone.sh"]
private let calmArgs = ["/bin/sleep", "3600"]

// MARK: - Gate: the four locks

final class RemovalGateTests: XCTestCase {
    private let dirs = ["/Users/test/Library/LaunchAgents"]

    private func item(path: String?, orphaned: Bool = true,
                      domain: ItemDomain = .user) -> BackgroundItem {
        BackgroundItem(key: path ?? "k", displayName: path ?? "k",
                       path: path, label: "de.test.thing",
                       domain: domain, orphaned: orphaned)
    }

    func testOnlyPlistShapePassesLockOne() {
        // No backing file at all:
        guard case .denied(let noFile) =
                RemediationGate.evaluateRemove(item: item(path: nil), launchDirs: dirs) else {
            return XCTFail("no path must be refused")
        }
        XCTAssertTrue(noFile.contains("no backing launch .plist"))
        // Inside the dir but not a .plist:
        guard case .denied(let notPlist) =
                RemediationGate.evaluateRemove(
                    item: item(path: "/Users/test/Library/LaunchAgents/helper"), launchDirs: dirs) else {
            return XCTFail("non-plist must be refused even inside the launch dir")
        }
        XCTAssertTrue(notPlist.contains("no backing launch .plist"))
    }

    func testOutsideAllowlistRefused() {
        // Correct shape, wrong directory: /tmp has orphan plists in real life too.
        guard case .denied(let reason) =
                RemediationGate.evaluateRemove(
                    item: item(path: "/private/tmp/orphan.plist"), launchDirs: dirs) else {
            return XCTFail("outside the allowlist must be refused")
        }
        XCTAssertTrue(reason.contains("outside the allowlist"), "actual: \(reason)")

        // Subdir trick: exact parent must match, not just the prefix.
        guard case .denied(let subdir) =
                RemediationGate.evaluateRemove(
                    item: item(path: "/Users/test/Library/LaunchAgents/nested/x.plist"), launchDirs: dirs) else {
            return XCTFail("a subdirectory is not the launch dir")
        }
        XCTAssertTrue(subdir.contains("outside the allowlist"))
    }

    func testOrphanPlistInsideAllowlistAllowed() {
        let decision = RemediationGate.evaluateRemove(
            item: item(path: "/Users/test/Library/LaunchAgents/de.test.thing.plist"), launchDirs: dirs)
        XCTAssertEqual(decision, .allowed)
    }

    func testNonOrphanRefused() {
        // The lock that keeps launchkeeper out of rm-wrapper territory: a working
        // component leaves via disable, never via deletion.
        guard case .denied(let reason) =
                RemediationGate.evaluateRemove(
                    item: item(path: "/Users/test/Library/LaunchAgents/de.test.thing.plist",
                               orphaned: false), launchDirs: dirs) else {
            return XCTFail("non-orphaned must be refused")
        }
        XCTAssertTrue(reason.contains("not orphaned"), "actual: \(reason)")
    }

    func testSymlinkEscapingAllowlistRefused() throws {
        let root = tempRoot("symlink")
        defer { try? FileManager.default.removeItem(atPath: root) }
        let fm = FileManager.default
        let agents = root + "/LaunchAgents"
        let elsewhere = root + "/elsewhere"
        try fm.createDirectory(atPath: agents, withIntermediateDirectories: true)
        try fm.createDirectory(atPath: elsewhere, withIntermediateDirectories: true)
        let victim = elsewhere + "/payload.plist"
        try Data("<plist/>".utf8).write(to: URL(fileURLWithPath: victim))
        try fm.createSymbolicLink(atPath: agents + "/de.linked.plist", withDestinationPath: victim)

        // The LINK ends inside the launch dir, its TARGET does not: deleting
        // through it would reach outside the allowlist.
        guard case .denied(let reason) =
                RemediationGate.evaluateRemove(
                    item: item(path: agents + "/de.linked.plist"), launchDirs: [agents]) else {
            return XCTFail("symlink escape must be refused")
        }
        XCTAssertTrue(reason.contains("symlink"), "actual: \(reason)")
    }

    func testSymlinkWithinLaunchDirAllowed() throws {
        let root = tempRoot("symlink-ok")
        defer { try? FileManager.default.removeItem(atPath: root) }
        let fm = FileManager.default
        let agents = root + "/LaunchAgents"
        try fm.createDirectory(atPath: agents, withIntermediateDirectories: true)
        try Data("<plist/>".utf8).write(to: URL(fileURLWithPath: agents + "/de.real.plist"))
        try fm.createSymbolicLink(atPath: agents + "/de.linked.plist",
                                  withDestinationPath: agents + "/de.real.plist")
        let decision = RemediationGate.evaluateRemove(
            item: item(path: agents + "/de.linked.plist"), launchDirs: [agents])
        XCTAssertEqual(decision, .allowed,
                       "a link that stays inside the launch dir keeps the operation inside the allowlist")
    }
}

// MARK: - Planner: argv shape for remove

final class RemovalPlannerTests: XCTestCase {
    private func user(loaded: Bool, enabled: Bool = true) -> BackgroundItem {
        BackgroundItem(key: "com.example.script", displayName: "com.example.script",
                       path: "/Users/test/Library/LaunchAgents/com.example.script.plist",
                       label: "com.example.script",
                       executable: "/bin/bash", domain: .user,
                       loaded: loaded, enabled: enabled, orphaned: true)
    }

    func testUnloadedRemoveIsSingleArgvRm() {
        let plan = RemediationPlanner.plan(operation: .remove, item: user(loaded: false), uid: 501)
        XCTAssertEqual(plan.map(\.display), [
            "/bin/rm -- /Users/test/Library/LaunchAgents/com.example.script.plist",
        ], "argv arrays, `--` before the path, never a shell")
    }

    func testLoadedRemoveUnloadsBeforeDeleting() {
        let plan = RemediationPlanner.plan(operation: .remove, item: user(loaded: true), uid: 501)
        XCTAssertEqual(plan.map(\.display), [
            "/bin/launchctl bootout gui/501/com.example.script",
            "/bin/rm -- /Users/test/Library/LaunchAgents/com.example.script.plist",
        ], "the file is never pulled out from under a loaded job")
    }

    func testDisabledItemDropsStaleOverrideAfterDelete() {
        let plan = RemediationPlanner.plan(operation: .remove,
                                           item: user(loaded: true, enabled: false), uid: 501)
        XCTAssertEqual(plan.map(\.display), [
            "/bin/launchctl bootout gui/501/com.example.script",
            "/bin/rm -- /Users/test/Library/LaunchAgents/com.example.script.plist",
            "/bin/launchctl enable gui/501/com.example.script",
        ], "no NEW disable override is created — only a pre-existing one is dropped")
    }

    func testSystemDomainRemoveGoesThroughSudoOnly() {
        let daemon = BackgroundItem(key: "de.ghost.helper", displayName: "de.ghost.helper",
                                    path: "/Library/LaunchDaemons/de.ghost.helper.plist",
                                    label: "de.ghost.helper",
                                    executable: "/usr/local/bin/helper",
                                    domain: .system, loaded: true, enabled: false, orphaned: true)
        let plan = RemediationPlanner.plan(operation: .remove, item: daemon, uid: 501)
        XCTAssertEqual(plan.map(\.display), [
            "/usr/bin/sudo launchctl bootout system/de.ghost.helper",
            "/usr/bin/sudo rm -- /Library/LaunchDaemons/de.ghost.helper.plist",
            "/usr/bin/sudo launchctl enable system/de.ghost.helper",
        ], "system domain: every step rides the single interactive sudo seam")
    }

    func testNoLabelMeansNoPlan() {
        let item = BackgroundItem(key: "no-label", displayName: "no-label",
                                  path: "/tmp/x.plist", domain: .user, orphaned: true)
        XCTAssertTrue(RemediationPlanner.plan(operation: .remove, item: item, uid: 501).isEmpty)
    }

    func testUndoHintPointsAtBackupAndReenable() {
        var item = user(loaded: false)
        item.id = "07"   // ids are positional per run — the hint must NOT use it
        let hint = RemediationPlanner.undoHint(for: .remove, item: item)
        XCTAssertEqual(hint, "launchkeeper restore <pre-remove backup> && launchkeeper enable com.example.script --now",
                       "for remove the undo hint IS the recovery path — "
                       + "it must address the entry by its stable label")
    }
}

// MARK: - Executor: deletion + verify-after-mutate

final class RemovalExecutorTests: XCTestCase {
    private func ghostItem(path: String, loaded: Bool, enabled: Bool = true,
                           domain: ItemDomain = .user) -> BackgroundItem {
        BackgroundItem(key: "de.launchkeeper.ghost", displayName: "de.launchkeeper.ghost",
                       path: path, label: "de.launchkeeper.ghost",
                       executable: "/bin/bash", domain: domain,
                       loaded: loaded, enabled: enabled, orphaned: true)
    }

    private func writeFile(_ path: String) throws {
        try FileManager.default.createDirectory(atPath: (path as NSString).deletingLastPathComponent,
                                                withIntermediateDirectories: true)
        try Data(plistBody(label: "de.launchkeeper.ghost", programArguments: ghostArgs)
            .utf8).write(to: URL(fileURLWithPath: path))
    }

    func testHappyPathDeletesFileAndClearsState() throws {
        let root = tempRoot("exec-happy")
        defer { try? FileManager.default.removeItem(atPath: root) }
        let plist = root + "/LaunchAgents/de.launchkeeper.ghost.plist"
        try writeFile(plist)

        let runner = RemovalRunner()
        runner.launchd.services["de.launchkeeper.ghost"] = 999
        runner.launchd.disabled.insert("de.launchkeeper.ghost")
        let executor = RemediationExecutor(runner: runner, uid: 501)
        let item = ghostItem(path: plist, loaded: true, enabled: false)

        let outcome = executor.execute(
            RemediationPlanner.plan(operation: .remove, item: item, uid: 501),
            operation: .remove, item: item)

        XCTAssertEqual(outcome.status, .appliedOk, "actual: \(outcome.status) \(outcome.messages)")
        XCTAssertFalse(FileManager.default.fileExists(atPath: plist), "file must be really gone")
        XCTAssertFalse(runner.launchd.services.keys.contains("de.launchkeeper.ghost"))
        XCTAssertFalse(runner.launchd.disabled.contains("de.launchkeeper.ghost"),
                       "stale override must be dropped after removal")
        XCTAssertFalse(runner.log.contains { $0.contains("sudo") },
                       "user domain never goes through sudo: \(runner.log)")
    }

    func testSilentRmCaughtByFileSystemVerification() throws {
        // Every command exits 0, `rm` included, but nothing is deleted.
        // Exit codes prove nothing — this is the case the spec's
        // "silent fake" test exists for.
        let root = tempRoot("exec-silent")
        defer { try? FileManager.default.removeItem(atPath: root) }
        let plist = root + "/LaunchAgents/de.launchkeeper.ghost.plist"
        try writeFile(plist)

        let runner = RemovalRunner()
        runner.silentRemove = true
        let executor = RemediationExecutor(runner: runner, uid: 501)
        let item = ghostItem(path: plist, loaded: false)
        let outcome = executor.execute(
            RemediationPlanner.plan(operation: .remove, item: item, uid: 501),
            operation: .remove, item: item)
        guard case .appliedFailed(let detail) = outcome.status else {
            return XCTFail("expected appliedFailed, got \(outcome.status)")
        }
        XCTAssertTrue(detail.contains("file still exists"), "actual: \(detail)")
        XCTAssertTrue(FileManager.default.fileExists(atPath: plist),
                      "verification must fail BEFORE anything believes the delete happened")
    }

    func testUnmodeledRmFailsCleanly() throws {
        // A runner that cannot answer `rm` at all (exit 127) must stop the
        // plan at the rm step — the executor may not improvise a substitute.
        let fake = FakeLaunchd()
        let executor = RemediationExecutor(runner: fake, uid: 501)
        let item = ghostItem(path: "/Users/test/Library/LaunchAgents/de.launchkeeper.ghost.plist",
                             loaded: false)
        let outcome = executor.execute(
            RemediationPlanner.plan(operation: .remove, item: item, uid: 501),
            operation: .remove, item: item)
        XCTAssertEqual(outcome.status, .appliedFailed("exit 127"))
        XCTAssertEqual(outcome.executed.count, 1)
    }

    func testSystemDomainRemoveUsesInteractiveSudoSeam() throws {
        let root = tempRoot("exec-system")
        defer { try? FileManager.default.removeItem(atPath: root) }
        let plist = root + "/FakeDaemons/de.launchkeeper.ghost.plist"
        try writeFile(plist)

        let runner = RemovalRunner()
        runner.launchd.services["de.launchkeeper.ghost"] = 4242
        let executor = RemediationExecutor(runner: runner, uid: 501)
        let item = ghostItem(path: plist, loaded: true, domain: .system)
        // The temp FakeDaemons dir stands in for a root-owned launch dir:
        // since V0.4.2 the FILE's directory decides whether rm needs sudo.
        let outcome = executor.execute(
            RemediationPlanner.plan(operation: .remove, item: item, uid: 501,
                                    systemDirPrefixes: [root + "/FakeDaemons"]),
            operation: .remove, item: item)

        XCTAssertEqual(outcome.status, .appliedOk, "actual: \(outcome.status) \(outcome.messages)")
        XCTAssertTrue(runner.interactiveLog.contains("/usr/bin/sudo rm -- \(plist)"),
                      "delete must ride the interactive seam: \(runner.interactiveLog)")
        XCTAssertTrue(runner.interactiveLog.contains("/usr/bin/sudo launchctl bootout system/de.launchkeeper.ghost"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: plist))
    }
}

// MARK: - Engine end-to-end: scan -> resolve -> gate -> backup -> plan -> verify

final class RemovalEngineTests: XCTestCase {
    private let userOnly = ScanOptions(includeUser: true, includeSystem: false,
                                       scanBTM: false, scanSignatures: false, scanExtensions: false, scanSystemExtensions: false, scanHelpers: false, scanScheduled: false, scanLegacy: false, scanPlugins: false, scanShell: false, scanNetwork: false, scanReceipts: false)

    private struct Setup {
        var root: String
        var home: String
        var agents: String
        var backupsRoot: String
        var engine: RemediationEngine
        var runner: RemovalRunner
    }

    /// Hermetic engine: launch dirs and backups root are temp paths, scan is
    /// user-domain only. The REAL /Library and the real backups dir are never
    /// read or written — the default launchDirs/backupsRoot would point there.
    private func makeSetup(entries: [(name: String, args: [String])],
                           services: [String: Int] = [:],
                           disabled: [String] = []) throws -> Setup {
        let root = tempRoot("engine")
        let home = root + "/home"
        let agents = home + "/Library/LaunchAgents"
        try makeRemoveFixture(home: home, entries: entries)
        let runner = RemovalRunner()
        for (label, pid) in services { runner.launchd.services[label] = pid }
        for label in disabled { runner.launchd.disabled.insert(label) }
        let env = RemediationEnvironment(runner: runner, home: home, uid: 501,
                                         launchDirs: [agents],
                                         backupsRoot: root + "/backups")
        let engine = RemediationEngine(environment: env,
                                       audit: AuditLog(directory: home + "/logs"))
        return Setup(root: root, home: home, agents: agents,
                     backupsRoot: root + "/backups", engine: engine, runner: runner)
    }

    private func snapshotNames(_ setup: Setup) -> [String] {
        (try? FileManager.default.contentsOfDirectory(atPath: setup.backupsRoot)) ?? []
    }

    func testDryRunShowsPlanAndTouchesNothing() throws {
        let setup = try makeSetup(entries: [("de.launchkeeper.ghost", ghostArgs)])
        defer { try? FileManager.default.removeItem(atPath: setup.root) }
        let plist = setup.agents + "/de.launchkeeper.ghost.plist"

        let result = setup.engine.run(operation: .remove, target: "de.launchkeeper.ghost",
                                      apply: false, scanOptions: userOnly)
        XCTAssertEqual(result.status, .planned)
        XCTAssertEqual(result.target, "gui/501/de.launchkeeper.ghost \(plist)",
                       "a deletion audit line must name the exact file")
        XCTAssertEqual(result.plan.map(\.display), ["/bin/rm -- \(plist)"])
        XCTAssertTrue(result.messages.contains { $0.contains("backup would be created first") })
        XCTAssertTrue(FileManager.default.fileExists(atPath: plist), "dry-run deletes nothing")
        XCTAssertFalse(setup.runner.log.contains { $0.contains("rm ") },
                       "dry-run must not even ask for rm: \(setup.runner.log)")
        XCTAssertTrue(snapshotNames(setup).isEmpty, "no snapshot for a dry-run")
        XCTAssertTrue(setup.engine.audit.readAll().contains("planned"))
    }

    func testApplyRequiresBackupAndDeletesOnTopOfIt() throws {
        let setup = try makeSetup(entries: [("de.launchkeeper.ghost", ghostArgs)],
                                  services: ["de.launchkeeper.ghost": 777])
        defer { try? FileManager.default.removeItem(atPath: setup.root) }
        let plist = setup.agents + "/de.launchkeeper.ghost.plist"

        let result = setup.engine.run(operation: .remove, target: "de.launchkeeper.ghost",
                                      apply: true, scanOptions: userOnly)
        XCTAssertEqual(result.status, .appliedOk, "actual: \(result.status) \(result.messages)")
        XCTAssertFalse(FileManager.default.fileExists(atPath: plist))
        XCTAssertFalse(setup.runner.launchd.services.keys.contains("de.launchkeeper.ghost"),
                       "loaded job must be booted out before its file goes")

        let snapshots = snapshotNames(setup)
        XCTAssertEqual(snapshots.count, 1, "exactly one pre-remove snapshot: \(snapshots)")
        let name = try XCTUnwrap(snapshots.first)
        XCTAssertTrue(name.hasPrefix("pre-remove") || name.contains("pre-remove"),
                      "backup label must say what it is for: \(name)")
        XCTAssertTrue(result.undoHint?.contains(name) == true,
                      "undo must name the REAL snapshot: \(result.undoHint ?? "nil")")

        let audit = setup.engine.audit.readAll()
        XCTAssertTrue(audit.contains("backup \(name) pre-remove"), "actual audit:\n\(audit)")
        XCTAssertTrue(audit.contains("remove gui/501/de.launchkeeper.ghost \(plist) applied-ok"),
                      "actual audit:\n\(audit)")
        XCTAssertFalse(setup.runner.log.contains { $0.contains("sudo") })
    }

    func testBackupFailureBlocksTheDelete() throws {
        // backupsRoot is a FILE here — the snapshot can never be written, so
        // the whole removal must refuse. A delete without a restorable
        // snapshot is banned outright.
        let root = tempRoot("nobackup")
        defer { try? FileManager.default.removeItem(atPath: root) }
        let home = root + "/home"
        let agents = home + "/Library/LaunchAgents"
        try makeRemoveFixture(home: home, entries: [("de.launchkeeper.ghost", ghostArgs)])
        try Data("not a directory".utf8)
            .write(to: URL(fileURLWithPath: root + "/blocked"))

        let runner = RemovalRunner()
        let env = RemediationEnvironment(runner: runner, home: home, uid: 501,
                                         launchDirs: [agents],
                                         backupsRoot: root + "/blocked")
        let engine = RemediationEngine(environment: env,
                                       audit: AuditLog(directory: home + "/logs"))
        let plist = agents + "/de.launchkeeper.ghost.plist"

        let result = engine.run(operation: .remove, target: "de.launchkeeper.ghost",
                                apply: true, scanOptions: userOnly)
        guard case .refused(let reason) = result.status, reason.contains("backup failed") else {
            return XCTFail("expected backup-failure refusal, got \(result.status)")
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: plist), "nothing may be deleted")
        XCTAssertFalse(runner.log.contains { $0.contains("rm") },
                       "not even rm was asked: \(runner.log)")
    }

    func testWorkingServiceRefusedEndToEnd() throws {
        // /bin/sleep exists → no orphan signal → remove must refuse: this
        // component would leave via `disable`, not deletion.
        let setup = try makeSetup(entries: [("com.example.calm", calmArgs)],
                                  services: ["com.example.calm": 555])
        defer { try? FileManager.default.removeItem(atPath: setup.root) }
        let plist = setup.agents + "/com.example.calm.plist"

        let result = setup.engine.run(operation: .remove, target: "com.example.calm",
                                      apply: true, scanOptions: userOnly)
        guard case .refused(let reason) = result.status, reason.contains("not orphaned") else {
            return XCTFail("expected non-orphan refusal, got \(result.status)")
        }
        XCTAssertTrue(result.messages.contains { $0.contains("no flag bypasses it") })
        XCTAssertTrue(FileManager.default.fileExists(atPath: plist))
        XCTAssertFalse(setup.runner.log.contains { $0.contains("rm") })
        XCTAssertTrue(setup.engine.audit.readAll().contains("refused(not orphaned"))
    }

    func testAppleLabelRefusedEndToEndForRemove() throws {
        let setup = try makeSetup(entries: [("com.apple.foo", ghostArgs)])
        defer { try? FileManager.default.removeItem(atPath: setup.root) }
        let plist = setup.agents + "/com.apple.foo.plist"

        let result = setup.engine.run(operation: .remove, target: "com.apple.foo",
                                      apply: true, scanOptions: userOnly)
        guard case .refused(let reason) = result.status, reason.contains("com.apple.*") else {
            return XCTFail("expected Apple refusal, got \(result.status)")
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: plist))
        XCTAssertFalse(setup.runner.log.contains { $0.contains("rm") })
    }

    func testRemoveThenRestoreRoundTrip() throws {
        // The undo story must actually work: delete for real, then bring the
        // file back from the pre-remove snapshot.
        let setup = try makeSetup(entries: [("de.launchkeeper.ghost", ghostArgs)])
        defer { try? FileManager.default.removeItem(atPath: setup.root) }
        let plist = setup.agents + "/de.launchkeeper.ghost.plist"
        let original = try Data(contentsOf: URL(fileURLWithPath: plist))

        let result = setup.engine.run(operation: .remove, target: "de.launchkeeper.ghost",
                                      apply: true, scanOptions: userOnly)
        XCTAssertEqual(result.status, .appliedOk, "actual: \(result.status) \(result.messages)")
        XCTAssertFalse(FileManager.default.fileExists(atPath: plist))

        let name = try XCTUnwrap(snapshotNames(setup).first)
        let backupEnv = BackupEnvironment(launchDirs: [setup.agents],
                                          systemDirPrefixes: [],
                                          backupsRoot: setup.backupsRoot,
                                          runner: ScriptedCommandRunner(),
                                          home: setup.home, uid: 501)
        let backups = BackupService(env: backupEnv)
        guard case .success(let dry) = backups.restore(name: name, apply: false) else {
            return XCTFail("restore dry-run failed")
        }
        XCTAssertEqual(dry.wouldRestore, [plist], "the deleted file must be recognized as missing")

        guard case .success(let done) = backups.restore(name: name, apply: true) else {
            return XCTFail("restore apply failed")
        }
        XCTAssertEqual(done.restored, [plist])
        XCTAssertEqual(try Data(contentsOf: URL(fileURLWithPath: plist)), original,
                       "undo must restore the EXACT bytes that were deleted")
    }
}

// MARK: - V0.4.2: a refusal names the step that DOES help

final class FilelessRemoveRefusalTests: XCTestCase {
    private let userOnly = ScanOptions(includeUser: true, includeSystem: false,
                                       scanBTM: false, scanSignatures: false, scanExtensions: false, scanSystemExtensions: false, scanHelpers: false, scanScheduled: false, scanLegacy: false, scanPlugins: false, scanShell: false, scanNetwork: false, scanReceipts: false)

    /// The live case (2026-09-22): an app had been
    /// uninstalled, plist gone, launchd still holds the job for this login
    /// session. `remove` has nothing to delete — and must say what helps.
    func testLoadedJobWithoutFilePointsAtDisable() throws {
        let root = tempRoot("fileless")
        defer { try? FileManager.default.removeItem(atPath: root) }
        let home = root + "/home"
        try makeRemoveFixture(home: home, entries: [])          // empty LaunchAgents
        let runner = RemovalRunner()
        runner.launchd.services["com.example.zombie"] = 0        // loaded, no plist anywhere
        let env = RemediationEnvironment(runner: runner, home: home, uid: 501,
                                         launchDirs: [home + "/Library/LaunchAgents"],
                                         backupsRoot: root + "/backups")
        let engine = RemediationEngine(environment: env, audit: AuditLog(directory: home + "/logs"))

        let result = engine.run(operation: .remove, target: "com.example.zombie",
                                apply: true, scanOptions: userOnly)
        guard case .refused(let reason) = result.status else {
            return XCTFail("expected refusal, got \(result.status)")
        }
        XCTAssertTrue(reason.hasPrefix("no backing file — nothing to remove"), reason)
        XCTAssertTrue(reason.contains("launchkeeper disable com.example.zombie --apply"),
                      "refusal must name the working command: \(reason)")
        XCTAssertTrue(reason.contains("gui/501/com.example.zombie"), reason)
        XCTAssertFalse(runner.log.contains { $0.contains("rm ") }, "nothing may run: \(runner.log)")
        XCTAssertTrue(runner.interactiveLog.isEmpty, "nothing may run: \(runner.interactiveLog)")
    }
}
