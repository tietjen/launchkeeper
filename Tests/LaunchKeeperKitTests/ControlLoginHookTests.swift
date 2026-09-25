import XCTest
@testable import LaunchKeeperKit

// V0.7.0: loginwindow hooks become switchable. `disable` parks the script
// path under `LaunchKeeperDisabled<kind>` in the same plist, then deletes the
// live key; `enable` mirrors it. Hermetic: a `defaults` twin edits a temp
// plist file, the legacy stage reads temp loginwindow plists.

/// `defaults` twin over real temp plist files (so the scanner and the
/// engine's own read see every change). Handles the sudo seam too.
final class FakeDefaults: CommandRunner {
    var silentDelete = false
    private(set) var log: [String] = []

    private func load(_ domain: String) -> [String: Any] {
        guard let data = FileManager.default.contents(atPath: domain + ".plist"),
              let dict = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        else { return [:] }
        return dict
    }

    private func save(_ dict: [String: Any], _ domain: String) -> Bool {
        guard let data = try? PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
        else { return false }
        return FileManager.default.createFile(atPath: domain + ".plist", contents: data)
    }

    func run(command: String, arguments: [String], timeout: TimeInterval) -> CommandResult {
        log.append(([command] + arguments).joined(separator: " "))
        var args = arguments
        switch command {
        case "/bin/launchctl" where args == ["print", "gui/501"]:
            return CommandResult(exitCode: 0, stdout: "gui/501 = {\nservices = {\n}\n}\n", stderr: "")
        case "/bin/launchctl" where args == ["print-disabled", "gui/501"]:
            return CommandResult(exitCode: 0, stdout: "", stderr: "")
        case "/usr/bin/sudo" where args.first == "defaults":
            args.removeFirst()
        case "/usr/bin/defaults":
            break
        default:
            return CommandResult(exitCode: 127, stdout: "", stderr: "not modeled")
        }
        switch args.first {
        case "read" where args.count == 3:
            guard let value = load(args[1])[args[2]] as? String else {
                return CommandResult(exitCode: 1, stdout: "", stderr: "does not exist")
            }
            return CommandResult(exitCode: 0, stdout: value + "\n", stderr: "")
        case "write" where args.count == 5 && args[3] == "-string":
            var dict = load(args[1])
            dict[args[2]] = args[4]
            return CommandResult(exitCode: save(dict, args[1]) ? 0 : 1, stdout: "", stderr: "")
        case "delete" where args.count == 3:
            guard !silentDelete else { return CommandResult(exitCode: 0, stdout: "", stderr: "") }
            var dict = load(args[1])
            guard dict.removeValue(forKey: args[2]) != nil else {
                return CommandResult(exitCode: 1, stdout: "", stderr: "not found")
            }
            return CommandResult(exitCode: save(dict, args[1]) ? 0 : 1, stdout: "", stderr: "")
        default:
            return CommandResult(exitCode: 64, stdout: "", stderr: "usage")
        }
    }

    var writes: [String] { log.filter { $0.contains(" write ") || $0.contains(" delete ") } }
}

final class LoginHookControlTests: XCTestCase {
    private let options = ScanOptions(includeUser: true, includeSystem: false, scanBTM: false,
                                      scanSignatures: false, scanExtensions: false,
                                      scanSystemExtensions: false, scanHelpers: false, scanScheduled: false,
                                      scanLegacy: true, scanPlugins: false, scanShell: false, scanNetwork: false,
                                      scanReceipts: false)

    private struct Setup {
        var home: String
        var userPlist: String
        var systemPlist: String
        var legacy: LegacyScanner
    }

    private func setup(user: [String: Any], system: [String: Any] = [:]) throws -> Setup {
        let home = FileManager.default.temporaryDirectory
            .appendingPathComponent("lk-hook-\(UUID().uuidString)", isDirectory: true).path
        try FileManager.default.createDirectory(atPath: home + "/Library/LaunchAgents", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: home + "/Library/Preferences", withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: home + "/sys", withIntermediateDirectories: true)
        let userPlist = home + "/Library/Preferences/com.apple.loginwindow.plist"
        let systemPlist = home + "/sys/com.apple.loginwindow.plist"
        for (path, dict) in [(userPlist, user), (systemPlist, system)] {
            let data = try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
            FileManager.default.createFile(atPath: path, contents: data)
        }
        let legacy = LegacyScanner(home: home, loginwindowPlists: [(userPlist, .user)],
                                   startupItemsDirectories: [], legacyFiles: [],
                                   emondRulesDirectory: home + "/none")
        return Setup(home: home, userPlist: userPlist, systemPlist: systemPlist, legacy: legacy)
    }

    private func engine(_ runner: CommandRunner, _ setup: Setup) -> RemediationEngine {
        RemediationEngine(environment: RemediationEnvironment(runner: runner, home: setup.home, uid: 501,
                                                              configSnapshotsRoot: setup.home + "/snapshots",
                                                              legacyScanner: setup.legacy),
                          audit: AuditLog(directory: setup.home + "/logs"))
    }

    private func read(_ path: String) -> [String: Any] {
        guard let data = FileManager.default.contents(atPath: path),
              let dict = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any]
        else { return [:] }
        return dict
    }

    func testDryRunPlansParkThenDeleteAndWritesNothing() throws {
        let s = try setup(user: ["LoginHook": "/Users/alice/hook.sh", "lastUser": "loggedIn"])
        defer { try? FileManager.default.removeItem(atPath: s.home) }
        let defaults = FakeDefaults()
        let result = engine(defaults, s).run(operation: .disable, target: "hook:LoginHook:user", apply: false,
                                             scanOptions: options)
        XCTAssertEqual(result.status, .planned, "\(result.messages)")
        XCTAssertEqual(result.target, "loginwindow:user:LoginHook")
        let domain = String(s.userPlist.dropLast(6))
        XCTAssertEqual(result.plan.map(\.display), [
            "/usr/bin/defaults write \(domain) LaunchKeeperDisabledLoginHook -string /Users/alice/hook.sh",
            "/usr/bin/defaults delete \(domain) LoginHook",
        ], "park first, delete second — no failure can lose the script path")
        XCTAssertTrue(defaults.writes.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: s.home + "/snapshots"))
    }

    func testApplyParksVerifiesAndEnablePutsItBack() throws {
        let s = try setup(user: ["LoginHook": "/Users/alice/hook.sh", "lastUser": "loggedIn"])
        defer { try? FileManager.default.removeItem(atPath: s.home) }
        let defaults = FakeDefaults()
        let result = engine(defaults, s).run(operation: .disable, target: "hook:LoginHook:user", apply: true,
                                             scanOptions: options)
        XCTAssertEqual(result.status, .appliedOk, "\(result.messages)")
        var dict = read(s.userPlist)
        XCTAssertNil(dict["LoginHook"])
        XCTAssertEqual(dict["LaunchKeeperDisabledLoginHook"] as? String, "/Users/alice/hook.sh")
        XCTAssertEqual(dict["lastUser"] as? String, "loggedIn", "other keys untouched")
        XCTAssertTrue(result.undoHint?.contains("defaults import") == true, result.undoHint ?? "-")

        let snapshots = try FileManager.default.contentsOfDirectory(atPath: s.home + "/snapshots")
        XCTAssertEqual(snapshots.count, 1)
        let saved = read(s.home + "/snapshots/\(snapshots[0])/com.apple.loginwindow.plist")
        XCTAssertEqual(saved["LoginHook"] as? String, "/Users/alice/hook.sh", "the snapshot is the state BEFORE")

        // The parked hook is still in the inventory, disabled.
        let report = ScanCoordinator(environment: ScanEnvironment(runner: defaults, home: s.home, uid: 501,
                                                                  legacyScanner: s.legacy)).perform(options: options)
        let parked = try XCTUnwrap(report.items.first { $0.key == "hook:LoginHook:user" })
        XCTAssertFalse(parked.enabled)
        XCTAssertEqual(parked.control?.level, .reversible)

        let back = engine(defaults, s).run(operation: .enable, target: "hook:LoginHook:user", apply: true,
                                           scanOptions: options)
        XCTAssertEqual(back.status, .appliedOk, "\(back.messages)")
        dict = read(s.userPlist)
        XCTAssertEqual(dict["LoginHook"] as? String, "/Users/alice/hook.sh")
        XCTAssertNil(dict["LaunchKeeperDisabledLoginHook"])
    }

    func testSilentDeleteIsCaughtByVerification() throws {
        let s = try setup(user: ["LoginHook": "/Users/alice/hook.sh"])
        defer { try? FileManager.default.removeItem(atPath: s.home) }
        let defaults = FakeDefaults()
        defaults.silentDelete = true
        let result = engine(defaults, s).run(operation: .disable, target: "hook:LoginHook:user", apply: true,
                                             scanOptions: options)
        guard case .appliedFailed(let detail) = result.status else {
            return XCTFail("exit 0 without effect must fail verification, got \(result.status)")
        }
        XCTAssertTrue(detail.contains("still set"), detail)
    }

    func testAnExistingParkedValueIsNeverOverwritten() throws {
        // Live AND parked: the scanner keeps the live one (with a warning),
        // the engine refuses to park over the old value.
        let s = try setup(user: ["LoginHook": "/Users/alice/new.sh", "LaunchKeeperDisabledLoginHook": "/Users/alice/old.sh"])
        defer { try? FileManager.default.removeItem(atPath: s.home) }
        let defaults = FakeDefaults()
        let result = engine(defaults, s).run(operation: .disable, target: "hook:LoginHook:user", apply: true,
                                             scanOptions: options)
        guard case .refused(let reason) = result.status else { return XCTFail("\(result.status)") }
        XCTAssertTrue(reason.contains("never overwrites"), reason)
        XCTAssertTrue(defaults.writes.isEmpty)
        XCTAssertTrue(s.legacy.scan().warnings.contains { $0.contains("the live one counts") })
    }

    func testSystemHookPlansThroughSudoAndOnlyTheRealSystemPlistQualifies() {
        var item = BackgroundItem(key: "hook:LogoutHook:system", displayName: "LogoutHook → /x", type: .loginHook,
                                  path: "/Library/Preferences/com.apple.loginwindow.plist", executable: "/x",
                                  owner: "root", uid: 0, domain: .system, category: .legacy)
        item.metadata["hook-kind"] = "LogoutHook"
        XCTAssertEqual(RemediationGate.evaluate(operation: .disable, item: item), .allowed)
        XCTAssertEqual(ControlAnalyzer(launchDirs: []).evaluate(item).mechanism, .loginHook)

        var elsewhere = item
        elsewhere.path = "/tmp/Library/Preferences/com.apple.loginwindow.plist"
        XCTAssertNotEqual(RemediationGate.evaluate(operation: .disable, item: elsewhere), .allowed,
                          "a system-domain hook must come from /Library/Preferences exactly")
        var detour = item
        detour.domain = .user
        detour.path = "/Users/alice/../../Library/Preferences/com.apple.loginwindow.plist"
        XCTAssertNotEqual(RemediationGate.evaluate(operation: .disable, item: detour), .allowed)
        XCTAssertNotEqual(RemediationGate.evaluate(operation: .remove, item: item), .allowed)
    }

    func testSystemHookRunsTheSudoSeam() throws {
        // The system plist lives in a temp dir here; the item claims system
        // domain, so every write goes through `sudo defaults`.
        let s = try setup(user: [:], system: ["LoginHook": "/usr/local/bin/hook.sh"])
        defer { try? FileManager.default.removeItem(atPath: s.home) }
        var item = BackgroundItem(key: "hook:LoginHook:system", displayName: "LoginHook", type: .loginHook,
                                  path: s.systemPlist, executable: "/usr/local/bin/hook.sh",
                                  owner: "root", uid: 0, domain: .system, category: .legacy)
        item.metadata["hook-kind"] = "LoginHook"
        let defaults = FakeDefaults()
        let env = RemediationEnvironment(runner: defaults, home: s.home, uid: 501,
                                         configSnapshotsRoot: s.home + "/snapshots")
        let prepared = try RemediationEngine(environment: env, audit: AuditLog(directory: s.home + "/logs"))
            .prepareLoginHook(operation: .disable, item: item, apply: true, undo: nil).get()
        XCTAssertEqual(prepared.plan.map(\.command), ["/usr/bin/sudo", "/usr/bin/sudo"])
        XCTAssertTrue(prepared.undo?.contains("sudo defaults import") == true, prepared.undo ?? "-")
        let outcome = RemediationExecutor(runner: defaults, uid: 501)
            .execute(prepared.plan, operation: .disable, item: item, expectation: prepared.expectation)
        XCTAssertEqual(outcome.status, .appliedOk, "\(outcome.messages)")
        XCTAssertEqual(read(s.systemPlist)["LaunchKeeperDisabledLoginHook"] as? String, "/usr/local/bin/hook.sh")
    }
}
