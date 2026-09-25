import XCTest
@testable import LaunchKeeperKit

// V0.7.0: existing Application Firewall rules flip between block (disable)
// and allow (enable) — socketfilterfw via the sudo seam, verified through
// `--listapps`. Rules are never added or removed; Apple binaries stay
// read-only. Hermetic: a stateful socketfilterfw twin.

final class FakeFirewall: CommandRunner {
    var rules: [(path: String, action: String)]
    var enabled = true
    var silent = false
    private(set) var log: [String] = []
    private let fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"

    init(_ rules: [(path: String, action: String)]) { self.rules = rules }

    private func listapps() -> String {
        var out = "Total number of apps = \(rules.count) \n"
        for (index, rule) in rules.enumerated() {
            out += "\(index + 1) : \(rule.path) \n"
            out += "             (\(rule.action == "block" ? "Block" : "Allow") incoming connections)\n"
        }
        return out
    }

    func run(command: String, arguments: [String], timeout: TimeInterval) -> CommandResult {
        log.append(([command] + arguments).joined(separator: " "))
        var args = arguments
        var command = command
        if command == "/usr/bin/sudo", let first = args.first {
            command = first
            args.removeFirst()
        }
        switch (command, args) {
        case ("/bin/launchctl", ["print", "gui/501"]):
            return CommandResult(exitCode: 0, stdout: "gui/501 = {\nservices = {\n}\n}\n", stderr: "")
        case ("/bin/launchctl", ["print-disabled", "gui/501"]):
            return CommandResult(exitCode: 0, stdout: "", stderr: "")
        case ("/usr/sbin/lsof", _):
            return CommandResult(exitCode: 1, stdout: "", stderr: "")
        case (fw, ["--getglobalstate"]):
            return CommandResult(exitCode: 0, stdout: enabled ? "Firewall is enabled. (State = 1)\n"
                                                              : "Firewall is disabled. (State = 0)\n", stderr: "")
        case (fw, ["--listapps"]):
            return CommandResult(exitCode: 0, stdout: listapps(), stderr: "")
        case (fw, let a) where a.count == 2 && (a[0] == "--blockapp" || a[0] == "--unblockapp"):
            guard !silent else { return CommandResult(exitCode: 0, stdout: "", stderr: "") }
            for index in rules.indices where rules[index].path == a[1] {
                rules[index].action = a[0] == "--blockapp" ? "block" : "allow"
            }
            return CommandResult(exitCode: 0, stdout: "", stderr: "")
        default:
            return CommandResult(exitCode: 127, stdout: "", stderr: "not modeled")
        }
    }

    var mutations: [String] { log.filter { $0.contains("blockapp") } }
}

final class FirewallControlTests: XCTestCase {
    private let options = ScanOptions(includeUser: true, includeSystem: false, scanBTM: false,
                                      scanSignatures: false, scanExtensions: false,
                                      scanSystemExtensions: false, scanHelpers: false, scanScheduled: false,
                                      scanLegacy: false, scanPlugins: false, scanShell: false, scanNetwork: true,
                                      scanReceipts: false)

    private func home() throws -> String {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("lk-fw-\(UUID().uuidString)", isDirectory: true).path
        try FileManager.default.createDirectory(atPath: dir + "/Library/LaunchAgents", withIntermediateDirectories: true)
        return dir
    }

    private func engine(_ runner: CommandRunner, home: String) -> RemediationEngine {
        RemediationEngine(environment: RemediationEnvironment(runner: runner, home: home, uid: 501),
                          audit: AuditLog(directory: home + "/logs"))
    }

    private func fake() -> FakeFirewall {
        FakeFirewall([("/usr/libexec/remoted", "allow"), ("/Library/Vendor/bin/vendord", "allow")])
    }

    func testDryRunPlansASudoBlockAndRunsNothing() throws {
        let home = try home()
        defer { try? FileManager.default.removeItem(atPath: home) }
        let fw = fake()
        let result = engine(fw, home: home).run(operation: .disable, target: "vendord", apply: false,
                                                scanOptions: options)
        XCTAssertEqual(result.status, .planned, "\(result.messages)")
        XCTAssertEqual(result.target, "firewall:/Library/Vendor/bin/vendord")
        XCTAssertEqual(result.plan.map(\.display),
                       ["/usr/bin/sudo /usr/libexec/ApplicationFirewall/socketfilterfw --blockapp /Library/Vendor/bin/vendord"])
        XCTAssertEqual(result.undoHint, "launchkeeper enable /Library/Vendor/bin/vendord")
        XCTAssertTrue(fw.mutations.isEmpty)
    }

    func testApplyBlocksVerifiesAndEnableAllowsAgain() throws {
        let home = try home()
        defer { try? FileManager.default.removeItem(atPath: home) }
        let fw = fake()
        let result = engine(fw, home: home).run(operation: .disable, target: "vendord", apply: true,
                                                scanOptions: options)
        XCTAssertEqual(result.status, .appliedOk, "\(result.messages)")
        XCTAssertEqual(fw.rules.last?.action, "block")
        XCTAssertTrue(fw.log.contains("/usr/libexec/ApplicationFirewall/socketfilterfw --listapps"))

        let back = engine(fw, home: home).run(operation: .enable, target: "/Library/Vendor/bin/vendord", apply: true,
                                              scanOptions: options)
        XCTAssertEqual(back.status, .appliedOk, "\(back.messages)")
        XCTAssertEqual(fw.rules.last?.action, "allow")
    }

    func testSilentFlipIsCaughtByVerification() throws {
        let home = try home()
        defer { try? FileManager.default.removeItem(atPath: home) }
        let fw = fake()
        fw.silent = true
        let result = engine(fw, home: home).run(operation: .disable, target: "vendord", apply: true,
                                                scanOptions: options)
        guard case .appliedFailed(let detail) = result.status else { return XCTFail("\(result.status)") }
        XCTAssertTrue(detail.contains("still says allow"), detail)
    }

    func testFirewallOffIsSaidOutLoud() throws {
        let home = try home()
        defer { try? FileManager.default.removeItem(atPath: home) }
        let fw = fake()
        fw.enabled = false
        let result = engine(fw, home: home).run(operation: .disable, target: "vendord", apply: false,
                                                scanOptions: options)
        XCTAssertTrue(result.messages.contains { $0.contains("Application Firewall is OFF") }, "\(result.messages)")
    }

    func testAppleRulesAndRemoveAreRefused() throws {
        let home = try home()
        defer { try? FileManager.default.removeItem(atPath: home) }
        let fw = fake()
        let apple = engine(fw, home: home).run(operation: .disable, target: "remoted", apply: true,
                                               scanOptions: options)
        guard case .refused(let reason) = apple.status else { return XCTFail("\(apple.status)") }
        XCTAssertTrue(reason.contains("Apple platform"), reason)
        let remove = engine(fw, home: home).run(operation: .remove, target: "vendord", apply: true,
                                                scanOptions: options)
        guard case .refused = remove.status else { return XCTFail("\(remove.status)") }
        XCTAssertTrue(fw.mutations.isEmpty)
    }

    func testListenerWithoutARuleStaysDisplayOnly() {
        var listener = BackgroundItem(key: "net:/opt/x/bin/server", displayName: "server (pid 1)", type: .listener,
                                      path: "/opt/x/bin/server", executable: "/opt/x/bin/server", category: .network)
        XCTAssertNil(listener.controlMechanism)
        XCTAssertEqual(ControlAnalyzer(launchDirs: []).evaluate(listener).level, .displayOnly)
        listener.metadata["firewall"] = "allow incoming connections"
        listener.metadata["firewall-path"] = "/opt/x/bin/server"
        XCTAssertEqual(listener.controlMechanism, .firewall)
        let control = ControlAnalyzer(launchDirs: []).evaluate(listener)
        XCTAssertEqual(control.level, .reversible)
        XCTAssertEqual(control.mechanism, .firewall)
    }
}
