import XCTest
@testable import LaunchKeeperKit

// V0.7.0: app extensions become switchable — `disable`/`enable` set the
// user's pluginkit election. Hermetic: a stateful pluginkit twin answers the
// scan (-mAvv), the verification read (-mAvv -i) and the election (-e), so
// the whole path gate → plan → executor → verify runs without the real tool.

/// Stateful pluginkit twin: listings reflect the current elections, `-e`
/// flips them. `silentElection` exits 0 without changing anything — the
/// failure mode only verify-after-mutate can catch.
final class FakePluginKit: CommandRunner {
    struct Registration {
        var identifier: String
        var version: String
        var election: String   // "+", "-", "" …
        var path: String
    }
    var registrations: [Registration]
    var silentElection = false
    var failElection = false
    private(set) var log: [String] = []

    init(_ registrations: [Registration]) { self.registrations = registrations }

    private func listing(_ records: [Registration]) -> String {
        guard !records.isEmpty else { return "  (no matches)\n" }
        var out = ""
        for record in records {
            let tag = record.election.isEmpty ? " " : record.election
            out += "\(tag)    \(record.identifier)(\(record.version))\n"
            out += "\t            Path = \(record.path)\n"
            out += "\t             SDK = com.apple.share-services\n\n"
        }
        return out + " (\(records.count) plug-ins)\n"
    }

    func run(command: String, arguments: [String], timeout: TimeInterval) -> CommandResult {
        log.append(([command] + arguments).joined(separator: " "))
        switch (command, arguments) {
        case ("/bin/launchctl", ["print", "gui/501"]):
            return CommandResult(exitCode: 0, stdout: "gui/501 = {\nservices = {\n}\n}\n", stderr: "")
        case ("/bin/launchctl", ["print-disabled", "gui/501"]):
            return CommandResult(exitCode: 0, stdout: "", stderr: "")
        case ("/usr/bin/pluginkit", ["-mAvv"]):
            return CommandResult(exitCode: 0, stdout: listing(registrations), stderr: "")
        case ("/usr/bin/pluginkit", let args) where args.count == 3 && args[0] == "-mAvv" && args[1] == "-i":
            return CommandResult(exitCode: 0, stdout: listing(registrations.filter { $0.identifier == args[2] }),
                                 stderr: "")
        case ("/usr/bin/pluginkit", let args) where args.count == 4 && args[0] == "-e" && args[2] == "-i":
            if failElection { return CommandResult(exitCode: 1, stdout: "", stderr: "boom") }
            guard !silentElection else { return CommandResult(exitCode: 0, stdout: "", stderr: "") }
            let tag: String
            switch args[1] {
            case "use": tag = "+"
            case "ignore": tag = "-"
            case "default": tag = ""
            default: return CommandResult(exitCode: 64, stdout: "", stderr: "bad election")
            }
            for index in registrations.indices where registrations[index].identifier == args[3] {
                registrations[index].election = tag
            }
            return CommandResult(exitCode: 0, stdout: "", stderr: "")
        default:
            return CommandResult(exitCode: 127, stdout: "", stderr: "not modeled")
        }
    }

    var elections: [String] { log.filter { $0.contains(" -e ") } }
}

private func extensionItem(identifier: String, election: String = "none",
                           path: String = "/Applications/Example.app/Contents/PlugIns/X.appex") -> BackgroundItem {
    var item = BackgroundItem(key: "ext:" + identifier, displayName: identifier, type: .appExtension,
                              path: path, owner: "user", uid: 501, domain: .user, category: .appExtensions)
    item.sources = [SourceEvidence(kind: .pluginkit, detail: "pluginkit: \(identifier)", confidence: .high)]
    item.metadata["ext-identifier"] = identifier
    item.metadata["ext-election"] = election
    return item
}

final class PluginKitControlGateTests: XCTestCase {
    func testThirdPartyExtensionIsSwitchableAppleAndSystemAreNot() {
        let vendor = extensionItem(identifier: "com.example.app.ShareExt")
        XCTAssertEqual(vendor.controlMechanism, .pluginkit)
        XCTAssertEqual(RemediationGate.evaluate(operation: .disable, item: vendor), .allowed)
        XCTAssertEqual(RemediationGate.evaluate(operation: .enable, item: vendor), .allowed)

        let apple = extensionItem(identifier: "com.apple.garageband10.QL")
        guard case .denied(let reason) = RemediationGate.evaluate(operation: .disable, item: apple) else {
            return XCTFail("Apple extensions are read-only")
        }
        XCTAssertTrue(reason.contains("com.apple"), reason)

        let system = extensionItem(identifier: "org.example.embedded",
                                   path: "/System/Library/ExtensionKit/Extensions/x.appex")
        XCTAssertNotEqual(RemediationGate.evaluate(operation: .disable, item: system), .allowed)
    }

    func testRemoveIsNeverAllowedForAnExtension() {
        let vendor = extensionItem(identifier: "com.example.app.ShareExt")
        guard case .denied(let reason) = RemediationGate.evaluate(operation: .remove, item: vendor) else {
            return XCTFail("extensions are elected, never deleted")
        }
        XCTAssertTrue(reason.contains("never deletes"), reason)
    }

    func testIdentifierThatLooksLikeAnOptionIsRefused() {
        XCTAssertNotEqual(RemediationGate.evaluate(operation: .disable, item: extensionItem(identifier: "-a")), .allowed)
        XCTAssertNotEqual(RemediationGate.evaluate(operation: .disable,
                                                   item: extensionItem(identifier: "com.x y")), .allowed)
        var missing = extensionItem(identifier: "com.example.x")
        missing.metadata["ext-identifier"] = nil
        XCTAssertNotEqual(RemediationGate.evaluate(operation: .disable, item: missing), .allowed)
    }

    func testBTMMergedExtensionIsStillSwitchedByItsElection() {
        // QuickLook extensions merge into their BTM record: btmPresent, no
        // plist, no launchd job. Before V0.7 that shape meant "BTM leftover";
        // the pluginkit evidence decides the mechanism first.
        var merged = extensionItem(identifier: "com.example.app.QL")
        merged.key = "btm:QL"
        merged.btmPresent = true
        XCTAssertEqual(RemediationGate.evaluate(operation: .disable, item: merged), .allowed)
    }

    func testControlMatrixSaysReversibleWithMechanism() {
        let analyzer = ControlAnalyzer(launchDirs: [])
        let control = analyzer.evaluate(extensionItem(identifier: "com.example.app.ShareExt"))
        XCTAssertEqual(control.level, .reversible)
        XCTAssertEqual(control.actions, ["disable", "enable"])
        XCTAssertEqual(control.mechanism, .pluginkit)
        let apple = analyzer.evaluate(extensionItem(identifier: "com.apple.x"))
        XCTAssertEqual(apple.level, .displayOnly)
        XCTAssertEqual(apple.mechanism, .pluginkit)
    }
}

final class PluginKitControlPlanTests: XCTestCase {
    func testPlansAreSinglePluginkitElections() {
        let item = extensionItem(identifier: "com.example.app.ShareExt", election: "use")
        XCTAssertEqual(RemediationPlanner.plan(operation: .disable, item: item, uid: 501).map(\.display),
                       ["/usr/bin/pluginkit -e ignore -i com.example.app.ShareExt"])
        XCTAssertEqual(RemediationPlanner.plan(operation: .enable, item: item, uid: 501).map(\.display),
                       ["/usr/bin/pluginkit -e use -i com.example.app.ShareExt"])
        XCTAssertEqual(RemediationPlanner.displayTarget(for: item, uid: 501), "pluginkit/com.example.app.ShareExt")
    }

    func testUndoGoesBackToThePreviousElectionExactly() {
        let wasUsed = extensionItem(identifier: "com.example.a", election: "use")
        XCTAssertEqual(RemediationPlanner.undoHint(for: .disable, item: wasUsed), "launchkeeper enable com.example.a")
        let wasIgnored = extensionItem(identifier: "com.example.b", election: "ignore")
        XCTAssertEqual(RemediationPlanner.undoHint(for: .enable, item: wasIgnored), "launchkeeper disable com.example.b")
        // No election = default: `enable` would elect `use` — a different
        // state. The hint names the exact way back.
        let hadNone = extensionItem(identifier: "com.example.c", election: "none")
        let hint = RemediationPlanner.undoHint(for: .disable, item: hadNone) ?? ""
        XCTAssertTrue(hint.hasPrefix("pluginkit -e default -i com.example.c"), hint)
    }

    func testResolverFindsAMergedExtensionByIdentifier() {
        var merged = extensionItem(identifier: "com.example.app.QL")
        merged.key = "btm:ABCD"
        merged.displayName = "Example Preview"
        merged.id = "07"
        guard case .unique(let found) = TargetResolver.resolve("com.example.app.QL", in: [merged]) else {
            return XCTFail("the undo hint addresses extensions by identifier — it must resolve")
        }
        XCTAssertEqual(found.key, "btm:ABCD")
    }
}

final class PluginKitControlEngineTests: XCTestCase {
    private let options = ScanOptions(includeUser: true, includeSystem: false, scanBTM: false,
                                      scanSignatures: false, scanExtensions: true,
                                      scanSystemExtensions: false, scanHelpers: false, scanScheduled: false,
                                      scanLegacy: false, scanPlugins: false, scanShell: false, scanNetwork: false,
                                      scanReceipts: false)

    private func home() throws -> String {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("lk-pk-\(UUID().uuidString)", isDirectory: true).path
        try FileManager.default.createDirectory(atPath: dir + "/Library/LaunchAgents", withIntermediateDirectories: true)
        return dir
    }

    private func fake() -> FakePluginKit {
        FakePluginKit([
            .init(identifier: "com.example.app.ShareExt", version: "1.2", election: "+",
                  path: "/Applications/Example.app/Contents/PlugIns/ShareExt.appex"),
            .init(identifier: "com.example.app.ShareExt", version: "1.1", election: "+",
                  path: "/Users/alice/Old/Example.app/Contents/PlugIns/ShareExt.appex"),
            .init(identifier: "com.apple.garageband10.QL", version: "1.0", election: "",
                  path: "/Applications/GarageBand.app/Contents/PlugIns/QL.appex"),
        ])
    }

    private func engine(_ runner: CommandRunner, home: String) -> RemediationEngine {
        RemediationEngine(environment: RemediationEnvironment(runner: runner, home: home, uid: 501),
                          audit: AuditLog(directory: home + "/logs"))
    }

    func testDryRunPlansAndExecutesNothing() throws {
        let home = try home()
        defer { try? FileManager.default.removeItem(atPath: home) }
        let pk = fake()
        let result = engine(pk, home: home).run(operation: .disable, target: "ShareExt", apply: false,
                                                scanOptions: options)
        XCTAssertEqual(result.status, .planned)
        XCTAssertEqual(result.target, "pluginkit/com.example.app.ShareExt")
        XCTAssertEqual(result.plan.map(\.display), ["/usr/bin/pluginkit -e ignore -i com.example.app.ShareExt"])
        XCTAssertEqual(result.undoHint, "launchkeeper enable com.example.app.ShareExt")
        XCTAssertTrue(pk.elections.isEmpty, "dry-run must not elect: \(pk.elections)")
        XCTAssertTrue(engine(pk, home: home).audit.readAll()
            .contains("disable pluginkit/com.example.app.ShareExt planned"))
    }

    func testApplyElectsAndVerifiesEveryVersion() throws {
        let home = try home()
        defer { try? FileManager.default.removeItem(atPath: home) }
        let pk = fake()
        let result = engine(pk, home: home).run(operation: .disable, target: "ShareExt", apply: true,
                                                scanOptions: options)
        XCTAssertEqual(result.status, .appliedOk, "\(result.messages)")
        XCTAssertEqual(pk.elections, ["/usr/bin/pluginkit -e ignore -i com.example.app.ShareExt"])
        XCTAssertTrue(pk.log.contains("/usr/bin/pluginkit -mAvv -i com.example.app.ShareExt"),
                      "verification must re-read the election")
        XCTAssertEqual(pk.registrations.filter { $0.identifier == "com.example.app.ShareExt" }.map(\.election),
                       ["-", "-"])
        XCTAssertTrue(result.messages.contains("verified: election visible in pluginkit"))

        // …and back.
        let back = engine(pk, home: home).run(operation: .enable, target: "com.example.app.ShareExt", apply: true,
                                              scanOptions: options)
        XCTAssertEqual(back.status, .appliedOk, "\(back.messages)")
        XCTAssertEqual(pk.registrations.first?.election, "+")
    }

    func testSilentElectionIsCaughtByVerification() throws {
        let home = try home()
        defer { try? FileManager.default.removeItem(atPath: home) }
        let pk = fake()
        pk.silentElection = true
        let result = engine(pk, home: home).run(operation: .disable, target: "ShareExt", apply: true,
                                                scanOptions: options)
        guard case .appliedFailed(let detail) = result.status else {
            return XCTFail("exit 0 without effect must fail verification, got \(result.status)")
        }
        XCTAssertTrue(detail.contains("still shows"), detail)
    }

    func testFailingElectionStopsAndReportsTheExitCode() throws {
        let home = try home()
        defer { try? FileManager.default.removeItem(atPath: home) }
        let pk = fake()
        pk.failElection = true
        let result = engine(pk, home: home).run(operation: .disable, target: "ShareExt", apply: true,
                                                scanOptions: options)
        XCTAssertEqual(result.status, .appliedFailed("exit 1"))
    }

    func testAppleExtensionIsRefusedAndNothingRuns() throws {
        let home = try home()
        defer { try? FileManager.default.removeItem(atPath: home) }
        let pk = fake()
        let result = engine(pk, home: home).run(operation: .disable, target: "garageband", apply: true,
                                                scanOptions: options)
        guard case .refused(let reason) = result.status else { return XCTFail("\(result.status)") }
        XCTAssertTrue(reason.contains("com.apple"), reason)
        XCTAssertTrue(pk.elections.isEmpty)
        XCTAssertTrue(engine(pk, home: home).audit.readAll().contains("refused("))
    }
}

// MARK: - V0.7: the control matrix never promises what the gate would refuse

final class ControlMatrixInvariantTests: XCTestCase {
    private func samples() -> [BackgroundItem] {
        var launchd = BackgroundItem(key: "com.vendor.agent", displayName: "agent", type: .launchAgentUser,
                                     path: "/Users/alice/Library/LaunchAgents/com.vendor.agent.plist",
                                     label: "com.vendor.agent", domain: .user, plistPresent: true)
        launchd.launchdPresent = true
        let appleJob = BackgroundItem(key: "com.apple.x", displayName: "x", type: .launchDaemon,
                                      path: "/System/Library/LaunchDaemons/com.apple.x.plist", label: "com.apple.x",
                                      domain: .system, plistPresent: true)
        var cron = BackgroundItem(key: "cron:alice:crontab:/x", displayName: "/x", type: .cronJob,
                                  owner: "alice", domain: .user, category: .scheduled)
        cron.metadata = ["cron-source": "crontab -l (alice)", "cron-schedule": "0 3 * * *", "cron-command": "/x"]
        var hook = BackgroundItem(key: "hook:LoginHook:system", displayName: "LoginHook", type: .loginHook,
                                  path: "/Library/Preferences/com.apple.loginwindow.plist", executable: "/x",
                                  domain: .system, category: .legacy)
        hook.metadata["hook-kind"] = "LoginHook"
        var rule = BackgroundItem(key: "fw:/opt/x", displayName: "x", type: .firewallRule, path: "/opt/x",
                                  domain: .system, category: .network)
        rule.metadata = ["firewall": "allow incoming connections", "firewall-path": "/opt/x"]
        var ext = BackgroundItem(key: "ext:com.vendor.ext", displayName: "ext", type: .appExtension,
                                 category: .appExtensions)
        ext.sources = [SourceEvidence(kind: .pluginkit, detail: "x", confidence: .high)]
        ext.metadata["ext-identifier"] = "com.vendor.ext"
        let sysext = BackgroundItem(key: "sysext:x", displayName: "x", type: .systemExtension, domain: .system,
                                    category: .systemExtensions)
        let shell = BackgroundItem(key: "shell:~/.zshrc", displayName: ".zshrc", type: .shellProfile,
                                   category: .shellStartup)
        return [launchd, appleJob, cron, hook, rule, ext, sysext, shell]
    }

    func testEveryPromisedActionPassesTheGateAndDisplayOnlyPromisesNothing() {
        let analyzer = ControlAnalyzer(launchDirs: [])
        for item in samples() {
            let control = analyzer.evaluate(item)
            for action in control.actions {
                guard let operation = RemediationOperation(rawValue: action) else {
                    return XCTFail("\(item.key): unknown action \(action)")
                }
                XCTAssertEqual(RemediationGate.evaluate(operation: operation, item: item), .allowed,
                               "\(item.key) promises \(action) but the gate refuses it")
            }
            if control.level == .displayOnly {
                XCTAssertTrue(control.actions.isEmpty, "\(item.key): display-only must not list actions")
            } else {
                XCTAssertEqual(control.mechanism, item.controlMechanism, "\(item.key): matrix and dispatch disagree")
            }
            // Nothing outside launchd is ever removable here.
            if item.controlMechanism != .launchd {
                XCTAssertFalse(control.actions.contains("remove"), item.key)
            }
        }
    }
}
