import XCTest
@testable import BTMKit

/// The codesign seam: Apple-core paths classify without spawning, /usr/local
/// and everything else goes through `codesign -dvvv` via the injectable runner.
final class SignatureScannerTests: XCTestCase {
    func testAppleCoreShortCircuitsWithoutSpawn() {
        // Runner would answer "adhoc" if consulted — getting "apple-system"
        // proves no process was launched for this path.
        let runner = ScriptedCommandRunner(
            defaultResult: CommandResult(exitCode: 0, stdout: "Signature=adhoc", stderr: ""))
        let record = SignatureScanner().status(for: "/usr/sbin/crond", runner: runner)
        XCTAssertEqual(record.status, "apple-system")
    }

    func testLocalBinGetsSignedCheck() {
        // /usr/local is NOT Apple territory (Homebrew, custom scripts).
        let key = "/usr/bin/codesign -dvvv /usr/local/bin/automount-guard.sh"
        let runner = ScriptedCommandRunner(responses: [key: CommandResult(
            exitCode: 0,
            stdout: """
            Identifier=com.example.automount
            CodeDirectory v=20400 size=512 flags=0x0
            TeamIdentifier=ABCD1234 Team ID=ABCD1234
            Authority=Developer ID Application: Ghost Inc (ABCD1234)
            """,
            stderr: "")])
        let record = SignatureScanner().status(for: "/usr/local/bin/automount-guard.sh", runner: runner)
        XCTAssertEqual(record.status, "signed")
        XCTAssertEqual(record.teamIdentifier, "ABCD1234")
    }

    func testUnsignedWhenCodesignFindsNothing() {
        let record = SignatureScanner().status(for: "/usr/local/bin/mystery",
                                               runner: ScriptedCommandRunner())
        XCTAssertEqual(record.status, "unsigned")
    }

    func testAdhocSignature() {
        let key = "/usr/bin/codesign -dvvv /Applications/Ghost.app/Contents/MacOS/Ghost"
        let runner = ScriptedCommandRunner(responses: [key: CommandResult(
            exitCode: 0, stdout: "Identifier=com.ghost\nSignature=adhoc", stderr: "")])
        let record = SignatureScanner().status(
            for: "/Applications/Ghost.app/Contents/MacOS/Ghost", runner: runner)
        XCTAssertEqual(record.status, "adhoc")
    }

    func testRelativePathNeverProbed() {
        let record = SignatureScanner().status(for: "Contents/MacOS/Helper",
                                               runner: ScriptedCommandRunner())
        XCTAssertEqual(record.status, "unavailable")
    }
}

/// End-to-end read-only pipeline over the injectable seams: synthetic plists,
/// canned launchctl/BTM output, temp home. No real system state, no shell-out.
final class ScanPipelineTests: XCTestCase {
    private func makeTempHome(withPlists: Bool = true) throws -> String {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("btmctl-tests-\(UUID().uuidString)", isDirectory: true)
        let agents = dir.appendingPathComponent("Library/LaunchAgents", isDirectory: true)
        try FileManager.default.createDirectory(at: agents, withIntermediateDirectories: true)
        if withPlists {
            let script = """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
              <key>Label</key><string>com.example.script</string>
              <key>ProgramArguments</key><array><string>/bin/bash</string><string>/nonexistent-xyz-dir/gone.sh</string></array>
              <key>RunAtLoad</key><true/>
            </dict>
            </plist>
            """
            try Data(script.utf8).write(to: agents.appendingPathComponent("com.example.script.plist"))
            try Data("this is not a plist".utf8)
                .write(to: agents.appendingPathComponent("com.example.bad.plist"))
        }
        return dir.path
    }

    private let launchdGui = """
    gui/501 = {
    services = {
                999   (pe) com.example.script
                  0      -  com.apple.mediacontinuityd
    }
    }
    """

    private let btmText = """
    Records for UID 0 : AAAA-BBBB
    Items:
     #1:
                      Name: script thing
                      Type: legacy agent (0x20010)
                Disposition: [enabled, allowed, notified] (0xb)
                Identifier: 16.com.example.script
                        URL: file:///anywhere/Library/LaunchAgents/com.example.script.plist
            Executable Path: /bin/bash
     #2:
                      Name: GhostService
                      Type: legacy daemon (0x10010)
                Disposition: [disabled, allowed, not notified] (0x2)
                Identifier: 16.de.example.ghost
                        URL: file:///Library/LaunchDaemons/de.example.ghost.plist
    """

    private func userOnlyOptions() -> ScanOptions {
        ScanOptions(includeUser: true, includeSystem: false, scanBTM: true, scanSignatures: false)
    }

    func testHappyPathMergesAcrossLayers() throws {
        let home = try makeTempHome()
        defer { try? FileManager.default.removeItem(atPath: home) }
        let runner = ScriptedCommandRunner(responses: [
            "/bin/launchctl print gui/501":
                CommandResult(exitCode: 0, stdout: launchdGui, stderr: ""),
            "/bin/launchctl print-disabled gui/501":
                CommandResult(exitCode: 0, stdout: "\t\"com.example.script\" => disabled\n", stderr: ""),
            "/usr/bin/sfltool dumpbtm":
                CommandResult(exitCode: 0, stdout: btmText, stderr: ""),
        ])
        let env = ScanEnvironment(runner: runner, home: home, uid: 501)
        let report = ScanCoordinator(environment: env).perform(options: userOnlyOptions())

        // Malformed plist must degrade to a warning, not a crash.
        XCTAssertTrue(report.warnings.contains { $0.contains("malformed plist") })
        XCTAssertTrue(report.checks.contains { $0.contains("sfltool dumpbtm: ok (2 records)") })

        // com.apple.mediacontinuityd is Apple bookkeeping and must NOT become
        // an item (correlator Pass 2 skip). Only the two third-party components remain.
        XCTAssertEqual(Set(report.items.map(\.key)), ["com.example.script", "btm:16.de.example.ghost"],
                       "actual: \(report.items.map(\.key))")

        guard let script = report.items.first(where: { $0.label == "com.example.script" }) else {
            return XCTFail("merged item missing")
        }
        XCTAssertEqual(Set(script.sources.map(\.kind)), [.plist, .launchd, .btm],
                       "one component, three evidence layers")
        XCTAssertTrue(script.running)
        XCTAssertEqual(script.pid, 999)
        XCTAssertFalse(script.enabled, "print-disabled override must win")

        guard let ghost = report.items.first(where: { $0.key == "btm:16.de.example.ghost" }) else {
            return XCTFail("standalone BTM entry missing")
        }
        XCTAssertTrue(ghost.orphaned, "BTM entry without backing plist")
        XCTAssertEqual(report.uncorrelated, ["16.de.example.ghost"])
    }

    func testMissingSourcesDegradeGracefully() throws {
        let home = try makeTempHome(withPlists: false)
        defer { try? FileManager.default.removeItem(atPath: home) }
        // Nothing scripted: every external tool "fails" — must not crash or
        // pretend; the report carries explicit gaps.
        let env = ScanEnvironment(runner: ScriptedCommandRunner(), home: home, uid: 501)
        let report = ScanCoordinator(environment: env).perform(options: userOnlyOptions())
        XCTAssertTrue(report.warnings.contains { $0.contains("launchctl print gui/501 failed") })
        XCTAssertTrue(report.warnings.contains { $0.contains("BTM layer not scanned") })
        XCTAssertTrue(report.checks.contains { $0.contains("sfltool dumpbtm: FAILED") })
        XCTAssertTrue(report.items.isEmpty)
    }

    func testBTMTimeoutDegradesHonestly() throws {
        // A hanging sfltool must fail fast and loud: honest check line plus
        // warning, and the plist/launchd layers keep working without BTM.
        let home = try makeTempHome(withPlists: false)
        defer { try? FileManager.default.removeItem(atPath: home) }
        let runner = ScriptedCommandRunner(responses: [
            "/bin/launchctl print gui/501":
                CommandResult(exitCode: 0, stdout: launchdGui, stderr: ""),
            "/bin/launchctl print-disabled gui/501":
                CommandResult(exitCode: 0, stdout: "", stderr: ""),
            "/usr/bin/sfltool dumpbtm":
                CommandResult(exitCode: -2, stdout: "", stderr: "timeout after 45s"),
        ])
        let env = ScanEnvironment(runner: runner, home: home, uid: 501)
        let report = ScanCoordinator(environment: env).perform(options: userOnlyOptions())
        XCTAssertTrue(report.checks.contains { $0.contains("sfltool dumpbtm: FAILED (timeout") })
        XCTAssertTrue(report.warnings.contains { $0.contains("timed out after 45s") })
        XCTAssertEqual(report.items.count, 1, "launchd layer must still produce the inventory")
        XCTAssertEqual(report.items.first?.running, true)
    }

    func testRealFixturesEndToEnd() throws {
        // Whole real capture (127 BTM records, 2900+ launchctl lines) through
        // the full pipeline. Signature stage off: keeps the test shell-out free.
        let home = try makeTempHome(withPlists: false)
        defer { try? FileManager.default.removeItem(atPath: home) }
        let runner = ScriptedCommandRunner(responses: [
            "/bin/launchctl print gui/501":
                CommandResult(exitCode: 0, stdout: Fixtures.text("launchctl-gui.txt"), stderr: ""),
            "/bin/launchctl print-disabled gui/501":
                CommandResult(exitCode: 0, stdout: Fixtures.text("disabled-gui.txt"), stderr: ""),
            "/usr/bin/sfltool dumpbtm":
                CommandResult(exitCode: 0, stdout: Fixtures.text("dumpbtm-nosudo.txt"), stderr: ""),
        ])
        let env = ScanEnvironment(runner: runner, home: home, uid: 501)
        let report = ScanCoordinator(environment: env).perform(options: userOnlyOptions())

        XCTAssertGreaterThan(report.items.count, 20, "real capture must yield a usable inventory")
        XCTAssertFalse(report.uncorrelated.isEmpty, "unmatched BTM entries must be reported")
        XCTAssertFalse(report.warnings.contains { $0.contains("BTM layer not scanned") })
        XCTAssertTrue(report.items.contains { $0.btmPresent && $0.launchdPresent },
                      "cross-layer correlation must occur on the real capture")
        XCTAssertTrue(report.items.contains { $0.label == "de.example.automount-guard" },
                      "spec's motivating example must be present in the capture")
    }
}

/// Default view must stay signal-dense; explicit flags unlock the raw view.
final class ListFilterTests: XCTestCase {
    private func appleItem() -> BackgroundItem {
        var item = BackgroundItem(key: "com.apple.mediacontinuityd",
                                  displayName: "com.apple.mediacontinuityd", type: .unknown)
        item.label = "com.apple.mediacontinuityd"
        item.launchdPresent = true
        item.running = true
        return item
    }

    private func transientItem() -> BackgroundItem {
        var item = BackgroundItem(key: "de.example.transient", displayName: "transient", type: .unknown)
        item.label = "de.example.transient"
        item.launchdPresent = true
        item.running = true
        return item
    }

    func testAppleInternalAndTransientHiddenByDefault() {
        let items = [appleItem(), transientItem()]
        XCTAssertTrue(ListFilter().apply(to: items).isEmpty,
                      "both are noise in the default view")
        var all = ListFilter()
        all.includeAll = true
        XCTAssertEqual(all.apply(to: items).count, 2)
    }

    func testUserOwnedPlistOverridesAppleHiding() {
        var item = appleItem()
        item.plistPresent = true
        item.owner = "alice"
        XCTAssertEqual(ListFilter().apply(to: [item]).count, 1,
                       "third-party finding with apple-ish name stays visible")
    }

    func testNarrowingFlagsBypassTransientSuppression() {
        var filter = ListFilter()
        filter.runningOnly = true
        XCTAssertEqual(filter.apply(to: [transientItem()]).count, 1,
                       "--running asks for live state; transient entries are the answer")
        var orphansOnly = ListFilter()
        orphansOnly.orphansOnly = true
        XCTAssertTrue(orphansOnly.apply(to: [transientItem()]).isEmpty,
                      "AND semantics: not orphaned, not shown")
        var orphaned = transientItem()
        orphaned.orphaned = true
        XCTAssertEqual(orphansOnly.apply(to: [orphaned]).count, 1)
    }

    func testDomainFlags() {
        // Both carry a plist so transient suppression is not what drives the outcome.
        var user = transientItem()
        user.domain = .user
        user.plistPresent = true
        var system = transientItem()
        system.domain = .system
        system.plistPresent = true
        var systemFilter = ListFilter()
        systemFilter.systemOnly = true
        XCTAssertEqual(systemFilter.apply(to: [user, system]).count, 1)
        var userFilter = ListFilter()
        userFilter.userOnly = true
        XCTAssertEqual(userFilter.apply(to: [user, system]).count, 1)
    }
}

final class RendererTests: XCTestCase {
    private func flaggedItem() -> BackgroundItem {
        var item = BackgroundItem(id: "01", key: "de.x.broken", displayName: "broken",
                                  type: .launchDaemon)
        item.domain = .user
        item.label = "de.x.broken"
        item.path = "/Library/LaunchAgents/de.x.broken.plist"
        item.executable = "/nonexistent-xyz-dir/gone"
        item.orphaned = true
        item.orphanReasons = ["executable missing: /nonexistent-xyz-dir/gone"]
        item.riskFlags = ["temp-or-hidden-path"]
        item.enabled = false
        return item
    }

    func testTableShowsFlagsAndEmptyMessage() {
        let table = TableRenderer.render([flaggedItem()], mode: .table)
        XCTAssertTrue(table.contains("ORPHAN"))
        XCTAssertTrue(table.contains("DISABLED"))
        XCTAssertTrue(table.contains("TEMP/PATH"))
        XCTAssertEqual(TableRenderer.render([], mode: .table), "no entries match the given filters")
    }

    func testOrphansModeShowsReason() {
        let out = TableRenderer.render([flaggedItem()], mode: .orphans)
        XCTAssertTrue(out.contains("executable missing"))
    }

    func testInspectEmitsReadOnlyNextSteps() {
        let out = InspectRenderer.render(flaggedItem(), uid: 501)
        XCTAssertTrue(out.contains("next steps (read-only"))
        XCTAssertTrue(out.contains("launchctl print gui/501/de.x.broken"))
        XCTAssertTrue(out.contains("ls -lO '/Library/LaunchAgents/de.x.broken.plist'"))
    }

    func testJSONRoundTrips() throws {
        let encoded = try JSONRenderer.encode([flaggedItem()])
        let decoded = try JSONDecoder().decode([BackgroundItem].self, from: Data(encoded.utf8))
        XCTAssertEqual(decoded.count, 1)
        XCTAssertEqual(decoded[0].orphanReasons, ["executable missing: /nonexistent-xyz-dir/gone"])
    }
}
