import XCTest
@testable import LaunchKeeperKit

// V0.5.6: scheduled (cron/at/pmset/periodic), legacy persistence and plugin
// directories. Hermetic: scripted runner, temp trees, fixtures.

private func tempRoot(_ tag: String) -> String {
    FileManager.default.temporaryDirectory
        .appendingPathComponent("lk-v056-\(tag)-\(UUID().uuidString)", isDirectory: true).path
}

private let crontabText = """
# m h dom mon dow command
SHELL=/bin/sh
MAILTO=alice
0 3 * * *   /opt/backup/run.sh --nightly
*/15 * * * * /Users/alice/bin/sync >/dev/null 2>&1

@reboot /usr/local/bin/agent --start
"""

private let atqText = """
Date\t\t\t\tOwner\t\tQueue\tJob#
Tue Sep 22 18:00:00 2026\talice\t\ta\t3
"""

final class ScheduledParserTests: XCTestCase {
    func testCrontab() {
        let entries = CronParser.parse(crontabText, user: "alice", source: "crontab")
        XCTAssertEqual(entries.count, 3, "\(entries)")
        XCTAssertEqual(entries[0].schedule, "0 3 * * *")
        XCTAssertEqual(entries[0].command, "/opt/backup/run.sh --nightly")
        XCTAssertEqual(entries[0].line, 4)
        XCTAssertEqual(entries[1].schedule, "*/15 * * * *")
        XCTAssertEqual(entries[2].schedule, "@reboot")
        XCTAssertEqual(entries[2].command, "/usr/local/bin/agent --start")
    }

    func testSystemCrontabHasUserColumn() {
        let entries = CronParser.parse("30 4 * * 1 root /usr/sbin/rotate\n", user: "root", source: "/etc/crontab", systemTable: true)
        XCTAssertEqual(entries.count, 1)
        XCTAssertEqual(entries[0].user, "root")
        XCTAssertEqual(entries[0].command, "/usr/sbin/rotate")
    }

    func testAtq() {
        let jobs = AtqParser.parse(atqText)
        XCTAssertEqual(jobs.count, 1)
        XCTAssertEqual(jobs[0].id, "3")
        XCTAssertEqual(jobs[0].queue, "a")
        XCTAssertEqual(jobs[0].owner, "alice")
        XCTAssertEqual(jobs[0].when, "Tue Sep 22 18:00:00 2026")
    }

    func testPmsetFixture() {
        let events = PmsetScheduleParser.parse(Fixtures.text("pmset-sched.txt"))
        XCTAssertEqual(events.count, 3)
        XCTAssertEqual(events[0].kind, "wake")
        XCTAssertTrue(events[0].owner.hasPrefix("com.apple."))
        XCTAssertEqual(events.filter(\.userVisible).count, 1)
        XCTAssertEqual(events[2].index, 2)
    }

    func testAuthorizationMechanismsFixture() {
        let names = AuthorizationMechanismParser.pluginNames(Fixtures.text("authorizationdb-login.txt"))
        XCTAssertTrue(names.contains("builtin"))
        XCTAssertTrue(names.contains("loginwindow"))
        XCTAssertTrue(names.contains("CryptoTokenKit"))
        XCTAssertFalse(names.contains("TeamViewerAuthPlugin"))
    }

    func testLaunchdScheduleRendering() {
        XCTAssertEqual(PlistReader.extractSchedule(dict: ["StartInterval": 3600]), "every 3600 s")
        XCTAssertEqual(PlistReader.extractSchedule(dict: ["StartCalendarInterval": ["Hour": 3, "Minute": 0]]),
                       "calendar Minute=0 Hour=3")
        XCTAssertEqual(PlistReader.extractSchedule(dict: ["StartCalendarInterval": [["Weekday": 1], ["Weekday": 5]]]),
                       "calendar Weekday=1; calendar Weekday=5")
        XCTAssertNil(PlistReader.extractSchedule(dict: ["RunAtLoad": true]))
    }
}

final class ScheduledScannerTests: XCTestCase {
    func testNoCrontabIsHealthyAndPeriodicIsWalked() throws {
        let root = tempRoot("sched")
        defer { try? FileManager.default.removeItem(atPath: root) }
        try FileManager.default.createDirectory(atPath: root + "/periodic/daily", withIntermediateDirectories: true)
        try Data("#!/bin/sh\n".utf8).write(to: URL(fileURLWithPath: root + "/periodic/daily/500.vendor-cleanup"))
        let runner = ScriptedCommandRunner(responses: [
            "/usr/bin/crontab -l": CommandResult(exitCode: 1, stdout: "", stderr: "crontab: no crontab for alice\n"),
            "/usr/bin/atq": CommandResult(exitCode: 0, stdout: "", stderr: ""),
            "/usr/bin/pmset -g sched": CommandResult(exitCode: 0, stdout: Fixtures.text("pmset-sched.txt"), stderr: ""),
        ])
        let result = ScheduledScanner(runner: runner, userName: "alice", systemCrontab: root + "/none",
                                      periodicRoots: [root + "/periodic"]).scan()
        XCTAssertTrue(result.failed.isEmpty, "\(result.warnings)")
        XCTAssertTrue(result.checks.contains("crontab: none for alice"), "\(result.checks)")
        XCTAssertEqual(result.periodic.map(\.name), ["500.vendor-cleanup"])
        XCTAssertEqual(result.periodic[0].period, "daily")
        XCTAssertEqual(result.powerEvents.count, 3)
    }

    func testPmsetFailureIsIncomplete() {
        let runner = ScriptedCommandRunner(responses: [
            "/usr/bin/crontab -l": CommandResult(exitCode: 0, stdout: crontabText, stderr: ""),
            "/usr/bin/atq": CommandResult(exitCode: 0, stdout: atqText, stderr: ""),
        ])
        let result = ScheduledScanner(runner: runner, userName: "alice", systemCrontab: "/nonexistent",
                                      periodicRoots: []).scan()
        XCTAssertEqual(result.failed, ["pmset"])
        XCTAssertEqual(result.cron.count, 3)
        XCTAssertEqual(result.atJobs.count, 1)
    }
}

final class LegacyScannerTests: XCTestCase {
    func testHooksStartupItemsAndFiles() throws {
        let root = tempRoot("legacy")
        defer { try? FileManager.default.removeItem(atPath: root) }
        let fm = FileManager.default
        try fm.createDirectory(atPath: root + "/StartupItems/OLDAGENT", withIntermediateDirectories: true)
        try Data("#!/bin/sh\n".utf8).write(to: URL(fileURLWithPath: root + "/StartupItems/OLDAGENT/OLDAGENT"))
        let params: [String: Any] = ["Description": "Old agent", "Provides": ["OLDAGENT"]]
        try PropertyListSerialization.data(fromPropertyList: params, format: .xml, options: 0)
            .write(to: URL(fileURLWithPath: root + "/StartupItems/OLDAGENT/StartupParameters.plist"))
        try fm.createDirectory(atPath: root + "/StartupItems/Bare", withIntermediateDirectories: true)
        let loginwindow: [String: Any] = ["LoginHook": "/usr/local/bin/hook.sh", "lastUser": "loggedIn"]
        try PropertyListSerialization.data(fromPropertyList: loginwindow, format: .xml, options: 0)
            .write(to: URL(fileURLWithPath: root + "/loginwindow.plist"))
        try Data("echo hi\n".utf8).write(to: URL(fileURLWithPath: root + "/rc.local"))
        try fm.createDirectory(atPath: root + "/emond", withIntermediateDirectories: true)
        try Data("<plist/>".utf8).write(to: URL(fileURLWithPath: root + "/emond/SampleRules.plist"))
        try Data("<plist/>".utf8).write(to: URL(fileURLWithPath: root + "/emond/Vendor.plist"))

        let scanner = LegacyScanner(loginwindowPlists: [(root + "/loginwindow.plist", .system), (root + "/missing.plist", .user)],
                                    startupItemsDirectories: [root + "/StartupItems"],
                                    legacyFiles: [("rc-script", root + "/rc.local"), ("launchd-conf", root + "/launchd.conf")],
                                    emondRulesDirectory: root + "/emond")
        let result = scanner.scan()
        XCTAssertEqual(result.hooks.count, 1)
        XCTAssertEqual(result.hooks[0].kind, "LoginHook")
        XCTAssertEqual(result.hooks[0].script, "/usr/local/bin/hook.sh")
        XCTAssertEqual(result.startupItems.map(\.name), ["Bare", "OLDAGENT"])
        XCTAssertEqual(result.startupItems[1].description, "Old agent")
        XCTAssertEqual(result.startupItems[1].script, root + "/StartupItems/OLDAGENT/OLDAGENT")
        XCTAssertFalse(result.startupItems[0].hasParameters)
        XCTAssertEqual(result.files.map(\.kind), ["rc-script", "emond-rule"])
        XCTAssertEqual(result.files[1].path, root + "/emond/Vendor.plist", "SampleRules.plist is Apple's")
    }
}

final class PluginDirectoryScannerTests: XCTestCase {
    func testBundlesAndLoginWiring() throws {
        let root = tempRoot("plugins")
        defer { try? FileManager.default.removeItem(atPath: root) }
        let fm = FileManager.default
        let auth = root + "/SecurityAgentPlugins"
        try fm.createDirectory(atPath: auth + "/VendorAuth.bundle/Contents", withIntermediateDirectories: true)
        let info: [String: Any] = ["CFBundleIdentifier": "com.vendor.auth", "CFBundleShortVersionString": "2.0"]
        try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
            .write(to: URL(fileURLWithPath: auth + "/VendorAuth.bundle/Contents/Info.plist"))
        try fm.createDirectory(atPath: auth + "/HomeDirMechanism.bundle", withIntermediateDirectories: true)
        try Data("x".utf8).write(to: URL(fileURLWithPath: auth + "/Component.plist"))
        let hal = root + "/HAL"
        try fm.createDirectory(atPath: hal + "/Virtual.driver", withIntermediateDirectories: true)
        try fm.createDirectory(atPath: hal + "/NotABundle", withIntermediateDirectories: true)

        let runner = ScriptedCommandRunner(responses: [
            "/usr/bin/security authorizationdb read system.login.console":
                CommandResult(exitCode: 0, stdout: Fixtures.text("authorizationdb-login.txt"), stderr: ""),
        ])
        let result = PluginDirectoryScanner(runner: runner, directories: [
            PluginDirectory(kind: "authorization", path: auth, domain: .system),
            PluginDirectory(kind: "audio-hal", path: hal, domain: .system),
            PluginDirectory(kind: "quicklook", path: root + "/none", domain: .user),
        ]).scan()
        XCTAssertEqual(result.plugins.map(\.name), ["HomeDirMechanism", "VendorAuth", "Virtual"])
        XCTAssertEqual(result.plugins[0].wiredIntoLogin, true)
        XCTAssertEqual(result.plugins[1].wiredIntoLogin, false)
        XCTAssertEqual(result.plugins[1].bundleIdentifier, "com.vendor.auth")
        XCTAssertEqual(result.plugins[1].version, "2.0")
        XCTAssertNil(result.plugins[2].wiredIntoLogin)
        XCTAssertTrue(result.checks.contains("plugin directories: 3 bundles in 2 directories"), "\(result.checks)")
    }

    func testAuthorizationdbFailureIsAWarningOnly() {
        let root = tempRoot("plugins-auth")
        let result = PluginDirectoryScanner(runner: ScriptedCommandRunner(), directories: [
            PluginDirectory(kind: "authorization", path: root, domain: .system)]).scan()
        XCTAssertTrue(result.warnings.contains { $0.contains("authorizationdb unreadable") }, "\(result.warnings)")
    }
}

final class ScheduledLegacyPluginCorrelationTests: XCTestCase {
    private func correlate(_ input: ItemCorrelator.Input) -> [BackgroundItem] {
        var items = ItemCorrelator().correlate(input).items
        OrphanDetector().apply(to: &items)
        ControlAnalyzer(launchDirs: ["/Library/LaunchDaemons"]).apply(to: &items)
        return items
    }

    func testCronCommandMissingIsAnOrphan() throws {
        var scheduled = ScheduledScanner.Result()
        scheduled.cron = [CronEntry(user: "alice", source: "crontab", line: 4, schedule: "0 3 * * *",
                                    command: "/opt/gone/run.sh --nightly"),
                          CronEntry(user: "alice", source: "crontab", line: 5, schedule: "@reboot", command: "echo up")]
        scheduled.powerEvents = [PowerEvent(index: 0, kind: "wake", when: "09/22/2026 16:38:36",
                                            owner: "com.apple.alarm.user-invisible-com.apple.acmd.alarm", userVisible: false)]
        let items = correlate(.init(jobs: [], launchd: [], btm: [], disabled: [:], uid: 501, scheduled: scheduled))
        let gone = try XCTUnwrap(items.first { $0.key == "cron:alice:crontab:/opt/gone/run.sh --nightly" })
        XCTAssertEqual(gone.category, .scheduled)
        XCTAssertEqual(gone.metadata["schedule"], "cron 0 3 * * *")
        XCTAssertTrue(gone.orphaned)
        XCTAssertTrue(gone.orphanReasons.contains { $0.hasPrefix("executable missing: /opt/gone/run.sh") }, "\(gone.orphanReasons)")
        // V0.7.0: user-crontab lines are switchable (comment out / back in).
        XCTAssertEqual(gone.control?.level, .reversible)
        XCTAssertEqual(gone.control?.mechanism, .cron)
        let echo = try XCTUnwrap(items.first { $0.key == "cron:alice:crontab:echo up" })
        XCTAssertNil(echo.executable, "relative commands are not resolvable")
        XCTAssertFalse(echo.orphaned)
        // Apple's own power alarms hide in the default list like other Apple internals.
        let alarm = try XCTUnwrap(items.first { $0.type == .powerEvent })
        var filter = ListFilter(); filter.category = .scheduled
        XCTAssertFalse(filter.apply(to: items).contains { $0.key == alarm.key })
        filter.includeAll = true
        XCTAssertTrue(filter.apply(to: items).contains { $0.key == alarm.key })
    }

    func testScheduledViewIncludesLaunchdTimers() throws {
        let timer = LaunchJobRecord(label: "com.vendor.nightly", path: "/Library/LaunchDaemons/com.vendor.nightly.plist",
                                    domain: .system, kind: .launchDaemon, program: "/bin/echo", arguments: [],
                                    runAtLoad: false, keepAlive: false, ownerName: "root", malformed: false,
                                    schedule: "calendar Minute=0 Hour=3")
        let plain = LaunchJobRecord(label: "com.vendor.agent", path: "/Library/LaunchDaemons/com.vendor.agent.plist",
                                    domain: .system, kind: .launchDaemon, program: "/bin/echo", arguments: [],
                                    runAtLoad: true, keepAlive: false, ownerName: "root", malformed: false)
        let items = correlate(.init(jobs: [timer, plain], launchd: [], btm: [], disabled: [:], uid: 501))
        var filter = ListFilter(); filter.category = .scheduled
        XCTAssertEqual(filter.apply(to: items).map(\.key), ["com.vendor.nightly"])
        filter.category = .launchItems
        XCTAssertEqual(filter.apply(to: items).count, 2, "timers stay launch items")
        XCTAssertEqual(items.first { $0.key == "com.vendor.nightly" }?.metadata["schedule"], "calendar Minute=0 Hour=3")
    }

    func testStartupItemIsALeftoverAndPluginsAreDisplayOnly() throws {
        var legacy = LegacyScanner.Result()
        legacy.startupItems = [StartupItemRecord(name: "OLDAGENT", directory: "/Library/StartupItems/OLDAGENT",
                                                 script: nil, description: "Old agent", provides: ["OLDAGENT"], hasParameters: true)]
        legacy.hooks = [LoginHookRecord(kind: "LoginHook", script: "/usr/local/bin/gone-hook.sh",
                                        source: "/Library/Preferences/com.apple.loginwindow.plist", domain: .system)]
        let plugins = [PluginBundleRecord(kind: "authorization", path: "/Library/Security/SecurityAgentPlugins/VendorAuth.bundle",
                                          name: "VendorAuth", bundleIdentifier: "com.vendor.auth", version: "2.0",
                                          domain: .system, wiredIntoLogin: false),
                       PluginBundleRecord(kind: "prefpane", path: "/Users/alice/Library/PreferencePanes/Tool.prefPane",
                                          name: "Tool", domain: .user)]
        let items = correlate(.init(jobs: [], launchd: [], btm: [], disabled: [:], uid: 501, legacy: legacy, plugins: plugins))
        let startup = try XCTUnwrap(items.first { $0.key == "startupitem:OLDAGENT" })
        XCTAssertEqual(startup.category, .legacy)
        XCTAssertTrue(startup.orphaned)
        XCTAssertEqual(startup.orphanConfidence, .medium)
        XCTAssertTrue(startup.control?.reason.contains("OS X 10.10") == true)
        let hook = try XCTUnwrap(items.first { $0.key == "hook:LoginHook:system" })
        XCTAssertTrue(hook.orphaned, "hook script missing → executable missing")
        XCTAssertTrue(hook.control?.reason.contains("defaults delete /Library/Preferences/com.apple.loginwindow.plist LoginHook") == true,
                      hook.control?.reason ?? "-")
        let auth = try XCTUnwrap(items.first { $0.key == "plugin:authorization:VendorAuth" })
        XCTAssertEqual(auth.category, .pluginDirectories)
        XCTAssertFalse(auth.loaded)
        XCTAssertEqual(auth.metadata["auth-login-mechanism"], "not referenced by system.login.console")
        XCTAssertEqual(auth.control?.level, .displayOnly)
        XCTAssertFalse(auth.orphaned, "unreferenced is a fact, not evidence of a leftover")
        let pane = try XCTUnwrap(items.first { $0.key == "plugin:prefpane:Tool" })
        XCTAssertEqual(pane.domain, .user)
        XCTAssertEqual(pane.launchdDomainKind, .gui)
    }
}

final class ScheduledStageTests: XCTestCase {
    func testStagesReportChecksAndIncompleteness() throws {
        let root = tempRoot("stage")
        defer { try? FileManager.default.removeItem(atPath: root) }
        try FileManager.default.createDirectory(atPath: root + "/Library/LaunchAgents", withIntermediateDirectories: true)
        let runner = ScriptedCommandRunner(responses: [
            "/bin/launchctl print gui/501": CommandResult(exitCode: 0, stdout: "gui/501 = {\nservices = {\n}\n}\n", stderr: ""),
            "/bin/launchctl print-disabled gui/501": CommandResult(exitCode: 0, stdout: "", stderr: ""),
            "/usr/bin/crontab -l": CommandResult(exitCode: 1, stdout: "", stderr: "crontab: no crontab for alice\n"),
            "/usr/bin/atq": CommandResult(exitCode: 0, stdout: "", stderr: ""),
            // pmset not scripted → exit 127 → incomplete
        ])
        let options = ScanOptions(includeUser: true, includeSystem: false, scanBTM: false, scanSignatures: false,
                                  scanExtensions: false, scanSystemExtensions: false, scanHelpers: false,
                                  scanScheduled: true, scanLegacy: false, scanPlugins: false, scanShell: false, scanNetwork: false, scanReceipts: false)
        let report = ScanCoordinator(environment: ScanEnvironment(runner: runner, home: root, uid: 501)).perform(options: options)
        XCTAssertEqual(report.incompleteLayers, ["pmset"])
        XCTAssertTrue(report.checks.contains { $0.hasPrefix("pmset sched: FAILED") }, "\(report.checks)")
        XCTAssertTrue(report.checks.contains("legacy: skipped"))
        XCTAssertTrue(report.checks.contains("plugin directories: skipped"))
    }
}
