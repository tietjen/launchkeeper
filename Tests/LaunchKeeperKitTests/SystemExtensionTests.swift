import XCTest
@testable import LaunchKeeperKit

// V0.5.5: system extensions, kexts and privileged helper tools. Hermetic:
// scripted runner, temp directory trees, anonymized fixture.

private func tempRoot(_ tag: String) -> String {
    FileManager.default.temporaryDirectory
        .appendingPathComponent("lk-sysext-\(tag)-\(UUID().uuidString)", isDirectory: true).path
}

private let sysextText = """
2 extension(s)
--- com.apple.system_extension.network_extension (Go to 'System Settings > General > Login Items & Extensions > Network Extensions' to modify these system extension(s))
enabled\tactive\tteamID\tbundleID (version)\tname\t[state]
*\t*\tABCDE12345\tcom.example.filter (4.3.1/4.3.1)\tFilter\t[activated enabled]
--- com.apple.system_extension.endpoint_security (Go to 'System Settings > General > Login Items & Extensions > Endpoint Security Extensions' to modify these system extension(s))
enabled\tactive\tteamID\tbundleID (version)\tname\t[state]
\t*\tFGHIJ67890\tcom.example.gone.es (1.0/1)\tGone ES\t[activated waiting for user]
garbage line without tabs
"""

private let kmutilText = """
No variant specified, falling back to release
    3  235 0                  0          0          com.apple.kpi.bsd (27.0.0) D46FC75B-A889-3796-A66C-D28FDD50FB68 <>
  180    0 0xfffffe0011000000 0x8000     0x8000     com.example.driver.fake (2.1.0) 11111111-2222-3333-4444-555555555555 <5 4 3>
"""

private let helperPlist = """
{
\t"CFBundleIdentifier" = "com.example.helper";
\t"SMAuthorizedClients" = (
\t\t"identifier "com.example.app" and anchor apple generic and certificate leaf[subject.OU] = "ABCDE12345"";
\t\t"identifier "com.example.app.agent" and anchor apple generic";
\t\t"identifier "com.example.app" and anchor apple generic";
\t);
\t"CFBundleName" = "com.example.helper";
\t"CFBundleVersion" = "1.2.6";
};
"""

final class SystemExtensionParserTests: XCTestCase {
    func testSyntheticSections() {
        let (records, warnings) = SystemExtensionParser.parse(sysextText)
        XCTAssertEqual(records.count, 2)
        XCTAssertEqual(records[0].kind, "network_extension")
        XCTAssertEqual(records[0].pane, "Network Extensions")
        XCTAssertEqual(records[0].enabled, true)
        XCTAssertEqual(records[0].active, true)
        XCTAssertEqual(records[0].teamIdentifier, "ABCDE12345")
        XCTAssertEqual(records[0].bundleIdentifier, "com.example.filter")
        XCTAssertEqual(records[0].version, "4.3.1/4.3.1")
        XCTAssertEqual(records[0].name, "Filter")
        XCTAssertEqual(records[0].state, "[activated enabled]")
        XCTAssertEqual(records[1].kind, "endpoint_security")
        XCTAssertEqual(records[1].enabled, false, "empty enabled column")
        XCTAssertEqual(records[1].state, "[activated waiting for user]")
        XCTAssertEqual(warnings.count, 1, "\(warnings)")
    }

    func testFixture() {
        let (records, warnings) = SystemExtensionParser.parse(Fixtures.text("systemextensionsctl.txt"))
        XCTAssertEqual(records.count, 3)
        XCTAssertTrue(warnings.isEmpty, "\(warnings)")
        XCTAssertEqual(Set(records.map(\.kind)), ["network_extension", "driver_extension", "cmio"])
        XCTAssertEqual(records.filter { $0.enabled }.count, 2)
        XCTAssertTrue(records.allSatisfy { $0.teamIdentifier?.count == 10 })
    }

    func testKmutilKeepsOnlyThirdPartyKexts() {
        let kexts = KernelExtensionParser.parseLoaded(kmutilText)
        XCTAssertEqual(kexts.map(\.bundleIdentifier), ["com.example.driver.fake"])
        XCTAssertEqual(kexts[0].version, "2.1.0")
        XCTAssertTrue(kexts[0].loaded)
    }

    func testEmbeddedInfoPlist() {
        let parsed = EmbeddedInfoPlistParser.parse(helperPlist)
        XCTAssertEqual(parsed.bundleIdentifier, "com.example.helper")
        XCTAssertEqual(parsed.version, "1.2.6")
        XCTAssertEqual(parsed.clients, ["com.example.app", "com.example.app.agent"], "deduplicated, in order")
    }
}

final class SystemExtensionScannerTests: XCTestCase {
    func testInstalledCopyHostAppAndKexts() throws {
        let root = tempRoot("scan")
        defer { try? FileManager.default.removeItem(atPath: root) }
        let fm = FileManager.default
        let extRoot = root + "/Library/SystemExtensions"
        try fm.createDirectory(atPath: extRoot + "/UUID-1/com.example.filter.systemextension", withIntermediateDirectories: true)
        try fm.createDirectory(atPath: extRoot + "/.staging", withIntermediateDirectories: true)
        let apps = root + "/Applications"
        try fm.createDirectory(atPath: apps + "/Example.app/Contents/Library/SystemExtensions/com.example.filter.systemextension",
                               withIntermediateDirectories: true)
        let kextDir = root + "/Library/Extensions"
        try fm.createDirectory(atPath: kextDir + "/Fake.kext/Contents", withIntermediateDirectories: true)
        let info: [String: Any] = ["CFBundleIdentifier": "com.example.driver.installed", "CFBundleShortVersionString": "3.0"]
        try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0)
            .write(to: URL(fileURLWithPath: kextDir + "/Fake.kext/Contents/Info.plist"))

        let runner = ScriptedCommandRunner(responses: [
            "/usr/bin/systemextensionsctl list": CommandResult(exitCode: 0, stdout: sysextText, stderr: ""),
            "/usr/bin/kmutil showloaded --list-only": CommandResult(exitCode: 0, stdout: kmutilText, stderr: ""),
            "/usr/bin/mdfind kMDItemCFBundleIdentifier == 'com.example.gone.es'": CommandResult(exitCode: 0, stdout: "", stderr: ""),
        ])
        let scanner = SystemExtensionScanner(runner: runner, home: root, extensionsRoot: extRoot,
                                             legacyKextDirectory: kextDir, applicationDirectories: [apps])
        let result = scanner.scan()
        XCTAssertTrue(result.failed.isEmpty, "\(result.warnings)")
        let filter = try XCTUnwrap(result.extensions.first { $0.bundleIdentifier == "com.example.filter" })
        XCTAssertEqual(filter.installedPath, extRoot + "/UUID-1/com.example.filter.systemextension")
        XCTAssertEqual(filter.hostAppPath, apps + "/Example.app")
        let gone = try XCTUnwrap(result.extensions.first { $0.bundleIdentifier == "com.example.gone.es" })
        XCTAssertNil(gone.installedPath)
        XCTAssertNil(gone.hostAppPath, "not in /Applications, Spotlight empty")
        XCTAssertEqual(result.kexts.map(\.bundleIdentifier).sorted(), ["com.example.driver.fake", "com.example.driver.installed"])
        XCTAssertEqual(result.kexts.first { $0.bundleIdentifier == "com.example.driver.installed" }?.loaded, false)
        XCTAssertEqual(result.kexts.first { $0.bundleIdentifier == "com.example.driver.installed" }?.path, kextDir + "/Fake.kext")
    }

    func testListFailureIsReportedAsIncomplete() {
        let runner = ScriptedCommandRunner(responses: [
            "/usr/bin/kmutil showloaded --list-only": CommandResult(exitCode: 0, stdout: "", stderr: ""),
        ])
        let root = tempRoot("fail")
        let result = SystemExtensionScanner(runner: runner, home: root, extensionsRoot: root + "/none",
                                            legacyKextDirectory: root + "/none", applicationDirectories: []).scan()
        XCTAssertEqual(result.failed, ["systemextensionsctl"])
        XCTAssertTrue(result.warnings.contains { $0.contains("system extensions not scanned") })
    }
}

final class PrivilegedHelperScannerTests: XCTestCase {
    func testHelpersWithAndWithoutInfoPlist() throws {
        let root = tempRoot("helpers")
        defer { try? FileManager.default.removeItem(atPath: root) }
        let dir = root + "/PrivilegedHelperTools"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        try Data("bin".utf8).write(to: URL(fileURLWithPath: dir + "/com.example.helper"))
        try Data("bin".utf8).write(to: URL(fileURLWithPath: dir + "/com.example.bare"))
        try Data("x".utf8).write(to: URL(fileURLWithPath: dir + "/.DS_Store"))
        let runner = ScriptedCommandRunner(responses: [
            "/bin/launchctl plist __TEXT,__info_plist \(dir)/com.example.helper": CommandResult(exitCode: 0, stdout: helperPlist, stderr: ""),
            "/bin/launchctl plist __TEXT,__info_plist \(dir)/com.example.bare": CommandResult(exitCode: 1, stdout: "", stderr: "no such section"),
            "/usr/bin/mdfind kMDItemCFBundleIdentifier == 'com.example.app'": CommandResult(exitCode: 0, stdout: "/Applications/Example.app\n", stderr: ""),
        ])
        let result = PrivilegedHelperScanner(runner: runner, directory: dir).scan()
        XCTAssertEqual(result.helpers.map(\.name), ["com.example.bare", "com.example.helper"])
        let helper = result.helpers[1]
        XCTAssertEqual(helper.bundleIdentifier, "com.example.helper")
        XCTAssertEqual(helper.authorizedClients, ["com.example.app", "com.example.app.agent"])
        XCTAssertEqual(helper.clientAppPath, "/Applications/Example.app")
        XCTAssertFalse(result.helpers[0].hasInfoPlist)
        XCTAssertTrue(result.checks[0].contains("2 in"), result.checks[0])
        XCTAssertTrue(result.checks[0].contains("1 without embedded Info.plist"), result.checks[0])
    }

    func testAbsentDirectoryIsNotAFailure() {
        let result = PrivilegedHelperScanner(runner: ScriptedCommandRunner(), directory: tempRoot("absent")).scan()
        XCTAssertTrue(result.helpers.isEmpty && result.failed.isEmpty)
    }
}

final class SystemExtensionCorrelationTests: XCTestCase {
    private func correlate(_ input: ItemCorrelator.Input) -> [BackgroundItem] {
        var items = ItemCorrelator().correlate(input).items
        OrphanDetector().apply(to: &items)
        ControlAnalyzer(launchDirs: ["/Library/LaunchDaemons"]).apply(to: &items)
        return items
    }

    func testHelperMergesWithItsSMJobBlessDaemon() throws {
        // The helper binary exists (else the daemon is an orphan for a reason of its own).
        let root = tempRoot("merge")
        defer { try? FileManager.default.removeItem(atPath: root) }
        try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
        let binary = root + "/com.example.helper"
        try Data("bin".utf8).write(to: URL(fileURLWithPath: binary))
        let daemon = LaunchJobRecord(label: "com.example.helper", path: "/Library/LaunchDaemons/com.example.helper.plist",
                                     domain: .system, kind: .launchDaemon,
                                     program: binary, arguments: [],
                                     runAtLoad: false, keepAlive: false, ownerName: "root", malformed: false)
        let helper = PrivilegedHelperRecord(path: binary,
                                            name: "com.example.helper", bundleIdentifier: "com.example.helper",
                                            version: "1.2.6", authorizedClients: ["com.example.app"],
                                            hasInfoPlist: true, clientAppPath: "/Applications/Example.app")
        let items = correlate(.init(jobs: [daemon], launchd: [], btm: [], disabled: [:], uid: 501, helpers: [helper]))
        XCTAssertEqual(items.count, 1, "\(items.map(\.key))")
        let item = items[0]
        XCTAssertEqual(item.category, .privilegedHelpers)
        XCTAssertEqual(item.type, .launchDaemon, "the daemon item keeps its launchd nature")
        XCTAssertEqual(item.sources.map(\.kind), [.plist, .helperTool])
        XCTAssertEqual(item.parentApplication, "Example")
        XCTAssertEqual(item.metadata["helper-clients"], "com.example.app")
        XCTAssertEqual(item.control?.level, .reversible, "a daemon-backed helper keeps launchd control")
        XCTAssertFalse(item.orphaned)
    }

    func testHelperWithoutDaemonIsALeftover() throws {
        let helper = PrivilegedHelperRecord(path: "/Library/PrivilegedHelperTools/com.example.stale",
                                            name: "com.example.stale", bundleIdentifier: "com.example.stale",
                                            authorizedClients: ["com.example.goneapp"], hasInfoPlist: true,
                                            clientAppPath: nil)
        let items = correlate(.init(jobs: [], launchd: [], btm: [], disabled: [:], uid: 501, helpers: [helper]))
        let item = try XCTUnwrap(items.first { $0.key == "helper:com.example.stale" })
        XCTAssertEqual(item.type, .privilegedHelper)
        XCTAssertEqual(item.launchdDomainKind, .system)
        XCTAssertTrue(item.orphaned)
        XCTAssertTrue(item.orphanReasons.contains { $0.contains("without a LaunchDaemon") }, "\(item.orphanReasons)")
        XCTAssertFalse(item.orphanReasons.contains("parent application bundle missing"),
                       "a Spotlight miss is not evidence: \(item.orphanReasons)")
        XCTAssertNil(item.appPresent)
        XCTAssertEqual(item.parentApplication, "com.example.goneapp", "named for display")
        XCTAssertEqual(item.metadata["helper-client-app"], "not found via Spotlight")
        XCTAssertEqual(item.control?.level, .displayOnly)
        XCTAssertTrue(item.control?.reason.contains("V0.8") == true)
    }

    func testSystemExtensionsAndKextsBecomeItems() throws {
        let ext = SystemExtensionRecord(kind: "network_extension", pane: "Network Extensions", enabled: true, active: true,
                                        teamIdentifier: "ABCDE12345", bundleIdentifier: "com.example.filter",
                                        version: "4.3.1/4.3.1", name: "Filter", state: "[activated enabled]",
                                        installedPath: "/Library/SystemExtensions/U/com.example.filter.systemextension",
                                        hostAppPath: "/Applications/Example.app")
        let gone = SystemExtensionRecord(kind: "endpoint_security", enabled: false, active: true,
                                         bundleIdentifier: "com.example.gone.es", name: "Gone", state: "[activated waiting for user]")
        let kext = KernelExtensionRecord(bundleIdentifier: "com.example.driver", version: "3.0", loaded: false,
                                         path: "/Library/Extensions/Fake.kext")
        let items = correlate(.init(jobs: [], launchd: [], btm: [], disabled: [:], uid: 501,
                                    systemExtensions: [ext, gone], kexts: [kext]))
        let filter = try XCTUnwrap(items.first { $0.key == "sysext:com.example.filter" })
        XCTAssertEqual(filter.category, .systemExtensions)
        XCTAssertEqual(filter.parentApplication, "Example")
        XCTAssertTrue(filter.running && filter.enabled)
        XCTAssertEqual(filter.control?.level, .displayOnly)
        XCTAssertTrue(filter.control?.reason.contains("systemextensionsctl uninstall ABCDE12345 com.example.filter") == true,
                      filter.control?.reason ?? "-")
        XCTAssertTrue(filter.control?.reason.contains("Network Extensions") == true)
        XCTAssertFalse(filter.orphaned)
        let lost = try XCTUnwrap(items.first { $0.key == "sysext:com.example.gone.es" })
        XCTAssertTrue(lost.orphaned)
        XCTAssertTrue(lost.orphanReasons.contains { $0.contains("host app not found") }, "\(lost.orphanReasons)")
        XCTAssertEqual(lost.orphanConfidence, .medium)
        let driver = try XCTUnwrap(items.first { $0.key == "kext:com.example.driver" })
        XCTAssertEqual(driver.type, .kernelExtension)
        XCTAssertFalse(driver.loaded)
        XCTAssertEqual(driver.control?.level, .displayOnly)
    }
}

final class SystemExtensionStageTests: XCTestCase {
    func testStagesReportChecksAndIncompleteness() throws {
        let root = tempRoot("stage")
        defer { try? FileManager.default.removeItem(atPath: root) }
        try FileManager.default.createDirectory(atPath: root + "/Library/LaunchAgents", withIntermediateDirectories: true)
        let runner = ScriptedCommandRunner(responses: [
            "/bin/launchctl print gui/501": CommandResult(exitCode: 0, stdout: "gui/501 = {\nservices = {\n}\n}\n", stderr: ""),
            "/bin/launchctl print-disabled gui/501": CommandResult(exitCode: 0, stdout: "", stderr: ""),
            "/usr/bin/kmutil showloaded --list-only": CommandResult(exitCode: 0, stdout: "", stderr: ""),
            // systemextensionsctl not scripted → exit 127 → incomplete
        ])
        let options = ScanOptions(includeUser: true, includeSystem: false, scanBTM: false, scanSignatures: false,
                                  scanExtensions: false, scanSystemExtensions: true, scanHelpers: false, scanScheduled: false, scanLegacy: false, scanPlugins: false, scanShell: false, scanNetwork: false)
        let report = ScanCoordinator(environment: ScanEnvironment(runner: runner, home: root, uid: 501)).perform(options: options)
        XCTAssertEqual(report.incompleteLayers, ["systemextensionsctl"])
        XCTAssertTrue(report.checks.contains { $0.hasPrefix("systemextensionsctl list: FAILED") }, "\(report.checks)")
        XCTAssertTrue(report.checks.contains { $0.hasPrefix("kmutil showloaded: ok") }, "\(report.checks)")
        XCTAssertTrue(report.checks.contains("privileged helpers: skipped"))
    }
}
