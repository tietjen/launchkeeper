import XCTest
@testable import LaunchKeeperKit

// V0.8.1: `remove` takes provable leftover files into the quarantine —
// privileged helpers no job starts, StartupItems, paths.d files whose every
// entry is gone. Hermetic: temp root as "/", FakeInstaller performs the moves.

final class CleanupLeftoverTests: XCTestCase {
    private var root = ""
    private var home = ""

    override func setUpWithError() throws {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("lk-leftover-\(UUID().uuidString)", isDirectory: true).path
        root = base + "/root"
        home = base + "/home"
        try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(atPath: (root as NSString).deletingLastPathComponent)
    }

    private func write(_ path: String, _ content: String) {
        try? FileManager.default.createDirectory(atPath: ((root + path) as NSString).deletingLastPathComponent,
                                                 withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: root + path, contents: Data(content.utf8))
    }

    private func engine(_ fake: FakeInstaller) -> CleanupEngine {
        CleanupEngine(environment: CleanupEnvironment(runner: fake, disk: DiskView(rootPrefix: root), home: home,
                                                      quarantineRoot: home + "/quarantine"),
                      audit: AuditLog(directory: home + "/logs"))
    }

    private func item(_ type: ItemType, _ path: String, orphaned: Bool = true) -> BackgroundItem {
        var item = BackgroundItem(key: "k:" + path, displayName: (path as NSString).lastPathComponent, type: type,
                                  path: path, domain: .system, orphaned: orphaned)
        item.orphanReasons = ["test"]
        return item
    }

    func testMechanismAndControlMatrix() {
        let helper = item(.privilegedHelper, "/Library/PrivilegedHelperTools/com.vendor.helper")
        XCTAssertEqual(helper.controlMechanism, .quarantine)
        let control = ControlAnalyzer(launchDirs: []).evaluate(helper)
        XCTAssertEqual(control.level, .removable)
        XCTAssertEqual(control.actions, ["remove"])
        XCTAssertEqual(control.mechanism, .quarantine)
        XCTAssertNotEqual(RemediationGate.evaluate(operation: .disable, item: helper), .allowed)

        var withJob = helper
        withJob.launchdPresent = true
        withJob.label = "com.vendor.helper"
        XCTAssertEqual(withJob.controlMechanism, .launchd, "a helper with its daemon is switched, not taken")

        let alive = item(.pathEntry, "/etc/paths.d/tool", orphaned: false)
        XCTAssertEqual(ControlAnalyzer(launchDirs: []).evaluate(alive).level, .displayOnly)
    }

    func testGateAllowsOnlyDirectEntriesOfTheThreeLocations() {
        XCTAssertEqual(RemediationGate.evaluate(operation: .remove,
                                                item: item(.startupItem, "/Library/StartupItems/OLD")), .allowed)
        XCTAssertEqual(RemediationGate.evaluate(operation: .remove,
                                                item: item(.pathEntry, "/private/etc/manpaths.d/tool")), .allowed)
        for bad in [item(.startupItem, "/Library/StartupItems/OLD/OLD"),
                    item(.privilegedHelper, "/Library/LaunchDaemons/x"),
                    item(.pathEntry, "/etc/paths.d/../hosts"),
                    item(.pathEntry, "/etc/paths.d/.hidden"),
                    item(.pathEntry, "/usr/libexec/paths.d/x")] {
            XCTAssertNotEqual(RemediationGate.evaluate(operation: .remove, item: bad), .allowed, bad.path ?? "")
        }
    }

    func testHelperStartupItemAndDeadPathsFileMoveAndComeBack() throws {
        let fake = FakeInstaller(root: root)
        write("/Library/PrivilegedHelperTools/com.vendor.helper", "bin")
        write("/Library/StartupItems/OLD/OLD", "#!/bin/sh")
        write("/Library/StartupItems/OLD/StartupParameters.plist", "<plist/>")
        write("/etc/paths.d/org.vendor.tool", "/Applications/Tool.app/Contents/Resources/bin\n")
        for leftover in [item(.privilegedHelper, "/Library/PrivilegedHelperTools/com.vendor.helper"),
                         item(.startupItem, "/Library/StartupItems/OLD"),
                         item(.pathEntry, "/etc/paths.d/org.vendor.tool")] {
            let dry = engine(fake).quarantineItem(leftover, apply: false)
            XCTAssertEqual(dry.status, .planned, "\(dry.messages)")
            XCTAssertTrue(FileManager.default.fileExists(atPath: root + leftover.path!), "dry-run moves nothing")

            let moved = engine(fake).quarantineItem(leftover, apply: true)
            XCTAssertEqual(moved.status, .appliedOk, "\(moved.messages)")
            XCTAssertFalse(FileManager.default.fileExists(atPath: root + leftover.path!))
            let name = try XCTUnwrap(moved.quarantine)
            XCTAssertEqual(moved.undoHint, "launchkeeper quarantine restore \(name)")

            let back = engine(fake).restore(name: name, apply: true)
            XCTAssertEqual(back.status, .appliedOk, "\(back.messages)")
            XCTAssertTrue(FileManager.default.fileExists(atPath: root + leftover.path!))
        }
        XCTAssertTrue(FileManager.default.fileExists(atPath: root + "/Library/StartupItems/OLD/StartupParameters.plist"),
                      "a StartupItem moves and returns as a whole folder")
    }

    func testPathsFileWithOneLiveEntryIsNotALeftover() {
        let fake = FakeInstaller(root: root)
        write("/opt/tool/bin/.keep", "")
        write("/etc/paths.d/mixed", "/Applications/Gone.app/bin\n/opt/tool/bin\n")
        let result = engine(fake).quarantineItem(item(.pathEntry, "/etc/paths.d/mixed"), apply: true)
        guard case .refused(let reason) = result.status else { return XCTFail("\(result.status)") }
        XCTAssertTrue(reason.contains("PATH entry exists"), reason)
        XCTAssertTrue(fake.mutations.isEmpty)
    }

    func testAppleClaimedOrWrongTypeIsRefused() {
        let fake = FakeInstaller(root: root)
        write("/Library/PrivilegedHelperTools/com.vendor.helper", "bin")
        fake.appleClaims = ["/Library/PrivilegedHelperTools/com.vendor.helper"]
        let apple = engine(fake).quarantineItem(item(.privilegedHelper, "/Library/PrivilegedHelperTools/com.vendor.helper"),
                                                apply: true)
        guard case .refused(let reason) = apple.status else { return XCTFail("\(apple.status)") }
        XCTAssertTrue(reason.contains("Apple"), reason)

        try? FileManager.default.createDirectory(atPath: root + "/Library/PrivilegedHelperTools/dir.helper",
                                                 withIntermediateDirectories: true)
        let dir = engine(fake).quarantineItem(item(.privilegedHelper, "/Library/PrivilegedHelperTools/dir.helper"),
                                              apply: true)
        guard case .refused = dir.status else { return XCTFail("a helper must be a file") }
        XCTAssertTrue(fake.mutations.isEmpty)
    }
}
