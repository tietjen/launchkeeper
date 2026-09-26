import XCTest
@testable import LaunchKeeperKit

// V0.8.2: leftovers of gone apps. Hermetic: a temp tree plays "/", the home
// is the logical /Users/alice inside it, presence sources are injected.

final class CleanupAppLeftoverTests: XCTestCase {
    private var root = ""
    private var quarantine = ""
    private let home = "/Users/alice"

    override func setUpWithError() throws {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("lk-apps-\(UUID().uuidString)", isDirectory: true).path
        root = base + "/root"
        quarantine = base + "/quarantine"
        try FileManager.default.createDirectory(atPath: root + home + "/Library", withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(atPath: (root as NSString).deletingLastPathComponent)
    }

    private func write(_ path: String, _ content: String = "x") {
        try? FileManager.default.createDirectory(atPath: ((root + path) as NSString).deletingLastPathComponent,
                                                 withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: root + path, contents: Data(content.utf8))
    }

    private func prefs(_ path: String, _ dict: [String: Any]) {
        let data = try! PropertyListSerialization.data(fromPropertyList: dict, format: .binary, options: 0)
        write(path, "")
        FileManager.default.createFile(atPath: root + path, contents: data)
    }

    private func sources(installed: Set<String> = [], ls: [String: String] = [:],
                         spotlight: Bool? = false) -> AppPresenceSources {
        AppPresenceSources(installed: installed, launchServices: { ls[$0] }, spotlight: { _ in spotlight })
    }

    private func engine(_ runner: FakeInstaller) -> CleanupEngine {
        CleanupEngine(environment: CleanupEnvironment(runner: runner, disk: DiskView(rootPrefix: root), home: home,
                                                      quarantineRoot: quarantine),
                      audit: AuditLog(directory: quarantine + "-logs"))
    }

    private func gone(_ id: String) {
        prefs(home + "/Library/Preferences/\(id).plist", ["NSWindow Frame Main": "0 0 100 100"])
        write(home + "/Library/Caches/\(id)/cache.db")
        write(home + "/Library/Saved Application State/\(id).savedState/data.data")
    }

    func testBundleIdSyntaxAndHardExclusions() {
        XCTAssertTrue(AppLeftoverLocations.isBundleIdentifier("org.vim.MacVim"))
        XCTAssertFalse(AppLeftoverLocations.isBundleIdentifier("Google"))
        XCTAssertFalse(AppLeftoverLocations.isBundleIdentifier("com.vendor"))
        for excluded in ["org.cups.printers", "systemgroup.com.apple.x.y", "group.com.vendor.shared",
                         "MN5S649TXM.ZitiPacketTunnel.group", "warp.log.old.0", "main.kts.compiled.cache",
                         "org.sparkle-project.Sparkle.Autoupdate", "com.apple.Safari"] {
            XCTAssertTrue(AppLeftoverLocations.isExcluded(excluded), excluded)
        }
        XCTAssertFalse(AppLeftoverLocations.isExcluded("org.vim.MacVim"))
    }

    func testPresenceRules() {
        let s = sources(installed: ["com.vendor.App", "com.utm.UTM"], ls: ["org.ls.Known": "/Apps/Known.app"])
        XCTAssertEqual(s.presence(of: "com.vendor.app").label, "present", "case-insensitive like LaunchServices")
        XCTAssertEqual(s.presence(of: "com.vendor.App.helper").label, "present")
        XCTAssertEqual(s.presence(of: "com.utm.QEMUHelper").label, "unknown", "same vendor still installed")
        XCTAssertEqual(s.presence(of: "org.ls.Known").label, "present")
        XCTAssertEqual(s.presence(of: "org.gone.App").label, "gone")
        XCTAssertEqual(sources(spotlight: nil).presence(of: "org.gone.App").label, "unknown",
                       "Spotlight silent = no verdict")
        XCTAssertEqual(sources(spotlight: true).presence(of: "org.gone.App").label, "present")
    }

    func testScanNeedsAppEvidenceAndGroupsByBundleId() {
        gone("org.vim.MacVim")
        write(home + "/Library/Caches/org.swift.swiftpm/manifest.db")                 // a CLI tool
        prefs(home + "/Library/Preferences/org.tool.cli.plist", ["lastRun": 1])      // no GUI keys
        write(home + "/Library/Containers/com.vendor.sandboxed/Data/x")
        write(home + "/Library/Logs/warp.log.old.0")
        prefs("/Library/Preferences/org.cups.printers.plist", ["NSWindow Frame X": "y"])
        let candidates = AppLeftoverScanner(disk: DiskView(rootPrefix: root), home: home).scan(sources: sources())
        func verdict(_ id: String) -> String? { candidates.first { $0.bundleIdentifier == id }?.presence.label }
        XCTAssertEqual(verdict("org.vim.MacVim"), "gone")
        XCTAssertEqual(candidates.first { $0.bundleIdentifier == "org.vim.MacVim" }?.paths.count, 3)
        XCTAssertEqual(verdict("com.vendor.sandboxed"), "gone", "a sandbox container is proof enough")
        XCTAssertEqual(verdict("org.swift.swiftpm"), "no-app-evidence")
        XCTAssertEqual(verdict("org.tool.cli"), "no-app-evidence")
        XCTAssertNil(verdict("warp.log.old.0"))
        XCTAssertNil(verdict("org.cups.printers"), "the system's printer setup is never a candidate")
    }

    func testRemoveMovesEveryPathAndRestoreBringsThemBack() throws {
        gone("org.vim.MacVim")
        prefs("/Library/Preferences/org.vim.MacVim.plist", ["k": "v"])
        let fake = FakeInstaller(root: root)
        let dry = engine(fake).removeAppLeftovers(bundleIdentifier: "org.vim.MacVim", sources: sources(), apply: false)
        XCTAssertEqual(dry.status, .planned, "\(dry.messages)")
        XCTAssertEqual(dry.plan.filter { $0.command == "/usr/bin/sudo" }.count, 2, "only /Library needs root")
        XCTAssertTrue(fake.log.isEmpty, "dry-run runs nothing")

        let moved = engine(fake).removeAppLeftovers(bundleIdentifier: "org.vim.MacVim", sources: sources(), apply: true)
        XCTAssertEqual(moved.status, .appliedOk, "\(moved.messages)")
        XCTAssertFalse(FileManager.default.fileExists(atPath: root + home + "/Library/Caches/org.vim.MacVim"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: root + "/Library/Preferences/org.vim.MacVim.plist"))
        let name = try XCTUnwrap(moved.quarantine)
        let back = engine(fake).restore(name: name, apply: true)
        XCTAssertEqual(back.status, .appliedOk, "\(back.messages)")
        // V0.9.5: home paths go back as the user, /Library via sudo.
        let sudoTargets = back.plan.filter { $0.command == "/usr/bin/sudo" }.flatMap(\.arguments)
        XCTAssertTrue(sudoTargets.contains { $0.hasSuffix("/Library/Preferences/org.vim.MacVim.plist") })
        XCTAssertFalse(sudoTargets.contains { $0.contains(home + "/Library/Caches") }, "\(back.plan.map(\.display))")
        XCTAssertTrue(FileManager.default.fileExists(
            atPath: root + home + "/Library/Saved Application State/org.vim.MacVim.savedState/data.data"))
    }

    func testRefusals() {
        gone("com.vendor.App")
        write(home + "/Library/Caches/org.swift.swiftpm/x")
        let fake = FakeInstaller(root: root)
        let installed = engine(fake).removeAppLeftovers(bundleIdentifier: "com.vendor.App",
                                                        sources: sources(installed: ["com.vendor.App"]), apply: true)
        guard case .refused(let reason) = installed.status else { return XCTFail("\(installed.status)") }
        XCTAssertTrue(reason.contains("app present"), reason)
        let tool = engine(fake).removeAppLeftovers(bundleIdentifier: "org.swift.swiftpm", sources: sources(), apply: true)
        guard case .refused(let why) = tool.status else { return XCTFail("\(tool.status)") }
        XCTAssertTrue(why.contains("no sign it was an app"), why)
        for bad in ["Google", "com.apple.Safari", "../x.y.z", "org.cups.printers"] {
            guard case .refused = engine(fake).removeAppLeftovers(bundleIdentifier: bad, sources: sources(),
                                                                  apply: true).status else { return XCTFail(bad) }
        }
        XCTAssertTrue(fake.mutations.isEmpty && !fake.log.contains { $0.hasPrefix("/bin/mv") })
    }
}
