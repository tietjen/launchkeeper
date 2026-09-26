import XCTest
@testable import LaunchKeeperKit

// V0.9.0: `watch` — the watcher logic with scripted scans (no FSEvents),
// and the filter that decides which file-system events set off a rescan.

final class InventoryWatcherTests: XCTestCase {
    private func item(_ key: String, enabled: Bool = true, path: String? = nil) -> BackgroundItem {
        BackgroundItem(key: key, displayName: key, type: .launchAgentUser, path: path ?? "/x/\(key).plist",
                       label: key, domain: .user, enabled: enabled)
    }

    private func watcher(_ reports: [ScanReport]) -> InventoryWatcher {
        var queue = reports
        return InventoryWatcher(now: { Date(timeIntervalSince1970: 1_790_000_000) }) {
            queue.isEmpty ? ScanReport(items: [], uncorrelated: [], warnings: []) : queue.removeFirst()
        }
    }

    private func report(_ items: [BackgroundItem], incomplete: [String] = []) -> ScanReport {
        ScanReport(items: items, uncorrelated: [], warnings: [], incompleteLayers: incomplete)
    }

    func testBaselineThenAddedRemovedChanged() {
        let w = watcher([
            report([item("com.vendor.a"), item("com.vendor.b")]),
            report([item("com.vendor.a", enabled: false), item("com.vendor.c")]),
        ])
        let first = w.tick(trigger: "start")
        XCTAssertEqual(first.map(\.kind), [.baseline])
        XCTAssertTrue(first[0].note?.hasPrefix("2 entries") == true)

        let second = w.tick(trigger: "fsevents: /Users/alice/Library/LaunchAgents/com.vendor.c.plist")
        XCTAssertEqual(second.map(\.kind), [.added, .removed, .changed])
        XCTAssertEqual(second[0].key, "com.vendor.c")
        XCTAssertEqual(second[1].key, "com.vendor.b")
        XCTAssertEqual(second[2].changes.map(\.field), ["enabled"])
        XCTAssertTrue(second[0].summary.hasPrefix("NEW launch-items: com.vendor.c"), second[0].summary)
        XCTAssertEqual(second[0].trigger, "fsevents: /Users/alice/Library/LaunchAgents/com.vendor.c.plist")
    }

    func testIncompleteScanIsSkippedAndKeepsTheBaseline() {
        let w = watcher([
            report([item("com.vendor.a")]),
            report([], incomplete: ["sfltool dumpbtm"]),     // BTM timed out: everything would look "removed"
            report([item("com.vendor.a")]),
        ])
        _ = w.tick(trigger: "start")
        let skipped = w.tick(trigger: "interval")
        XCTAssertEqual(skipped.map(\.kind), [.skipped])
        XCTAssertTrue(skipped[0].note?.contains("sfltool dumpbtm") == true)
        XCTAssertTrue(w.tick(trigger: "interval").isEmpty, "nothing changed against the kept baseline")
    }

    func testIncompleteFirstScanDoesNotBecomeTheBaseline() {
        let w = watcher([report([], incomplete: ["pluginkit"]), report([item("com.vendor.a")])])
        XCTAssertEqual(w.tick(trigger: "start").map(\.kind), [.skipped])
        XCTAssertEqual(w.tick(trigger: "interval").map(\.kind), [.baseline])
    }

    func testListeningProcessesAreRuntimeStateNotConfiguration() {
        let firefox = BackgroundItem(key: "net:/Applications/Firefox.app/Contents/MacOS/firefox",
                                     displayName: "firefox (pid 1)", type: .listener, category: .network)
        let config = watcher([report([]), report([firefox])])
        _ = config.tick(trigger: "start")
        XCTAssertTrue(config.tick(trigger: "interval").isEmpty, "live: NEW network: firefox was noise")

        var queue = [report([]), report([firefox])]
        let state = InventoryWatcher(includeState: true) { queue.removeFirst() }
        _ = state.tick(trigger: "start")
        XCTAssertEqual(state.tick(trigger: "interval").map(\.kind), [.added])
    }

    func testAppleInternalsAreHiddenUnlessAll() {
        var apple = item("com.apple.x")
        apple.path = "/System/Library/LaunchAgents/com.apple.x.plist"
        let quiet = watcher([report([]), report([apple])])
        _ = quiet.tick(trigger: "start")
        XCTAssertTrue(quiet.tick(trigger: "interval").isEmpty)
    }
}

final class WatchPathsTests: XCTestCase {
    private let paths = WatchPaths(home: "/Users/alice")

    func testDirectEntriesAndSingleFilesAreRelevant() {
        for relevant in ["/Users/alice/Library/LaunchAgents/com.x.plist", "/Library/LaunchDaemons/com.x.plist",
                         "/Library/PrivilegedHelperTools/com.x.helper", "/etc/paths.d/tool",
                         "/private/etc/paths.d/tool", "/Applications/New.app",
                         "/Users/alice/Library/Preferences/com.apple.loginwindow.plist", "/Users/alice/.zshrc",
                         "/Library/StartupItems"] {
            XCTAssertTrue(paths.isRelevant(relevant), relevant)
        }
    }

    func testNoiseIsIgnored() {
        for noise in ["/Applications/Busy.app/Contents/Resources/cache.db",
                      "/Users/alice/Library/Preferences/com.vendor.app.plist",
                      "/Library/Preferences/com.apple.TimeMachine.plist",
                      "/Library/LaunchDaemons/sub/dir/file", "/Users/alice/Documents/x"] {
            XCTAssertFalse(paths.isRelevant(noise), noise)
        }
    }

    func testStreamRootsCoverEveryWatchedFileParent() {
        let roots = Set(paths.streamRoots)
        for file in paths.files { XCTAssertTrue(roots.contains((file as NSString).deletingLastPathComponent), file) }
    }
}

final class BTMDumpCacheTests: XCTestCase {
    /// Counts sfltool calls; everything else answers empty.
    final class CountingRunner: CommandRunner {
        var dumps = 0
        func run(command: String, arguments: [String], timeout: TimeInterval) -> CommandResult {
            if command == "/usr/bin/sfltool" {
                dumps += 1
                return CommandResult(exitCode: 0, stdout: "", stderr: "")
            }
            if command == "/bin/launchctl" {
                return CommandResult(exitCode: 0, stdout: "x = {\nservices = {\n}\n}\n", stderr: "")
            }
            return CommandResult(exitCode: 0, stdout: "", stderr: "")
        }
    }

    func testFileTriggeredRescansReuseTheDumpIntervalRefreshes() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent("lk-btmcache-\(UUID().uuidString)").path
        try FileManager.default.createDirectory(atPath: home + "/Library/LaunchAgents", withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: home) }
        let runner = CountingRunner()
        let cache = BTMDumpCache()
        let options = ScanOptions(includeUser: true, includeSystem: false, scanBTM: true, scanSignatures: false,
                                  scanExtensions: false, scanSystemExtensions: false, scanHelpers: false,
                                  scanScheduled: false, scanLegacy: false, scanPlugins: false, scanShell: false,
                                  scanNetwork: false, scanReceipts: false)
        let coordinator = ScanCoordinator(environment: ScanEnvironment(runner: runner, home: home, uid: 501, btmCache: cache))
        _ = coordinator.perform(options: options)
        XCTAssertEqual(runner.dumps, 1)
        XCTAssertNotNil(cache.taken)

        cache.preferCached = true
        let reused = coordinator.perform(options: options)
        XCTAssertEqual(runner.dumps, 1, "a file-triggered rescan pays no second dump")
        XCTAssertTrue(reused.checks.contains { $0.hasPrefix("sfltool dumpbtm: reused from") }, "\(reused.checks)")

        cache.preferCached = false
        _ = coordinator.perform(options: options)
        XCTAssertEqual(runner.dumps, 2, "the interval refreshes")
    }
}
