import XCTest
@testable import LaunchKeeperKit

// V0.9.1: `--root` — inventory another system from its files. Every path is
// read below the root, every user home there is scanned, and no tool that
// describes the live machine runs.

final class OfflineRootTests: XCTestCase {
    private var root = ""

    /// Records what reaches the real runner; answers codesign with "unsigned".
    final class RecordingRunner: CommandRunner {
        var calls: [String] = []
        func run(command: String, arguments: [String], timeout: TimeInterval) -> CommandResult {
            calls.append(([command] + arguments).joined(separator: " "))
            return CommandResult(exitCode: 1, stdout: "", stderr: "code object is not signed at all")
        }
    }

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("lk-offline-\(UUID().uuidString)").path
        func plist(_ path: String, label: String, program: String) throws {
            try FileManager.default.createDirectory(atPath: ((root + path) as NSString).deletingLastPathComponent,
                                                    withIntermediateDirectories: true)
            let dict: [String: Any] = ["Label": label, "ProgramArguments": [program], "RunAtLoad": true]
            let data = try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
            FileManager.default.createFile(atPath: root + path, contents: data)
        }
        func file(_ path: String, _ text: String = "x") throws {
            try FileManager.default.createDirectory(atPath: ((root + path) as NSString).deletingLastPathComponent,
                                                    withIntermediateDirectories: true)
            FileManager.default.createFile(atPath: root + path, contents: Data(text.utf8))
        }
        try plist("/Library/LaunchDaemons/com.vendor.daemon.plist", label: "com.vendor.daemon",
                  program: "/Library/Vendor/bin/daemon")
        try file("/Library/Vendor/bin/daemon")
        try plist("/Users/alice/Library/LaunchAgents/com.vendor.gone.plist", label: "com.vendor.gone",
                  program: "/Applications/Gone.app/Contents/MacOS/gone")
        try plist("/Users/bob/Library/LaunchAgents/com.vendor.tool.plist", label: "com.vendor.tool",
                  program: "/Applications/Tool.app/Contents/MacOS/tool")
        try file("/Applications/Tool.app/Contents/MacOS/tool")
        try file("/private/etc/paths.d/tool", "/opt/tool/bin\n")
        try file("/Users/alice/.zshrc", "export PATH=/opt/x:$PATH\n")
        try FileManager.default.createDirectory(atPath: root + "/Users/Shared", withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws { try? FileManager.default.removeItem(atPath: root) }

    private func scan(_ runner: RecordingRunner) -> ScanReport {
        ScanCoordinator(environment: ScanEnvironment(runner: runner, offlineRoot: root)).perform(options: ScanOptions())
    }

    func testEveryUserEveryPathBelowTheRoot() throws {
        let runner = RecordingRunner()
        let report = scan(runner)
        XCTAssertTrue(report.checks[0].contains("2 user home(s): /Users/alice, /Users/bob"), report.checks[0])
        let keys = Set(report.items.map(\.key))
        XCTAssertTrue(keys.isSuperset(of: ["com.vendor.daemon", "com.vendor.gone", "com.vendor.tool"]), "\(keys)")

        let gone = try XCTUnwrap(report.items.first { $0.key == "com.vendor.gone" })
        XCTAssertTrue(gone.orphaned, "the executable is missing BELOW THE ROOT")
        let tool = try XCTUnwrap(report.items.first { $0.key == "com.vendor.tool" })
        XCTAssertFalse(tool.orphaned, "present below the root — the live /Applications is irrelevant")
        XCTAssertEqual(tool.path, "/Users/bob/Library/LaunchAgents/com.vendor.tool.plist", "paths stay logical")
        let paths = try XCTUnwrap(report.items.first { $0.type == .pathEntry })
        XCTAssertTrue(paths.orphaned, "/opt/tool/bin is missing below the root (via /etc → /private/etc)")
        XCTAssertTrue(report.items.contains { $0.path == "/Users/alice/.zshrc" })
        XCTAssertTrue(report.items.allSatisfy { $0.control?.level == .displayOnly })
    }

    func testNoLiveToolRunsAndFileToolsGetMappedPaths() {
        let runner = RecordingRunner()
        _ = scan(runner)
        for call in runner.calls {
            XCTAssertTrue(call.hasPrefix("/usr/bin/codesign") || call.hasPrefix("/bin/launchctl plist"), call)
        }
        XCTAssertTrue(runner.calls.contains { $0.contains(root + "/Library/Vendor/bin/daemon") },
                      "codesign reads the file below the root: \(runner.calls)")
    }

    func testRunnerAllowlist() {
        XCTAssertTrue(OfflineRunner.allowed("/usr/bin/codesign", ["-dvvv", "/x"]))
        XCTAssertFalse(OfflineRunner.allowed("/usr/bin/codesign", ["--sign", "-", "/x"]))
        XCTAssertTrue(OfflineRunner.allowed("/bin/launchctl", ["plist", "__TEXT,__info_plist", "/x"]))
        for (command, args) in [("/bin/launchctl", ["print", "system"]), ("/usr/bin/sfltool", ["dumpbtm"]),
                                ("/usr/bin/pluginkit", ["-mAvv"]), ("/usr/sbin/pkgutil", ["--pkgs"]),
                                ("/usr/bin/mdfind", ["x"]), ("/usr/sbin/lsof", ["-i"])] {
            XCTAssertFalse(OfflineRunner.allowed(command, args), command)
        }
    }

    func testRootedFileManagerMapsAndFallsBackToPrivate() {
        let fm = RootedFileManager(root: root)
        XCTAssertEqual(fm.map("/Library/x"), root + "/Library/x")
        XCTAssertEqual(fm.map("/etc/paths.d/tool"), root + "/private/etc/paths.d/tool", "Data volume without /etc link")
        XCTAssertEqual(fm.map(root + "/already"), root + "/already")
        XCTAssertTrue(fm.fileExists(atPath: "/etc/paths.d/tool"))
        XCTAssertEqual(fm.homes(), ["/Users/alice", "/Users/bob"], "Shared is not a user")
    }
}
