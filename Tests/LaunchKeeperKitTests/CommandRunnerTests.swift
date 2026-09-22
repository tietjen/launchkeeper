import XCTest
@testable import LaunchKeeperKit

/// The ONE place where tests spawn a real process: the interactive seam
/// itself. Everything else stays behind test doubles. The child is always
/// /bin/sh or /bin/sleep — never sudo, never launchctl.
final class SystemCommandRunnerInteractiveTests: XCTestCase {
    private let runner = SystemCommandRunner()

    func testExitStatusPropagates() {
        XCTAssertEqual(runner.runInteractive(command: "/bin/sh", arguments: ["-c", "exit 3"], timeout: 10), 3)
        XCTAssertEqual(runner.runInteractive(command: "/bin/sh", arguments: ["-c", "exit 0"], timeout: 10), 0)
    }

    func testChildStaysInOurProcessGroup() {
        // Regression for the clear-text password prompt (V0.4.2): a child in
        // its own process group is a BACKGROUND job on the terminal and can
        // neither switch echo off nor read /dev/tty. It must share ours.
        let ours = String(getpgrp())
        let code = runner.runInteractive(
            command: "/bin/sh",
            arguments: ["-c", "[ \"$(ps -o pgid= -p $$ | tr -d ' ')\" = \"$1\" ]", "sh", ours],
            timeout: 10)
        XCTAssertEqual(code, 0, "child process group differs from ours (\(ours))")
    }

    func testTimeoutTerminatesAndReportsMinusTwo() {
        let started = Date()
        let code = runner.runInteractive(command: "/bin/sleep", arguments: ["30"], timeout: 0.3)
        XCTAssertEqual(code, -2)
        XCTAssertLessThan(Date().timeIntervalSince(started), 5, "the child must be reaped promptly")
    }

    func testSpawnFailureIsMinusOne() {
        XCTAssertEqual(runner.runInteractive(command: "/nonexistent/launchkeeper-no-such-binary",
                                             arguments: [], timeout: 5), -1)
    }

    func testSignaledChildMapsTo128PlusSignal() {
        XCTAssertEqual(runner.runInteractive(command: "/bin/sh", arguments: ["-c", "kill -9 $$"], timeout: 10), 137)
    }
}
