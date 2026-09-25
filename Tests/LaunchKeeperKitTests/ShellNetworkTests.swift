import XCTest
@testable import LaunchKeeperKit

// V0.5.7: shell startup files and network (listening sockets, firewall).

private func tempRoot(_ tag: String) -> String {
    FileManager.default.temporaryDirectory
        .appendingPathComponent("lk-v057-\(tag)-\(UUID().uuidString)", isDirectory: true).path
}

private let lsofTCP = """
p1065
crapportd
Ljti
f11
PTCP
n*:59368
f14
PTCP
n*:59368
p2528
cBeeper
Ljti
f111
PTCP
n127.0.0.1:23373
p88
cvendord
Lroot
f5
PTCP
n*:8443
"""

private let lsofUDP = """
p1065
crapportd
Ljti
f26
PUDP
n*:3722
p1089
cidentitys
Ljti
f7
PUDP
n*:*
p2827
cClaude Helper
Ljti
f40
PUDP
n10.0.22.5:52011->142.250.185.78:443
"""

private let psText = """
 1065 /usr/libexec/rapportd
 2528 /Applications/Beeper Desktop.app/Contents/MacOS/Beeper Desktop
   88 /Library/Vendor/bin/vendord
"""

private let firewallList = """
Total number of apps = 3 
1 : /usr/libexec/remoted 
             (Allow incoming connections)
2 : /Library/Vendor/bin/vendord 
             (Block incoming connections)
3 : /Applications/Other.app 
             (Allow incoming connections)
"""

final class ShellFileParserTests: XCTestCase {
    func testSourcesHintsAndNoLineLeaks() {
        let text = """
        # comment: source nothing
        export API_TOKEN=SECRET123
        source ~/.secrets.sh
        . "$HOME/.local/env"
        source ${HOME}/.cargo/env
        source $ZSH/oh-my-zsh.sh
        source relative.sh
        alias ollama:start='sudo launchctl load /Library/LaunchDaemons/ollama.plist'
        launchctl load ~/Library/LaunchAgents/com.vendor.plist
        nohup /opt/agent/run SECRET123 &
        make && make install
        curl -fsSL https://example.com/install.sh | bash
        eval "$(/opt/homebrew/bin/brew shellenv)"
        """
        let parsed = ShellFileParser.parse(text, home: "/Users/alice", baseDirectory: "/Users/alice")
        XCTAssertEqual(parsed.sourced, ["/Users/alice/.secrets.sh", "/Users/alice/.local/env",
                                        "/Users/alice/.cargo/env", "/Users/alice/relative.sh"])
        XCTAssertEqual(parsed.unresolved, ["$ZSH/oh-my-zsh.sh"])
        XCTAssertEqual(parsed.hints, ["line 9: launchctl", "line 10: nohup", "line 10: background job (&)",
                                      "line 12: curl|wget piped to a shell", "line 13: eval of a command substitution"],
                       "aliases and && are not hints")
        XCTAssertFalse(parsed.hints.joined().contains("SECRET"), "never a line's content")
    }
}

final class ShellStartupScannerTests: XCTestCase {
    func testProfilesSourcedFilesAndPaths() throws {
        let home = tempRoot("home")
        defer { try? FileManager.default.removeItem(atPath: home) }
        let fm = FileManager.default
        try fm.createDirectory(atPath: home + "/paths.d", withIntermediateDirectories: true)
        try "source ~/.extra.sh\nsource ~/.gone.sh\nlaunchctl load x\n".write(toFile: home + "/.zshrc", atomically: true, encoding: .utf8)
        try "export X=1\n".write(toFile: home + "/.extra.sh", atomically: true, encoding: .utf8)
        try "\(home)\n/nonexistent/bin\n/var/run/com.apple.security.cryptexd/codex.system/bootstrap/usr/bin\n"
            .write(toFile: home + "/paths.d/vendor", atomically: true, encoding: .utf8)
        let result = ShellStartupScanner(home: home, userFiles: [home + "/.zshrc", home + "/.bashrc"], systemFiles: [],
                                         pathsDirectories: [home + "/paths.d"]).scan()
        XCTAssertEqual(result.files.map(\.kind), ["profile", "sourced", "paths"], "\(result.files.map(\.path))")
        let zshrc = result.files[0]
        XCTAssertEqual(zshrc.missingSources, [home + "/.gone.sh"])
        XCTAssertEqual(zshrc.hints, ["line 3: launchctl"])
        XCTAssertNotNil(zshrc.modified)
        XCTAssertEqual(result.files[1].sourcedBy, home + "/.zshrc")
        XCTAssertEqual(result.files[2].missingSources, ["/nonexistent/bin"], "runtime mounts under /var/run are not missing")
        XCTAssertTrue(result.checks[0].hasPrefix("shell startup: 1 files, 1 sourced, 1 launch hints"), result.checks[0])
    }
}

final class NetworkParserTests: XCTestCase {
    func testLsofFieldsAndGrouping() {
        let sockets = LsofFieldParser.parse(lsofTCP) + LsofFieldParser.parse(lsofUDP)
        XCTAssertEqual(sockets.count, 5, "IPv4+IPv6 twins kept until grouping, *:* and connected sockets dropped")
        let processes = LsofFieldParser.group(sockets)
        XCTAssertEqual(processes.map(\.pid), [1065, 2528, 88])
        XCTAssertEqual(processes[0].sockets.map(\.address), ["*:59368", "*:3722"])
        XCTAssertEqual(processes[0].sockets.map(\.proto), ["tcp", "udp"])
        XCTAssertEqual(processes[1].sockets[0].port, 23373)
        XCTAssertTrue(processes[1].sockets[0].loopbackOnly)
        XCTAssertEqual(processes[2].user, "root")
    }

    func testFirewallList() {
        let rules = FirewallListParser.parse(firewallList)
        XCTAssertEqual(rules.map(\.path), ["/usr/libexec/remoted", "/Library/Vendor/bin/vendord", "/Applications/Other.app"])
        XCTAssertEqual(rules.map(\.action), ["allow", "block", "allow"])
    }
}

final class NetworkScannerTests: XCTestCase {
    private let fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"

    func testProcessesGetPathsAndFirewallState() {
        let runner = ScriptedCommandRunner(responses: [
            "/usr/sbin/lsof -nP -iTCP -sTCP:LISTEN -F pcLPn": CommandResult(exitCode: 0, stdout: lsofTCP, stderr: ""),
            "/usr/sbin/lsof -nP -iUDP -F pcLPn": CommandResult(exitCode: 1, stdout: "", stderr: ""),
            "/bin/ps -o pid=,comm= -p 1065,2528,88": CommandResult(exitCode: 0, stdout: psText, stderr: ""),
            "\(fw) --getglobalstate": CommandResult(exitCode: 0, stdout: "Firewall is disabled. (State = 0)\n", stderr: ""),
            "\(fw) --listapps": CommandResult(exitCode: 0, stdout: firewallList, stderr: ""),
        ])
        let result = NetworkScanner(runner: runner).scan()
        XCTAssertTrue(result.failed.isEmpty, "\(result.warnings)")
        XCTAssertEqual(result.processes.map(\.executable), ["/usr/libexec/rapportd",
                                                            "/Applications/Beeper Desktop.app/Contents/MacOS/Beeper Desktop",
                                                            "/Library/Vendor/bin/vendord"])
        XCTAssertEqual(result.firewallState, "disabled")
        XCTAssertEqual(result.firewall.count, 3)
        XCTAssertTrue(result.checks.contains("lsof: ok (3 listening processes, 3 sockets)"), "\(result.checks)")
    }

    func testLsofFailureIsIncomplete() {
        let runner = ScriptedCommandRunner(responses: [
            "\(fw) --getglobalstate": CommandResult(exitCode: 0, stdout: "Firewall is enabled. (State = 1)\n", stderr: ""),
            "\(fw) --listapps": CommandResult(exitCode: 0, stdout: "Total number of apps = 0\n", stderr: ""),
        ])
        let result = NetworkScanner(runner: runner).scan()
        XCTAssertEqual(result.failed, ["lsof"])
        XCTAssertEqual(result.firewallState, "enabled")
    }
}

final class ShellNetworkCorrelationTests: XCTestCase {
    private func correlate(_ input: ItemCorrelator.Input, home: String = "/Users/alice") -> [BackgroundItem] {
        var items = ItemCorrelator(home: home).correlate(input).items
        OrphanDetector().apply(to: &items)
        ControlAnalyzer(launchDirs: ["/Library/LaunchDaemons"]).apply(to: &items)
        return items
    }

    func testListenerLinksToItsEntryAndFirewallMerges() throws {
        let root = tempRoot("net")
        defer { try? FileManager.default.removeItem(atPath: root) }
        try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
        let binary = root + "/vendord"
        try Data("bin".utf8).write(to: URL(fileURLWithPath: binary))
        let daemon = LaunchJobRecord(label: "com.vendor.daemon", path: "/Library/LaunchDaemons/com.vendor.daemon.plist",
                                     domain: .system, kind: .launchDaemon, program: binary, arguments: [],
                                     runAtLoad: true, keepAlive: true, ownerName: "root", malformed: false)
        var network = NetworkScanner.Result()
        network.processes = [
            ListeningProcess(pid: 88, command: "vendord", user: "root", executable: binary,
                             sockets: [ListeningSocket(pid: 88, command: "vendord", user: "root", proto: "tcp", address: "*:8443")]),
            ListeningProcess(pid: 1065, command: "rapportd", user: "alice", executable: "/usr/libexec/rapportd",
                             sockets: [ListeningSocket(pid: 1065, command: "rapportd", user: "alice", proto: "tcp", address: "*:59368")]),
        ]
        network.firewall = [FirewallRule(path: binary, action: "block"), FirewallRule(path: "/Applications/Other.app", action: "allow")]
        // An app nothing in the inventory starts (app-level login items are
        // containers of the background view, not items): no entry, said so.
        network.processes.append(ListeningProcess(pid: 2528, command: "Beeper", user: "alice",
            executable: "/Applications/Beeper Desktop.app/Contents/MacOS/Beeper Desktop",
            sockets: [ListeningSocket(pid: 2528, command: "Beeper", user: "alice", proto: "tcp", address: "127.0.0.1:23373")]))
        let items = correlate(.init(jobs: [daemon], launchd: [], btm: [], disabled: [:], uid: 501, network: network))
        let app = try XCTUnwrap(items.first { $0.key == "net:/Applications/Beeper Desktop.app/Contents/MacOS/Beeper Desktop" })
        XCTAssertNil(app.metadata["network-entry"])
        XCTAssertEqual(app.metadata["listening"], "tcp/23373 (loopback)")
        XCTAssertTrue(app.control?.reason.contains("no inventory entry starts it") == true, app.control?.reason ?? "-")

        let listener = try XCTUnwrap(items.first { $0.key == "net:\(binary)" })
        XCTAssertEqual(listener.category, .network)
        XCTAssertEqual(listener.metadata["network-entry"], "com.vendor.daemon")
        XCTAssertEqual(listener.metadata["listening"], "tcp/8443")
        XCTAssertEqual(listener.metadata["firewall"], "block incoming connections", "rule merged into the process")
        XCTAssertEqual(listener.sources.map(\.kind), [.lsof, .firewall])
        XCTAssertTrue(listener.control?.reason.contains("control its entry `com.vendor.daemon`") == true, listener.control?.reason ?? "-")
        let entry = try XCTUnwrap(items.first { $0.key == "com.vendor.daemon" })
        XCTAssertEqual(entry.metadata["listening"], "tcp/8443", "the entry learns its ports")
        XCTAssertTrue(TableRenderer.flagsText(entry).contains("LISTEN"))
        XCTAssertFalse(TableRenderer.flagsText(listener).contains("LISTEN"), "the network row itself is the listener")
        let standalone = try XCTUnwrap(items.first { $0.key == "fw:/Applications/Other.app" })
        XCTAssertEqual(standalone.type, .firewallRule)
        // V0.7.0: an existing third-party rule flips block/allow.
        XCTAssertEqual(standalone.control?.level, .reversible)
        XCTAssertEqual(listener.control?.mechanism, .firewall)
        // Apple's daemons hide by default, show with --all.
        let apple = try XCTUnwrap(items.first { $0.key == "net:/usr/libexec/rapportd" })
        var filter = ListFilter(); filter.category = .network
        XCTAssertEqual(filter.apply(to: items).map(\.key).sorted(), [listener.key, standalone.key, app.key].sorted())
        filter.includeAll = true
        XCTAssertTrue(filter.apply(to: items).contains { $0.key == apple.key })
    }

    func testShellProfilesAndMissingSources() throws {
        let files = [
            ShellStartupRecord(kind: "profile", path: "/Users/alice/.zshrc", domain: .user, size: 120, lines: 5,
                               sourced: ["/Users/alice/.extra.sh", "/Users/alice/.gone.sh"], unresolved: ["$ZSH/oh-my-zsh.sh"],
                               missingSources: ["/Users/alice/.gone.sh"], hints: ["line 3: launchctl"]),
            ShellStartupRecord(kind: "sourced", path: "/Users/alice/.extra.sh", domain: .user, sourcedBy: "/Users/alice/.zshrc"),
            ShellStartupRecord(kind: "paths", path: "/etc/paths.d/vendor", domain: .system, lines: 1,
                               sourced: ["/opt/vendor/bin"], missingSources: ["/opt/vendor/bin"]),
        ]
        let items = correlate(.init(jobs: [], launchd: [], btm: [], disabled: [:], uid: 501, shell: files))
        let zshrc = try XCTUnwrap(items.first { $0.key == "shell:/Users/alice/.zshrc" })
        XCTAssertEqual(zshrc.displayName, "~/.zshrc")
        XCTAssertEqual(zshrc.category, .shellStartup)
        XCTAssertEqual(zshrc.type, .shellProfile)
        XCTAssertTrue(zshrc.orphaned)
        XCTAssertEqual(zshrc.orphanConfidence, .low)
        XCTAssertTrue(zshrc.orphanReasons.contains("sources a missing file: /Users/alice/.gone.sh"), "\(zshrc.orphanReasons)")
        XCTAssertEqual(zshrc.metadata["shell-launch-hints"], "line 3: launchctl")
        XCTAssertEqual(zshrc.metadata["shell-sources-unresolved"], "$ZSH/oh-my-zsh.sh")
        XCTAssertEqual(zshrc.control?.level, .displayOnly)
        let extra = try XCTUnwrap(items.first { $0.key == "shell:/Users/alice/.extra.sh" })
        XCTAssertEqual(extra.metadata["shell-sourced-by"], "/Users/alice/.zshrc")
        XCTAssertFalse(extra.orphaned)
        let paths = try XCTUnwrap(items.first { $0.key == "shell:/etc/paths.d/vendor" })
        XCTAssertEqual(paths.type, .pathEntry)
        XCTAssertEqual(paths.domain, .system)
        XCTAssertTrue(paths.orphanReasons.contains("PATH entry points at a missing directory: /opt/vendor/bin"), "\(paths.orphanReasons)")
    }
}

final class ShellNetworkStageTests: XCTestCase {
    func testStagesReportChecksAndIncompleteness() throws {
        let root = tempRoot("stage")
        defer { try? FileManager.default.removeItem(atPath: root) }
        try FileManager.default.createDirectory(atPath: root + "/Library/LaunchAgents", withIntermediateDirectories: true)
        try "export A=1\n".write(toFile: root + "/.zshrc", atomically: true, encoding: .utf8)
        let runner = ScriptedCommandRunner(responses: [
            "/bin/launchctl print gui/501": CommandResult(exitCode: 0, stdout: "gui/501 = {\nservices = {\n}\n}\n", stderr: ""),
            "/bin/launchctl print-disabled gui/501": CommandResult(exitCode: 0, stdout: "", stderr: ""),
            // lsof + socketfilterfw not scripted → incomplete
        ])
        let options = ScanOptions(includeUser: true, includeSystem: false, scanBTM: false, scanSignatures: false,
                                  scanExtensions: false, scanSystemExtensions: false, scanHelpers: false,
                                  scanScheduled: false, scanLegacy: false, scanPlugins: false,
                                  scanShell: true, scanNetwork: true)
        let report = ScanCoordinator(environment: ScanEnvironment(runner: runner, home: root, uid: 501)).perform(options: options)
        XCTAssertEqual(report.incompleteLayers, ["lsof", "socketfilterfw"])
        XCTAssertTrue(report.items.contains { $0.key == "shell:\(root)/.zshrc" }, "the temp home's .zshrc is scanned")
        XCTAssertTrue(report.checks.contains { $0.hasPrefix("shell startup: 1 files") }, "\(report.checks)")
    }
}
