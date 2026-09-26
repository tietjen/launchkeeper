//
//  EffectiveProgramTests.swift
//  LaunchKeeperKitTests — what interpreter and launcher command lines really
//  run, the orphan rule built on it, the `Program` key, and own-file counts
//  of package receipts.
//

import XCTest
@testable import LaunchKeeperKit

final class EffectiveProgramTests: XCTestCase {
    private func resolve(_ argv: [String]) -> EffectiveProgram? {
        EffectiveProgram.resolve(executable: argv.first, arguments: Array(argv.dropFirst()))
    }

    func testShellsScriptsAndInlineCode() {
        XCTAssertEqual(resolve(["/bin/bash", "-l", "/Users/alice/bin/sync.sh", "/var/log/out.log"]),
                       EffectiveProgram(launchers: ["/bin/bash"], target: "/Users/alice/bin/sync.sh", kind: .script),
                       "the first plain argument is the script; later ones are its arguments")
        let inline = resolve(["/bin/sh", "-c", "exec /opt/x/bin/daemon --foreground", "sh", "arg"])
        XCTAssertEqual(inline?.kind, .inline)
        XCTAssertEqual(inline?.target, "exec /opt/x/bin/daemon --foreground")
        XCTAssertEqual(resolve(["/bin/zsh", "-o", "errexit", "/x/run.zsh"])?.target, "/x/run.zsh")
    }

    func testPythonModulesAndScripts() {
        XCTAssertEqual(resolve(["/usr/bin/python3", "-u", "-m", "http.server", "8000"]),
                       EffectiveProgram(launchers: ["/usr/bin/python3"], target: "http.server", kind: .module))
        XCTAssertEqual(resolve(["/opt/homebrew/bin/python3.12", "-W", "ignore", "/x/tool.py"])?.target, "/x/tool.py")
    }

    func testLauncherChainsReachTheRealProgram() {
        let arch = resolve(["/usr/bin/arch", "-arm64", "-e", "LANG=C", "/opt/tool/bin/tool", "--serve"])
        XCTAssertEqual(arch, EffectiveProgram(launchers: ["/usr/bin/arch"], target: "/opt/tool/bin/tool", kind: .binary))
        let chain = resolve(["/usr/bin/env", "-i", "PATH=/usr/bin", "/bin/bash", "/x/start.sh"])
        XCTAssertEqual(chain?.launchers, ["/usr/bin/env", "/bin/bash"])
        XCTAssertEqual(chain?.target, "/x/start.sh")
        XCTAssertEqual(resolve(["/usr/bin/caffeinate", "-i", "-t", "60", "/opt/x/bin/backup"])?.target, "/opt/x/bin/backup")
    }

    func testOtherInterpretersAndOpen() {
        XCTAssertEqual(resolve(["/usr/bin/osascript", "-e", "tell app \"X\" to run"])?.kind, .inline)
        XCTAssertEqual(resolve(["/usr/bin/osascript", "/Users/alice/Library/Scripts/x.scpt"])?.kind, .script)
        XCTAssertEqual(resolve(["/usr/bin/open", "-g", "-a", "Tool"]),
                       EffectiveProgram(launchers: ["/usr/bin/open"], target: "Tool", kind: .app))
        XCTAssertEqual(resolve(["/usr/local/bin/node", "--require", "dotenv/config", "/srv/app.js"])?.target, "/srv/app.js")
        XCTAssertEqual(resolve(["/bin/bash"])?.kind, EffectiveProgram.Kind.none, "interactive: nothing to name")
        XCTAssertNil(resolve(["/opt/x/bin/daemon", "--flag"]), "a real program resolves to itself — no entry")
    }

    func testSummaryAndAnnotation() {
        var items = [BackgroundItem(key: "a", displayName: "a", executable: "/usr/bin/arch",
                                    arguments: ["-x86_64", "/opt/old/bin/tool"])]
        EffectiveProgram.annotate(&items)
        XCTAssertEqual(items[0].metadata["runs"], "/opt/old/bin/tool via arch")
        XCTAssertEqual(items[0].metadata["runs-kind"], "binary")
    }

    func testOrphanRuleIgnoresOutputFilesAmongArguments() {
        var item = BackgroundItem(key: "de.x.log", displayName: "log", type: .launchAgentUser)
        item.executable = "/bin/bash"
        item.arguments = ["/bin/ls", "/nonexistent-xyz/out.log"]   // the script exists, the log file does not
        var items = [item]
        OrphanDetector().apply(to: &items)
        XCTAssertFalse(items[0].orphaned, "before V0.9.4 every absolute argument counted as the script")

        var arch = BackgroundItem(key: "de.x.arch", displayName: "arch", type: .launchAgentUser)
        arch.executable = "/usr/bin/arch"
        arch.arguments = ["-arm64", "/nonexistent-xyz/bin/tool"]
        var archItems = [arch]
        OrphanDetector().apply(to: &archItems)
        XCTAssertTrue(archItems[0].orphanReasons.contains("program missing: /nonexistent-xyz/bin/tool (run by arch)"),
                      "\(archItems[0].orphanReasons)")
    }

    func testProgramKeyWinsOverProgramArgumentsZero() {
        let job = PlistReader.extractJob(dict: ["Program": "/opt/x/bin/real",
                                                "ProgramArguments": ["x", "--flag"]])
        XCTAssertEqual(job.program, "/opt/x/bin/real", "launchd runs Program; argv[0] is only a name then")
        XCTAssertEqual(job.arguments, ["--flag"])
    }

    func testReceiptOwnFilesIgnoreSharedFolders() {
        // Live: ai.abacus.abacusai listed 15,245 paths; the one "present" was /Applications.
        var index = ReceiptIndex()
        index.add(ReceiptRecord(id: "ai.vendor.app", files: ["/Applications", "/Applications/Gone.app",
                                                             "/Applications/Gone.app/Contents"]))
        var report = ScanReport(items: [], uncorrelated: [], warnings: [])
        report.receiptIndex = index
        let row = ReceiptsView.build(from: report).rows[0]
        XCTAssertEqual(row.fileCount, 3)
        XCTAssertEqual(row.missingFiles, 2, "/Applications exists")
        XCTAssertEqual(row.ownFileCount, 2)
        XCTAssertEqual(row.ownMissingFiles, 2, "judged by its own files, the package is gone")
    }
}
