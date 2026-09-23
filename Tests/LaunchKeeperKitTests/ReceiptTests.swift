import XCTest
@testable import LaunchKeeperKit

// V0.6.0: package receipts as provenance, `receipts`, `list --origin`.

private func tempRoot(_ tag: String) -> String {
    FileManager.default.temporaryDirectory
        .appendingPathComponent("lk-v060-\(tag)-\(UUID().uuidString)", isDirectory: true).path
}

private func infoPlist(id: String, version: String, epoch: Int, location: String = "/") -> String {
    """
    <?xml version="1.0" encoding="UTF-8"?>
    <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
    <plist version="1.0"><dict>
    <key>install-location</key><string>\(location)</string>
    <key>install-time</key><integer>\(epoch)</integer>
    <key>pkg-version</key><string>\(version)</string>
    <key>pkgid</key><string>\(id)</string>
    <key>receipt-plist-version</key><real>1</real>
    <key>volume</key><string>/</string>
    </dict></plist>
    """
}

final class ReceiptParserTests: XCTestCase {
    func testInfoPlist() throws {
        let info = try XCTUnwrap(ReceiptInfoParser.parse(infoPlist(id: "org.example.pkg", version: "1.2", epoch: 1788260480)))
        XCTAssertEqual(info.version, "1.2")
        XCTAssertEqual(info.installTime, Date(timeIntervalSince1970: 1788260480))
        XCTAssertEqual(info.volume, "/")
        XCTAssertEqual(info.location, "/")
        XCTAssertNil(ReceiptInfoParser.parse("not a plist"))
    }

    func testAbsolutePaths() {
        XCTAssertEqual(ReceiptInfoParser.absolutePath(volume: "/", location: "/", relative: "Library/LaunchDaemons/x.plist"),
                       "/Library/LaunchDaemons/x.plist")
        XCTAssertEqual(ReceiptInfoParser.absolutePath(volume: "/", location: "/Applications", relative: "Tool.app/Contents"),
                       "/Applications/Tool.app/Contents")
        XCTAssertEqual(ReceiptInfoParser.absolutePath(volume: "/Volumes/Data", location: "/", relative: "opt/x"),
                       "/Volumes/Data/opt/x")
    }

    func testIndexOwnerWalksUpToTheBundleButNeverToASharedRoot() {
        let index = ReceiptIndex(receipts: [
            ReceiptRecord(id: "org.example.tool", files: ["/Applications", "/Applications/Tool.app", "/Applications/Tool.app/Contents",
                                                          "/Library", "/Library/LaunchDaemons",
                                                          "/Library/LaunchDaemons/org.example.tool.plist",
                                                          "/Library/LaunchDaemons/._org.example.tool.plist"]),
            ReceiptRecord(id: "org.example.other", files: ["/Applications", "/Library", "/Library/Application Support",
                                                           "/Library/Application Support/Other"]),
        ])
        XCTAssertEqual(index.owner(forPath: "/Library/LaunchDaemons/org.example.tool.plist"), "org.example.tool", "exact file")
        XCTAssertEqual(index.owner(forPath: "/Applications/Tool.app/Contents/MacOS/tool"), "org.example.tool", "bundle ancestor")
        XCTAssertEqual(index.owner(forPath: "/Library/Application Support/Other/sub/file"), "org.example.other", "vendor directory")
        XCTAssertNil(index.owner(forPath: "/Applications/Spotify.app/Contents/MacOS/Spotify"), "/Applications is everyone's")
        XCTAssertNil(index.owner(forPath: "/Library/LaunchDaemons/com.vendor.plist"),
                     "a standard directory confers nothing even when one receipt lists it")
        XCTAssertNil(index.owner(forPath: "/Library/Application Support/Elsewhere/file"))
        XCTAssertNil(index.owner(forPath: "/Library/Elsewhere/file"))
        XCTAssertEqual(index.fileCount, 8, "AppleDouble side files are not indexed")
        XCTAssertTrue(ReceiptIndex.isSharedRoot("/Users/alice/Library/LaunchAgents"))
        XCTAssertFalse(ReceiptIndex.isSharedRoot("/Users/alice/Library/Application Support/Vendor"))
        XCTAssertFalse(ReceiptIndex.isSharedRoot("/Applications/Tool.app"))
    }
}

final class ReceiptScannerTests: XCTestCase {
    func testNonAppleReceiptsAreIndexedWithAbsolutePaths() {
        let runner = ScriptedCommandRunner(responses: [
            "/usr/sbin/pkgutil --pkgs": CommandResult(exitCode: 0, stdout: "com.apple.pkg.Core\norg.example.tool\ncom.vendor.app\n", stderr: ""),
            "/usr/sbin/pkgutil --pkg-info-plist org.example.tool":
                CommandResult(exitCode: 0, stdout: infoPlist(id: "org.example.tool", version: "2.0", epoch: 1700000000), stderr: ""),
            "/usr/sbin/pkgutil --files org.example.tool":
                CommandResult(exitCode: 0, stdout: "Library\nLibrary/LaunchDaemons\nLibrary/LaunchDaemons/org.example.tool.plist\n", stderr: ""),
            "/usr/sbin/pkgutil --pkg-info-plist com.vendor.app":
                CommandResult(exitCode: 0, stdout: infoPlist(id: "com.vendor.app", version: "9", epoch: 1600000000, location: "/Applications"), stderr: ""),
            "/usr/sbin/pkgutil --files com.vendor.app": CommandResult(exitCode: 0, stdout: "Vendor.app\nVendor.app/Contents\n", stderr: ""),
        ])
        let result = ReceiptScanner(runner: runner).scan()
        XCTAssertFalse(result.failed)
        XCTAssertEqual(Set(result.index.receipts.keys), ["org.example.tool", "com.vendor.app"], "Apple's skipped")
        XCTAssertEqual(result.index.owner(forPath: "/Applications/Vendor.app/Contents/MacOS/Vendor"), "com.vendor.app")
        XCTAssertEqual(result.index.receipts["org.example.tool"]?.version, "2.0")
        XCTAssertTrue(result.checks.contains("pkgutil: ok (3 receipts, 2 indexed non-Apple, 5 paths)"), "\(result.checks)")
    }

    func testPkgutilFailureIsAWarningNotIncompleteness() {
        let result = ReceiptScanner(runner: ScriptedCommandRunner()).scan()
        XCTAssertTrue(result.failed)
        XCTAssertTrue(result.index.isEmpty)
        XCTAssertTrue(result.warnings.contains { $0.contains("package receipts not indexed") })
    }
}

final class ReceiptProvenanceTests: XCTestCase {
    private func item(key: String, path: String? = nil, executable: String? = nil, label: String? = nil,
                      metadata: [String: String] = [:]) -> BackgroundItem {
        var item = BackgroundItem(key: key, displayName: key, type: .launchDaemon, path: path, label: label,
                                  executable: executable, domain: .system)
        item.metadata = metadata
        return item
    }

    func testReceiptManualAndPrecedence() throws {
        let root = tempRoot("prov")
        defer { try? FileManager.default.removeItem(atPath: root) }
        let app = root + "/Dragged.app"
        try FileManager.default.createDirectory(atPath: app + "/Contents/MacOS", withIntermediateDirectories: true)
        let index = ReceiptIndex(receipts: [
            ReceiptRecord(id: "org.example.tool", version: "2.0", installTime: Date(timeIntervalSince1970: 1700000000),
                          files: ["/Library/LaunchDaemons/org.example.tool.plist", "/Applications/Tool.app"]),
        ])
        let resolver = ProvenanceResolver(receipts: index)

        let byPlist = resolver.resolve(item(key: "a", path: "/Library/LaunchDaemons/org.example.tool.plist", executable: "/nowhere/bin"))
        XCTAssertEqual(byPlist.kind, .receipt)
        XCTAssertEqual(byPlist.packageIdentifier, "org.example.tool")
        XCTAssertEqual(byPlist.version, "2.0")
        XCTAssertEqual(byPlist.installedAt, "2023-11-14")
        XCTAssertEqual(byPlist.detail, "package org.example.tool 2.0, installed 2023-11-14")

        let byBundle = resolver.resolve(item(key: "b", executable: "/Applications/Tool.app/Contents/MacOS/helper"))
        XCTAssertEqual(byBundle.kind, .receipt, "the receipt lists the app bundle")

        let dragged = resolver.resolve(item(key: "c", executable: app + "/Contents/MacOS/Dragged",
                                            metadata: ["app-bundle": app]))
        XCTAssertEqual(dragged.kind, .manual)
        XCTAssertTrue(dragged.detail?.contains("without a package receipt") == true)

        let unknownNoIndex = ProvenanceResolver().resolve(item(key: "d", executable: app + "/Contents/MacOS/Dragged",
                                                                metadata: ["app-bundle": app]))
        XCTAssertEqual(unknownNoIndex.kind, .unknown, "without pkgutil nobody can call it drag-installed")

        let brew = resolver.resolve(item(key: "e", path: "/Library/LaunchDaemons/org.example.tool.plist", label: "homebrew.mxcl.tool"))
        XCTAssertEqual(brew.kind, .homebrew, "the label wins over the receipt")
        let cask = resolver.resolve(item(key: "e2", executable: "/Applications/Docker.app/Contents/MacOS/helper",
                                         metadata: ["app-bundle": "/opt/homebrew/Caskroom/docker-desktop/4.0/Docker.app"]))
        XCTAssertEqual(cask.kind, .homebrew, "a cask's app bundle is Homebrew")

        let apple = resolver.resolve(item(key: "f", path: "/Library/LaunchDaemons/org.example.tool.plist", label: "com.apple.x"))
        XCTAssertEqual(apple.kind, .apple)

        let nothing = resolver.resolve(item(key: "g", path: "/Library/LaunchAgents/other.plist", executable: "/opt/other/bin"))
        XCTAssertEqual(nothing.kind, .unknown)
    }
}

final class ReceiptsViewTests: XCTestCase {
    func testRowsCountMissingFilesAndAttributeItems() throws {
        let root = tempRoot("view")
        defer { try? FileManager.default.removeItem(atPath: root) }
        try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
        try Data("x".utf8).write(to: URL(fileURLWithPath: root + "/present"))
        var index = ReceiptIndex()
        index.add(ReceiptRecord(id: "org.example.tool", version: "2.0", installTime: Date(timeIntervalSince1970: 1700000000),
                                files: [root + "/present", root + "/gone"]))
        index.add(ReceiptRecord(id: "com.apple.pkg.Core", files: ["/usr/bin/true"]))
        index.add(ReceiptRecord(id: "org.example.newer", installTime: Date(timeIntervalSince1970: 1800000000), files: []))
        var item = BackgroundItem(key: "org.example.tool", displayName: "org.example.tool", type: .launchDaemon, domain: .system)
        item.provenance = Provenance(kind: .receipt, packageIdentifier: "org.example.tool")
        var report = ScanReport(items: [item], uncorrelated: [], warnings: [])
        report.receiptIndex = index

        let view = ReceiptsView.build(from: report)
        XCTAssertEqual(view.rows.map(\.id), ["org.example.newer", "org.example.tool"], "newest first, Apple hidden")
        let tool = view.rows[1]
        XCTAssertEqual(tool.fileCount, 2)
        XCTAssertEqual(tool.missingFiles, 1)
        XCTAssertEqual(tool.items, ["org.example.tool"])
        XCTAssertEqual(tool.installedAt, "2023-11-14")
        XCTAssertEqual(ReceiptsView.build(from: report, includeApple: true).rows.count, 3)
        let text = view.renderText()
        XCTAssertTrue(text.contains("PACKAGE") && text.contains("org.example.tool") && text.contains("2 receipts, 1 with missing files"), text)

        let none = ReceiptsView.build(from: ScanReport(items: [], uncorrelated: [], warnings: []))
        XCTAssertFalse(none.indexed)
        XCTAssertTrue(none.renderText().contains("not indexed"))
    }

    func testListFilterOrigin() {
        var receipt = BackgroundItem(key: "a", displayName: "a", type: .launchDaemon, domain: .system)
        receipt.provenance = Provenance(kind: .receipt)
        var manual = BackgroundItem(key: "b", displayName: "b", type: .launchDaemon, domain: .system)
        manual.provenance = Provenance(kind: .manual)
        let none = BackgroundItem(key: "c", displayName: "c", type: .launchDaemon, domain: .system)
        var filter = ListFilter(); filter.origin = .receipt
        XCTAssertEqual(filter.apply(to: [receipt, manual, none]).map(\.key), ["a"])
        filter.origin = .unknown
        XCTAssertEqual(filter.apply(to: [receipt, manual, none]).map(\.key), ["c"], "no provenance counts as unknown")
    }
}

final class ReceiptStageTests: XCTestCase {
    func testStageIndexesReceiptsAndSignatureDetailsLandInMetadata() throws {
        let root = tempRoot("stage")
        defer { try? FileManager.default.removeItem(atPath: root) }
        let agents = root + "/Library/LaunchAgents"
        try FileManager.default.createDirectory(atPath: agents, withIntermediateDirectories: true)
        let binary = root + "/tool"
        try Data("bin".utf8).write(to: URL(fileURLWithPath: binary))
        let plist: [String: Any] = ["Label": "org.example.agent", "ProgramArguments": [binary]]
        try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
            .write(to: URL(fileURLWithPath: agents + "/org.example.agent.plist"))
        let codesign = """
        Executable=\(binary)
        Identifier=org.example.tool
        Format=Mach-O thin (arm64)
        Authority=Developer ID Application: Example Corp (EXAMPLE123)
        Authority=Developer ID Certification Authority
        Authority=Apple Root CA
        TeamIdentifier=EXAMPLE123
        """
        let runner = ScriptedCommandRunner(responses: [
            "/bin/launchctl print gui/501": CommandResult(exitCode: 0, stdout: "gui/501 = {\nservices = {\n}\n}\n", stderr: ""),
            "/bin/launchctl print-disabled gui/501": CommandResult(exitCode: 0, stdout: "", stderr: ""),
            "/usr/bin/codesign -dvvv \(binary)": CommandResult(exitCode: 0, stdout: "", stderr: codesign),
            "/usr/sbin/pkgutil --pkgs": CommandResult(exitCode: 0, stdout: "org.example.tool\n", stderr: ""),
            "/usr/sbin/pkgutil --pkg-info-plist org.example.tool":
                CommandResult(exitCode: 0, stdout: infoPlist(id: "org.example.tool", version: "2.0", epoch: 1700000000), stderr: ""),
            "/usr/sbin/pkgutil --files org.example.tool":
                CommandResult(exitCode: 0, stdout: String(agents.dropFirst()) + "/org.example.agent.plist\n", stderr: ""),
        ])
        let options = ScanOptions(includeUser: true, includeSystem: false, scanBTM: false, scanSignatures: true,
                                  scanExtensions: false, scanSystemExtensions: false, scanHelpers: false,
                                  scanScheduled: false, scanLegacy: false, scanPlugins: false,
                                  scanShell: false, scanNetwork: false, scanReceipts: true)
        let report = ScanCoordinator(environment: ScanEnvironment(runner: runner, home: root, uid: 501)).perform(options: options)
        XCTAssertNotNil(report.receiptIndex)
        XCTAssertTrue(report.checks.contains { $0.hasPrefix("pkgutil: ok (1 receipts, 1 indexed non-Apple") }, "\(report.checks)")
        let agent = try XCTUnwrap(report.items.first { $0.key == "org.example.agent" })
        XCTAssertEqual(agent.provenance?.kind, .receipt)
        XCTAssertEqual(agent.provenance?.packageIdentifier, "org.example.tool")
        XCTAssertEqual(agent.metadata["signature-team"], "EXAMPLE123")
        XCTAssertEqual(agent.metadata["signature-identifier"], "org.example.tool")
        XCTAssertEqual(agent.metadata["signature-authority"], "Developer ID Application: Example Corp (EXAMPLE123)")
    }
}
