import XCTest
@testable import LaunchKeeperKit

// V0.5.4: app extensions via pluginkit — parser, correlation with the BTM
// extension records, scan stage, control matrix. Hermetic: fixture + doubles.

private let sample = """
+    com.example.app.ShareExt(1.2)
\t            Path = /Applications/Example.app/Contents/PlugIns/ShareExt.appex
\t            UUID = 22361EB9-945D-463F-9B8A-6CEC0397C4F0
\t       Timestamp = 2026-09-22 05:55:01 +0000
\t             SDK = com.apple.share-services
\t   Parent Bundle = /Applications/Example.app
\t    Display Name = Share to Example
\t      Short Name = ShareExt
\t     Parent Name = Example
\t        Platform = macOS

-    com.example.app.Widget(1.2)
\t            Path = /Applications/Example.app/Contents/PlugIns/Widget.appex
\t             SDK = com.apple.widgetkit-extension
\t   Parent Bundle = /Applications/Example.app

     com.example.app.QL(1.2)
\t            Path = /Applications/Example.app/Contents/PlugIns/QL.appex
\t             SDK = com.apple.quicklook.preview
\t   Parent Bundle = /Applications/Example.app

     com.example.app.QL(1.1)
\t            Path = /Users/alice/Old/Example.app/Contents/PlugIns/QL.appex
\t             SDK = com.apple.quicklook.preview

=    com.example.old.Thing((null))
\t            Path = /Library/Old/Thing.appex
this line is garbage
"""

final class PluginKitParserTests: XCTestCase {
    func testSyntheticSampleParsesTagsFieldsAndVersions() {
        let (records, warnings) = PluginKitParser.parse(sample)
        XCTAssertEqual(records.count, 5)
        XCTAssertEqual(records.map(\.election), [.use, .ignore, .none, .none, .superseded])
        XCTAssertEqual(records[0].identifier, "com.example.app.ShareExt")
        XCTAssertEqual(records[0].version, "1.2")
        XCTAssertEqual(records[0].sdk, "com.apple.share-services")
        XCTAssertEqual(records[0].parentBundle, "/Applications/Example.app")
        XCTAssertEqual(records[0].displayName, "Share to Example")
        XCTAssertEqual(records[0].uuid, "22361EB9-945D-463F-9B8A-6CEC0397C4F0")
        XCTAssertEqual(records[1].enabled, false, "ignored by the user")
        XCTAssertEqual(records[2].enabled, true, "no election = default = available")
        XCTAssertEqual(records[4].version, "(null)")
        XCTAssertEqual(warnings.count, 1, "the garbage line is reported, not fatal: \(warnings)")
    }

    func testFixtureParses() {
        let (records, warnings) = PluginKitParser.parse(Fixtures.text("pluginkit.txt"))
        XCTAssertGreaterThan(records.count, 400)
        XCTAssertEqual(records.filter { $0.election == .use }.count, 34)
        XCTAssertTrue(warnings.isEmpty, "\(warnings.prefix(3))")
        let quicklook = records.filter { $0.sdk == "com.apple.quicklook.preview" }
        XCTAssertGreaterThan(quicklook.count, 5)
        XCTAssertTrue(records.allSatisfy { $0.path != nil }, "every record carries its bundle path")
        XCTAssertTrue(records.contains { !$0.identifier.hasPrefix("com.apple.") }, "third-party extensions present")
    }
}

final class AppExtensionCorrelationTests: XCTestCase {
    private func btm(_ fields: [String: String], uid: Int = 501) -> BTMRecord {
        BTMRecord(sectionUID: uid, fields: fields)
    }

    func testExtensionMergesIntoTheBTMRecordOfTheSameBundle() {
        // BTM knows the QuickLook plug-in by its relative URL under the app;
        // pluginkit knows it by absolute path. One component, two sources.
        let app = btm(["Name": "Example", "Type": "app (0x2)", "Identifier": "2.com.example.app",
                       "URL": "file:///Applications/Example.app/"])
        let ql = btm(["Name": "QL.appex", "Type": "quicklook (0x800)", "Identifier": "2048.com.example.app.QL",
                      "URL": "Contents/PlugIns/QL.appex", "Parent Identifier": "2.com.example.app",
                      "Disposition": "[enabled, allowed, notified] (0xb)"])
        let ext = AppExtensionRecord(identifier: "com.example.app.QL", version: "1.2", election: .none,
                                     path: "/Applications/Example.app/Contents/PlugIns/QL.appex",
                                     sdk: "com.apple.quicklook.preview", parentBundle: "/Applications/Example.app",
                                     parentName: "Example")
        let (items, _) = ItemCorrelator().correlate(.init(jobs: [], launchd: [], btm: [app, ql], disabled: [:],
                                                          uid: 501, extensions: [ext]))
        XCTAssertEqual(items.count, 1, "\(items.map(\.key))")
        let item = items[0]
        XCTAssertTrue(item.btmPresent)
        XCTAssertEqual(item.sources.map(\.kind), [.btm, .pluginkit])
        XCTAssertEqual(item.type, .appExtension)
        XCTAssertEqual(item.category, .appExtensions)
        XCTAssertEqual(item.path, "/Applications/Example.app/Contents/PlugIns/QL.appex", "absolute path wins")
        XCTAssertEqual(item.metadata["ext-sdk"], "com.apple.quicklook.preview")
        XCTAssertEqual(item.metadata["ext-election"], "none")
    }

    func testUnmatchedExtensionBecomesItsOwnItemAndIgnoreDisablesIt() {
        let ext = AppExtensionRecord(identifier: "com.example.app.Widget", version: "1.2", election: .ignore,
                                     path: "/Applications/Example.app/Contents/PlugIns/Widget.appex",
                                     sdk: "com.apple.widgetkit-extension", parentName: "Example")
        let (items, _) = ItemCorrelator().correlate(.init(jobs: [], launchd: [], btm: [], disabled: [:],
                                                          uid: 501, extensions: [ext]))
        XCTAssertEqual(items.count, 1)
        let item = items[0]
        XCTAssertEqual(item.key, "ext:com.example.app.Widget")
        XCTAssertEqual(item.displayName, "com.example.app.Widget")
        XCTAssertEqual(item.enabled, false)
        XCTAssertEqual(item.parentApplication, "Example")
        XCTAssertEqual(item.domain, .user)
        XCTAssertEqual(item.bundleIdentifier, "com.example.app.Widget")
    }

    func testAllVersionsCollapseIntoOneItem() {
        let v2 = AppExtensionRecord(identifier: "com.example.app.QL", version: "1.2", election: .none,
                                    path: "/Applications/Example.app/Contents/PlugIns/QL.appex")
        let v1 = AppExtensionRecord(identifier: "com.example.app.QL", version: "1.1", election: .none,
                                    path: "/Users/alice/Old/Example.app/Contents/PlugIns/QL.appex")
        let (items, _) = ItemCorrelator().correlate(.init(jobs: [], launchd: [], btm: [], disabled: [:],
                                                          uid: 501, extensions: [v2, v1]))
        XCTAssertEqual(items.count, 1)
        XCTAssertEqual(items[0].metadata["ext-version"], "1.2")
        XCTAssertEqual(items[0].metadata["ext-versions"], "1.1")
    }
}

final class AppExtensionScanStageTests: XCTestCase {
    private func home() throws -> String {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("lk-ext-\(UUID().uuidString)", isDirectory: true).path
        try FileManager.default.createDirectory(atPath: dir + "/Library/LaunchAgents", withIntermediateDirectories: true)
        return dir
    }

    private func runner(pluginkit: CommandResult) -> ScriptedCommandRunner {
        ScriptedCommandRunner(responses: [
            "/bin/launchctl print gui/501": CommandResult(exitCode: 0, stdout: "gui/501 = {\nservices = {\n}\n}\n", stderr: ""),
            "/bin/launchctl print-disabled gui/501": CommandResult(exitCode: 0, stdout: "", stderr: ""),
            "/usr/bin/pluginkit -mAvv": pluginkit,
        ])
    }

    private let options = ScanOptions(includeUser: true, includeSystem: false, scanBTM: false,
                                      scanSignatures: false, scanExtensions: true,
                                      scanSystemExtensions: false, scanHelpers: false)

    func testExtensionsBecomeItemsWithControlAndCategory() throws {
        let home = try home()
        defer { try? FileManager.default.removeItem(atPath: home) }
        let env = ScanEnvironment(runner: runner(pluginkit: CommandResult(exitCode: 0, stdout: sample, stderr: "")),
                                  home: home, uid: 501)
        let report = ScanCoordinator(environment: env).perform(options: options)
        XCTAssertTrue(report.checks.contains { $0.hasPrefix("pluginkit: ok (5 extensions, 1 elected)") }, "\(report.checks)")
        XCTAssertTrue(report.incompleteLayers.isEmpty)
        let extensions = report.items.filter { $0.category == .appExtensions }
        XCTAssertEqual(extensions.count, 4, "5 records, one identifier twice: \(extensions.map(\.key))")
        let share = try XCTUnwrap(extensions.first { $0.key == "ext:com.example.app.ShareExt" })
        XCTAssertEqual(share.control?.level, .displayOnly)
        XCTAssertTrue(share.control?.reason.contains("pluginkit -e use|ignore -i com.example.app.ShareExt") == true,
                      share.control?.reason ?? "-")
        XCTAssertEqual(share.parentApplication, "Example")
    }

    func testPluginkitFailureMarksTheInventoryIncomplete() throws {
        let home = try home()
        defer { try? FileManager.default.removeItem(atPath: home) }
        let env = ScanEnvironment(runner: runner(pluginkit: CommandResult(exitCode: 1, stdout: "", stderr: "boom")),
                                  home: home, uid: 501)
        let report = ScanCoordinator(environment: env).perform(options: options)
        XCTAssertEqual(report.incompleteLayers, ["pluginkit"])
        XCTAssertTrue(report.warnings.contains { $0.contains("app extensions not scanned") }, "\(report.warnings)")
        XCTAssertTrue(report.checks.contains { $0.hasPrefix("pluginkit: FAILED") })
    }

    func testAppleExtensionsHiddenByDefaultThirdPartyShown() {
        var apple = BackgroundItem(key: "ext:com.apple.x.QL", displayName: "com.apple.x.QL", type: .appExtension,
                                   domain: .user, category: .appExtensions)
        apple.sources = [SourceEvidence(kind: .pluginkit, detail: "x", confidence: .high)]
        var vendor = BackgroundItem(key: "ext:com.example.x.QL", displayName: "com.example.x.QL", type: .appExtension,
                                    domain: .user, category: .appExtensions)
        vendor.sources = apple.sources
        XCTAssertEqual(ListFilter().apply(to: [apple, vendor]).map(\.key), ["ext:com.example.x.QL"])
        var all = ListFilter(); all.includeAll = true
        XCTAssertEqual(all.apply(to: [apple, vendor]).count, 2)
    }
}
