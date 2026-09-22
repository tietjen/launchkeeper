import XCTest
@testable import LaunchKeeperKit

// V0.5: the Autoruns-style dimensions — category, control matrix as data,
// provenance — and the Login Items & Extensions view. Hermetic as always.

private func btm(_ fields: [String: String], uid: Int = 501, children: [String] = []) -> BTMRecord {
    BTMRecord(sectionUID: uid, fields: fields, trailingBlock: children)
}

final class CategoryTests: XCTestCase {
    private func standalone(type: String, name: String = "x", id: String = "9.com.example.x") -> BackgroundItem {
        let (items, _) = ItemCorrelator().correlate(.init(jobs: [], launchd: [], btm: [
            btm(["Name": name, "Type": "\(type) (0x1)", "Identifier": id,
                 "Disposition": "[enabled, allowed, notified] (0xb)", "Parent Identifier": "2.com.example.app"]),
        ], disabled: [:], uid: 501))
        return items[0]
    }

    func testBTMTypesMapToCategories() {
        XCTAssertEqual(standalone(type: "login item").category, .loginItems)
        XCTAssertEqual(standalone(type: "quicklook").category, .appExtensions)
        XCTAssertEqual(standalone(type: "spotlight").category, .appExtensions)
        XCTAssertEqual(standalone(type: "dock tile").category, .appExtensions)
        XCTAssertEqual(standalone(type: "legacy agent").category, .launchItems)
        XCTAssertEqual(standalone(type: "daemon").category, .launchItems)
    }

    func testBTMIdentityIsKeptOnTheItem() {
        let item = standalone(type: "quicklook", id: "2048.com.example.ql")
        XCTAssertEqual(item.metadata["btm-identifier"], "2048.com.example.ql")
        XCTAssertEqual(item.metadata["btm-parent"], "2.com.example.app")
        XCTAssertEqual(item.metadata["btm-type"], "quicklook")
    }

    func testLoginItemNeverMergesIntoALaunchAgentWithTheSameIdCore() {
        // Live shape: a LaunchAgent plist com.example.helper AND a BTM login
        // item 4.com.example.helper (the app's LoginItems helper). Two
        // components, two items — the login item must not disappear.
        let job = LaunchJobRecord(label: "com.example.helper", path: "/Users/t/Library/LaunchAgents/com.example.helper.plist",
                                  domain: .user, kind: .launchAgentUser, program: "/bin/sleep", arguments: [],
                                  runAtLoad: true, keepAlive: false, ownerName: "t", malformed: false)
        let login = btm(["Name": "ExampleHelper", "Type": "login item (0x4)", "Identifier": "4.com.example.helper",
                         "URL": "Contents/Library/LoginItems/ExampleHelper.app",
                         "Disposition": "[enabled, allowed, notified] (0xb)", "Parent Identifier": "2.com.example.app"])
        let (items, _) = ItemCorrelator().correlate(.init(jobs: [job], launchd: [], btm: [login], disabled: [:], uid: 501))
        XCTAssertEqual(items.count, 2, "\(items.map(\.key))")
        let li = try! XCTUnwrap(items.first { $0.category == .loginItems })
        XCTAssertEqual(li.displayName, "ExampleHelper")
        XCTAssertEqual(li.type, .loginItem)
        XCTAssertFalse(items.first { $0.label == "com.example.helper" && $0.plistPresent }!.btmPresent,
                       "the launch agent keeps its own identity")
    }

    func testBackgroundAppRefreshIsALoginItemRegistration() {
        XCTAssertEqual(standalone(type: "background app refresh").category, .loginItems)
    }

    func testPlistItemsAreLaunchItems() {
        let job = LaunchJobRecord(label: "com.example.a", path: "/Users/t/Library/LaunchAgents/com.example.a.plist",
                                  domain: .user, kind: .launchAgentUser, program: "/bin/sleep", arguments: [],
                                  runAtLoad: true, keepAlive: false, ownerName: "t", malformed: false)
        let (items, _) = ItemCorrelator().correlate(.init(jobs: [job], launchd: [], btm: [], disabled: [:], uid: 501))
        XCTAssertEqual(items[0].category, .launchItems)
    }
}

final class ControlAnalyzerTests: XCTestCase {
    private let launchDirs = ["/Users/t/Library/LaunchAgents", "/Library/LaunchAgents", "/Library/LaunchDaemons"]
    private var analyzer: ControlAnalyzer { ControlAnalyzer(launchDirs: launchDirs) }

    func testAppleIsDisplayOnly() {
        let item = BackgroundItem(key: "com.apple.x", displayName: "com.apple.x", label: "com.apple.x", domain: .user)
        let c = analyzer.evaluate(item)
        XCTAssertEqual(c.level, .displayOnly)
        XCTAssertTrue(c.reason.contains("com.apple.*"))
        XCTAssertTrue(c.actions.isEmpty)
    }

    func testHealthyUserAgentIsReversible() {
        var item = BackgroundItem(key: "com.example.a", displayName: "a",
                                  path: "/Users/t/Library/LaunchAgents/com.example.a.plist",
                                  label: "com.example.a", executable: "/bin/sleep", domain: .user)
        item.plistPresent = true
        let c = analyzer.evaluate(item)
        XCTAssertEqual(c.level, .reversible)
        XCTAssertEqual(c.actions, ["disable", "enable"])
    }

    func testOrphanedLaunchPlistIsRemovable() {
        var item = BackgroundItem(key: "com.example.gone", displayName: "gone",
                                  path: "/Users/t/Library/LaunchAgents/com.example.gone.plist",
                                  label: "com.example.gone", executable: "/nonexistent-xyz/gone", domain: .user,
                                  orphaned: true)
        item.plistPresent = true
        let c = analyzer.evaluate(item)
        XCTAssertEqual(c.level, .removable)
        XCTAssertEqual(c.actions, ["disable", "enable", "remove"])
    }

    func testBTMExtensionPointsAtSystemSettings() {
        var item = BackgroundItem(key: "btm:2048.com.example.ql", displayName: "QL.appex", type: .btmEntry,
                                  label: "com.example.ql", domain: .user)
        item.btmPresent = true
        let c = analyzer.evaluate(item)
        XCTAssertEqual(c.level, .displayOnly)
        XCTAssertTrue(c.reason.contains("System Settings"), c.reason)
    }

    func testBTMLeftoverIsDisplayOnlyWithTheLeftoverReason() {
        var item = BackgroundItem(key: "btm:16.com.example.gone", displayName: "gone", type: .btmEntry,
                                  path: "/Library/LaunchAgents/com.example.gone.plist", label: "com.example.gone",
                                  domain: .user, orphaned: true)
        item.btmPresent = true
        item.metadata["btm-leftover"] = "true"
        let c = analyzer.evaluate(item)
        XCTAssertEqual(c.level, .displayOnly)
        XCTAssertTrue(c.reason.hasPrefix("BTM leftover"), c.reason)
    }

    func testFilelessLoadedJobIsReversibleViaDisable() {
        var item = BackgroundItem(key: "com.example.zombie", displayName: "zombie", label: "com.example.zombie",
                                  domain: .user, loaded: true)
        item.launchdPresent = true
        let c = analyzer.evaluate(item)
        XCTAssertEqual(c.level, .reversible)
        XCTAssertTrue(c.reason.contains("next login"), c.reason)
    }
}

final class ProvenanceResolverTests: XCTestCase {
    private let resolver = ProvenanceResolver()

    func testAppleByLabel() {
        XCTAssertEqual(resolver.resolve(BackgroundItem(key: "k", displayName: "k", label: "com.apple.x")).kind, .apple)
    }

    func testHomebrewByLabelAndByPath() {
        XCTAssertEqual(resolver.resolve(BackgroundItem(key: "k", displayName: "k", label: "homebrew.mxcl.tool")).kind, .homebrew)
        XCTAssertEqual(resolver.resolve(BackgroundItem(key: "k", displayName: "k", label: "com.example.t",
                                                       executable: "/opt/homebrew/opt/tool/bin/tool")).kind, .homebrew)
    }

    func testAppStoreByReceipt() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent("lk-prov-\(UUID().uuidString)").path
        defer { try? FileManager.default.removeItem(atPath: root) }
        let bundle = root + "/Applications/Shop.app"
        try FileManager.default.createDirectory(atPath: bundle + "/Contents/_MASReceipt", withIntermediateDirectories: true)
        try Data("receipt".utf8).write(to: URL(fileURLWithPath: bundle + "/Contents/_MASReceipt/receipt"))
        var item = BackgroundItem(key: "k", displayName: "k", label: "com.example.shop.helper")
        item.metadata["app-bundle"] = bundle
        XCTAssertEqual(resolver.resolve(item).kind, .appStore)
    }

    func testUnknownStaysUnknown() {
        XCTAssertEqual(resolver.resolve(BackgroundItem(key: "k", displayName: "k", label: "com.example.t",
                                                       executable: "/Applications/T.app/Contents/MacOS/t")).kind, .unknown)
    }
}

final class BTMContainerIndexTests: XCTestCase {
    func testSameIdentifierAcrossUIDSectionsMergesIntoOneContainer() {
        let records = [
            btm(["Name": "Vendor App", "Type": "app (0x2)", "Identifier": "2.com.example.app",
                 "Team Identifier": "ABCDE12345", "URL": "file:///Applications/Vendor%20App.app/",
                 "Disposition": "[disabled, allowed, not notified] (0x2)"], uid: 501, children: ["8.com.example.helper"]),
            btm(["Name": "Vendor App", "Type": "app (0x2)", "Identifier": "2.com.example.app",
                 "Disposition": "[disabled, allowed, notified] (0xa)"], uid: -2, children: ["16.com.example.daemon"]),
            btm(["Name": "(null)", "Developer Name": "Vendor, Inc.", "Type": "developer (0x20)",
                 "Identifier": "32.TEAM.vendor", "Disposition": "[disabled, allowed, not notified] (0x2)"], uid: 501),
            btm(["Name": "helper", "Type": "legacy agent (0x10008)", "Identifier": "8.com.example.helper",
                 "Disposition": "[enabled, allowed, notified] (0xb)", "Parent Identifier": "2.com.example.app"]),
        ]
        let containers = BTMContainerIndex.build(from: records)
        XCTAssertEqual(containers.count, 2, "components are not containers; duplicates merge")
        let app = try! XCTUnwrap(containers.first { $0.kind == .app })
        XCTAssertEqual(app.uids, [501, -2])
        XCTAssertEqual(app.embedded, ["8.com.example.helper", "16.com.example.daemon"])
        XCTAssertEqual(app.teamIdentifier, "ABCDE12345")
        XCTAssertEqual(app.bundlePath, "/Applications/Vendor App.app")
        let dev = try! XCTUnwrap(containers.first { $0.kind == .developer })
        XCTAssertEqual(dev.name, "Vendor, Inc.", "(null) name falls back to the developer name")
    }

    func testFixtureYieldsContainers() {
        let (records, _) = BTMDumpParser.parse(Fixtures.text("dumpbtm-nosudo.txt"))
        let containers = BTMContainerIndex.build(from: records)
        XCTAssertGreaterThan(containers.count, 20)
        XCTAssertLessThanOrEqual(containers.count, 64, "64 raw app/developer records, duplicates across UIDs merge")
        XCTAssertTrue(containers.contains { $0.kind == .developer } && containers.contains { $0.kind == .app })
    }
}

final class BackgroundViewTests: XCTestCase {
    /// `btm` = the record's disposition bit (the pane's switch); `launchd` =
    /// the effective launchd state (false = a print-disabled override).
    private func item(_ name: String, parent: String, identifier: String, btm: Bool, launchd: Bool = true,
                      category: ItemCategory = .launchItems, type: String = "legacy agent",
                      executable: String? = nil) -> BackgroundItem {
        var i = BackgroundItem(id: "0\(abs(name.hashValue) % 9 + 1)", key: "btm:" + identifier, displayName: name,
                               type: .btmEntry, label: identifier, executable: executable, domain: .user,
                               enabled: btm && launchd, category: category)
        i.btmPresent = true
        i.metadata["btm-parent"] = parent
        i.metadata["btm-identifier"] = identifier
        i.metadata["btm-type"] = type
        i.metadata["btm-disposition"] = btm ? "[enabled, allowed, notified] (0xb)" : "[disabled, allowed, not notified] (0x2)"
        return i
    }

    private func report(items: [BackgroundItem], containers: [BTMContainer]) -> ScanReport {
        ScanReport(items: items, uncorrelated: [], warnings: [], checks: [], btmContainers: containers)
    }

    func testToggleIsTheComponentsBTMBit() {
        let containers = [
            BTMContainer(identifier: "2.on", name: "All On", kind: .app, dispositionTokens: ["disabled"]),
            BTMContainer(identifier: "2.off", name: "All Off", kind: .app, dispositionTokens: ["disabled"]),
            BTMContainer(identifier: "2.mixed", name: "Mixed", kind: .developer),
            BTMContainer(identifier: "2.empty", name: "Empty", kind: .app),
        ]
        let items = [
            item("a", parent: "2.on", identifier: "8.a", btm: true), item("b", parent: "2.on", identifier: "8.b", btm: true),
            item("c", parent: "2.off", identifier: "8.c", btm: false),
            item("d", parent: "2.mixed", identifier: "8.d", btm: true), item("e", parent: "2.mixed", identifier: "8.e", btm: false),
        ]
        let view = BackgroundView.build(from: report(items: items, containers: containers))
        let byName = Dictionary(uniqueKeysWithValues: view.background.map { ($0.name, $0) })
        XCTAssertEqual(byName["All On"]?.toggle, .on, "the container bit says disabled — the components decide")
        XCTAssertEqual(byName["All Off"]?.toggle, .off)
        XCTAssertEqual(byName["Mixed"]?.toggle, .mixed)
        XCTAssertEqual(byName["Empty"]?.toggle, Optional(.none))
        XCTAssertEqual(byName["All On"]?.rawDisposition, ["disabled"], "raw bit kept for the record")
    }

    func testLaunchdOverrideDoesNotFlipTheSwitch() {
        // Live 2026-09-22: GoogleUpdater / Wireshark — launchctl disable set,
        // BTM still enabled, the pane shows ON. The override is its own column.
        let containers = [BTMContainer(identifier: "2.upd", name: "Updater", kind: .app)]
        let items = [item("wake", parent: "2.upd", identifier: "8.wake", btm: true, launchd: false)]
        let view = BackgroundView.build(from: report(items: items, containers: containers))
        let row = view.background[0]
        XCTAssertEqual(row.toggle, .on, "the pane's switch follows the BTM bit")
        XCTAssertEqual(row.components[0].btmEnabled, true)
        XCTAssertEqual(row.components[0].launchdDisabled, true)
        XCTAssertEqual(row.components[0].enabled, false, "effective state honours the override")
        let text = view.renderText()
        XCTAssertTrue(text.contains("DISABLED*"), text)
        XCTAssertTrue(text.contains("lifts the override"), text)
    }

    func testAppLevelRegistrationIsAnOpenAtLoginEntryToo() {
        // Live: Bitwarden — an app record with its own enabled bit, no
        // components; the pane lists it under Open at Login AND as an ON row.
        let containers = [
            BTMContainer(identifier: "2.sm", name: "SM App", kind: .app, bundlePath: "/Applications/SM App.app",
                         dispositionTokens: ["enabled", "allowed", "notified"]),
            BTMContainer(identifier: "2.stale", name: "Stale", kind: .app, dispositionTokens: ["disabled", "allowed", "not notified"]),
        ]
        let view = BackgroundView.build(from: report(items: [], containers: containers))
        let byName = Dictionary(uniqueKeysWithValues: view.background.map { ($0.name, $0) })
        XCTAssertEqual(byName["SM App"]?.toggle, .appLevel)
        XCTAssertEqual(byName["Stale"]?.toggle, Optional(.none))
        XCTAssertEqual(view.loginItems.map(\.name), ["SM App"])
        XCTAssertEqual(view.loginItems[0].bundlePath, "/Applications/SM App.app")
        let text = view.renderText()
        XCTAssertTrue(text.contains("Open at Login (1)"), text)
        XCTAssertTrue(text.contains("the app itself is registered"), text)
        XCTAssertTrue(text.contains("stale row?"), text)
    }

    func testSMAppServiceLoginItemIsAComponentNotAnOpenAtLoginEntry() {
        // Live: DockerHelper (type "login item", parent Docker) is NOT under
        // Open at Login — it belongs under Docker's row.
        let containers = [BTMContainer(identifier: "2.app", name: "Vendor App", kind: .app, teamIdentifier: "ABCDE12345")]
        let helper = item("StartUpHelper", parent: "2.app", identifier: "4.helper", btm: true,
                          category: .loginItems, type: "login item")
        let view = BackgroundView.build(from: report(items: [helper], containers: containers))
        XCTAssertTrue(view.loginItems.isEmpty)
        XCTAssertEqual(view.background[0].components.map(\.name), ["StartUpHelper"])
        XCTAssertEqual(view.background[0].toggle, .on)
        let text = view.renderText()
        XCTAssertTrue(text.contains("Open at Login (0)"), text)
        XCTAssertTrue(text.contains("on         app        Vendor App"), text)
        XCTAssertFalse(try! JSONRenderer.encode(view).isEmpty)
    }

    func testUnnamedContainerIsNamedAfterItsComponentExecutable() {
        // Live: the pane shows "bash" for a developer row without a name.
        let containers = [BTMContainer(identifier: "32.T.unnamed", name: "32.T.unnamed", kind: .developer)]
        let items = [item("guard", parent: "32.T.unnamed", identifier: "16.de.example.guard", btm: true,
                          executable: "/bin/bash")]
        let view = BackgroundView.build(from: report(items: items, containers: containers))
        XCTAssertEqual(view.background[0].name, "bash")
    }

    func testEmbeddedListAlsoAttachesComponents() {
        let containers = [BTMContainer(identifier: "2.app", name: "App", kind: .app, embedded: ["8.x"])]
        var orphanOfParent = item("x", parent: "2.other", identifier: "8.x", btm: true)
        orphanOfParent.metadata["btm-parent"] = nil
        let view = BackgroundView.build(from: report(items: [orphanOfParent], containers: containers))
        XCTAssertEqual(view.background.first?.components.map(\.name), ["x"])
    }
}

final class ListFilterCategoryTests: XCTestCase {
    func testCategoryFilter() {
        var a = BackgroundItem(key: "a", displayName: "a", label: "com.example.a", domain: .user, category: .launchItems)
        a.plistPresent = true
        var b = BackgroundItem(key: "b", displayName: "b", label: "com.example.b", domain: .user, category: .appExtensions)
        b.btmPresent = true
        var filter = ListFilter()
        filter.category = .appExtensions
        XCTAssertEqual(filter.apply(to: [a, b]).map(\.key), ["b"])
    }
}
