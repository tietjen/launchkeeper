import XCTest
@testable import BTMKit

/// Core invariant under test: a BTM entry is NOT one plist. One component may
/// be backed by plist + launchd + BTM at once and must collapse to exactly one
/// item; pure launchd bookkeeping (Apple, application.*) must not become items.
final class ItemCorrelatorTests: XCTestCase {
    private let guardLabel = "de.example.guard"
    private let guardPath = "/Library/LaunchDaemons/de.example.guard.plist"
    private let guardExec = "/usr/local/bin/guard.sh"

    private func makeInput(
        includePlist: Bool = true, includeLaunchd: Bool = true, includeBTM: Bool = true,
        disabled: [String: Bool] = [:]
    ) -> ItemCorrelator.Input {
        var jobs: [LaunchJobRecord] = []
        if includePlist {
            jobs.append(LaunchJobRecord(
                label: guardLabel, path: guardPath, domain: .system, kind: .launchDaemon,
                program: guardExec, arguments: [], runAtLoad: true, keepAlive: false,
                ownerName: "root", malformed: false))
        }
        var services: [LaunchdServiceRecord] = []
        if includeLaunchd {
            services.append(LaunchdServiceRecord(
                label: guardLabel, domainKind: "system", pid: 4321, stateToken: "(pe)"))
        }
        var btmRecords: [BTMRecord] = []
        if includeBTM {
            btmRecords.append(BTMRecord(sectionUID: 0, fields: [
                "Name": "guard.sh",
                "Type": "legacy daemon (0x10010)",
                "Disposition": "[enabled, allowed, notified] (0xb)",
                "Identifier": "16.\(guardLabel)",
                "URL": "file://\(guardPath)",
                "Executable Path": guardExec,
            ]))
        }
        return ItemCorrelator.Input(jobs: jobs, launchd: services, btm: btmRecords,
                                    disabled: disabled, uid: 501)
    }

    func testThreeSourcesCollapseToOneItem() {
        let (items, uncorrelated) = ItemCorrelator().correlate(makeInput())
        XCTAssertEqual(uncorrelated, [])
        XCTAssertEqual(items.count, 1, "must collapse to one: \(items.map(\.key))")
        guard let rec = items.first else { return }
        XCTAssertEqual(rec.sources.map(\.kind), [.plist, .launchd, .btm])
        XCTAssertEqual(rec.type, .launchDaemon)
        XCTAssertEqual(rec.domain, .system)
        XCTAssertTrue(rec.running)
        XCTAssertEqual(rec.pid, 4321)
        XCTAssertTrue(rec.enabled, "disposition 0xb contains 'enabled'")
    }

    func testBTMOnlyStillSurfacesAndIsFlaggedUncorrelated() {
        // Spec: orphaned leftovers must still be visible after the plist is gone.
        let (items, uncorrelated) = ItemCorrelator().correlate(
            makeInput(includePlist: false, includeLaunchd: false))
        XCTAssertEqual(items.count, 1)
        XCTAssertEqual(uncorrelated, ["16.\(guardLabel)"],
                       "service-like BTM entry without backing evidence is uncorrelated")
        XCTAssertEqual(items[0].type, .btmEntry)
        XCTAssertEqual(items[0].domain, .system, "section UID 0 is system")
    }

    func testStandaloneMergeAcrossSections() {
        // Same Identifier in UID 501 AND 502 sections -> one item, two sources.
        var input = makeInput(includePlist: false, includeLaunchd: false, includeBTM: false)
        for uid in [501, 502] {
            input.btm.append(BTMRecord(sectionUID: uid, fields: [
                "Name": "helper", "Type": "login item (0x4)",
                "Disposition": "[enabled, allowed, notified] (0xb)",
                "Identifier": "4.com.example.helper",
            ]))
        }
        let (items, uncorrelated) = ItemCorrelator().correlate(input)
        XCTAssertEqual(items.count, 1, "cross-section duplicate must merge")
        XCTAssertEqual(items[0].sources.count, 2)
        XCTAssertEqual(uncorrelated, [], "login items are not service-like")
    }

    func testAppleRuntimeBookkeepingStaysHidden() {
        var input = makeInput(includePlist: false, includeBTM: false)
        input.launchd = [
            LaunchdServiceRecord(label: "com.apple.SafariPlatformSupport.Helper",
                                 domainKind: "gui", pid: nil, stateToken: "-"),
            LaunchdServiceRecord(label: "application.com.example.app.123.456",
                                 domainKind: "gui", pid: nil, stateToken: "-"),
        ]
        let (items, uncorrelated) = ItemCorrelator().correlate(input)
        XCTAssertTrue(items.isEmpty,
                      "Apple/per-app bookkeeping would flood the table: \(items.map(\.key))")
        XCTAssertEqual(uncorrelated, [])
    }

    func testDisabledMapMarksThirdPartyAgent() {
        // Third-party agent without a matching plist must still be tracked,
        // with the print-disabled verdict applied (Team-ID-prefixed key).
        // NOTE map value semantics: print-disabled "disabled" maps to `false`
        // in the parsed dictionary (LaunchctlParser.parseDisabled).
        var input = makeInput(includePlist: false, includeLaunchd: false, includeBTM: false)
        input.launchd = [LaunchdServiceRecord(label: "com.example.browser-helper",
                                              domainKind: "gui", pid: nil, stateToken: "(p)")]
        input.disabled = ["ABCDE12345.com.example.browser-helper": false]
        let (items, _) = ItemCorrelator().correlate(input)
        XCTAssertEqual(items.count, 1)
        XCTAssertFalse(items[0].enabled,
                       "Team-ID-prefixed disabled entry must mark the item disabled")
    }

    func testDisabledExactKeyMarksLaunchdOnlyItem() {
        var input = makeInput(includePlist: false, includeLaunchd: false, includeBTM: false)
        input.launchd = [LaunchdServiceRecord(label: "com.searchco.updater.agent",
                                              domainKind: "gui", pid: nil, stateToken: "(p)")]
        input.disabled = ["com.searchco.updater.agent": false]
        let (items, _) = ItemCorrelator().correlate(input)
        XCTAssertFalse(items.first?.enabled ?? true, "exact-key disable must apply")
        XCTAssertEqual(items.first?.domain, .user)
    }
}

/// V0.4.1 regression: on a real macOS 26 machine, "Vendor QL Extension.appex"
/// (installed, under an installed VendorApp.app) was reported as "parent
/// application bundle missing" — the child's relative BTM URL carried `%20`
/// into the existence probe. The parent-bundle probe must run on DECODED
/// paths, for the parent and for the child, and a genuinely missing plug-in
/// must still count as gone.
final class PercentEncodedBundleProbeTests: XCTestCase {
    private var root = ""

    override func setUpWithError() throws {
        root = FileManager.default.temporaryDirectory
            .appendingPathComponent("btmctl-pct-\(UUID().uuidString)", isDirectory: true).path
        try FileManager.default.createDirectory(
            atPath: root + "/Applications/My App.app/Contents/PlugIns/My QL Extension.appex",
            withIntermediateDirectories: true)
        try FileManager.default.createDirectory(
            atPath: root + "/Applications/Plain.app/Contents/PlugIns/Ext Two.appex",
            withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(atPath: root)
    }

    private func app(_ id: String, name: String, url: String) -> BTMRecord {
        BTMRecord(sectionUID: 501, fields: ["Name": name, "Type": "app (0x2)",
                                            "Identifier": "2.\(id)", "URL": url])
    }

    private func plugin(_ id: String, name: String, url: String, parent: String) -> BTMRecord {
        BTMRecord(sectionUID: 501, fields: ["Name": name, "Type": "quicklook (0x800)",
                                            "Identifier": "2048.\(id)", "URL": url,
                                            "Parent Identifier": "2.\(parent)"])
    }

    private func analyze(_ records: [BTMRecord]) -> [BackgroundItem] {
        let (items, _) = ItemCorrelator().correlate(.init(jobs: [], launchd: [], btm: records,
                                                          disabled: [:], uid: 501))
        var analyzed = items
        OrphanDetector().apply(to: &analyzed)
        return analyzed
    }

    func testEncodedParentAndChildAreProbedDecoded() throws {
        // Parent with a space (encoded) + child with spaces (encoded).
        let items = analyze([
            app("com.example.myapp", name: "My App", url: "file://\(root)/Applications/My%20App.app/"),
            plugin("com.example.myapp.ql", name: "My QL Extension.appex",
                   url: "Contents/PlugIns/My%20QL%20Extension.appex", parent: "com.example.myapp"),
        ])
        let item = try XCTUnwrap(items.first { $0.displayName == "My QL Extension.appex" })
        XCTAssertEqual(item.parentApplication, "My App")
        XCTAssertEqual(item.appPresent, true, "decoded bundle + decoded child must be found on disk")
        XCTAssertFalse(item.orphaned, item.orphanReasons.joined(separator: "; "))
    }

    func testEncodedChildUnderPlainParentIsNotAFalseOrphan() throws {
        // The exact live shape: parent without a space, child with one.
        let items = analyze([
            app("com.example.plain", name: "Plain", url: "file://\(root)/Applications/Plain.app/"),
            plugin("com.example.plain.two", name: "Ext Two.appex",
                   url: "Contents/PlugIns/Ext%20Two.appex", parent: "com.example.plain"),
        ])
        let item = try XCTUnwrap(items.first { $0.displayName == "Ext Two.appex" })
        XCTAssertEqual(item.appPresent, true)
        XCTAssertFalse(item.orphaned, item.orphanReasons.joined(separator: "; "))
    }

    func testGenuinelyMissingPluginIsStillFlagged() throws {
        let items = analyze([
            app("com.example.plain", name: "Plain", url: "file://\(root)/Applications/Plain.app/"),
            plugin("com.example.plain.gone", name: "Ext Gone.appex",
                   url: "Contents/PlugIns/Ext%20Gone.appex", parent: "com.example.plain"),
        ])
        let item = try XCTUnwrap(items.first { $0.displayName == "Ext Gone.appex" })
        XCTAssertEqual(item.appPresent, false)
        XCTAssertTrue(item.orphaned)
        XCTAssertTrue(item.orphanReasons.contains { $0.contains("parent application bundle missing") })
    }

    func testMacOS27PlainPathsBehaveIdentically() throws {
        let items = analyze([
            app("com.example.myapp", name: "My App", url: "\(root)/Applications/My App.app"),
            plugin("com.example.myapp.ql", name: "My QL Extension.appex",
                   url: "Contents/PlugIns/My QL Extension.appex", parent: "com.example.myapp"),
        ])
        let item = try XCTUnwrap(items.first { $0.displayName == "My QL Extension.appex" })
        XCTAssertEqual(item.appPresent, true)
        XCTAssertFalse(item.orphaned)
    }
}
