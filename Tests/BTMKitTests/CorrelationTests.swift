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
