//
//  BTMDumpFilterTests.swift
//  LaunchKeeperKitTests — V0.12.2: a dump read as root is cut down to the
//  client's and the system's sections; BTM-only entries without a name show
//  their label; the listener key prefix is pinned.
//

import XCTest
@testable import LaunchKeeperKit

final class BTMDumpFilterTests: XCTestCase {
    private var full: String { Fixtures.text("dumpbtm-nosudo.txt") }

    private func uids(_ text: String) -> Set<Int> {
        Set(BTMDumpParser.parse(text).records.map(\.sectionUID))
    }

    func testOnlyTheClientsAndTheSystemsSectionsRemain() {
        XCTAssertEqual(uids(full), [-2, 0, 501, 502], "fixture changed (UID 88 has an empty section)")
        let for501 = BTMDumpFilter.sections(of: full, visibleTo: 501)
        XCTAssertEqual(uids(for501), [-2, 0, 501])
        XCTAssertEqual(uids(BTMDumpFilter.sections(of: full, visibleTo: 502)), [-2, 0, 502])
        // Nothing of the kept sections is lost or changed.
        let all = BTMDumpParser.parse(full).records.filter { $0.sectionUID != 502 }
        XCTAssertEqual(BTMDumpParser.parse(for501).records.map(\.fields), all.map(\.fields))
        // The empty section of service account 88 survives (below 500).
        XCTAssertTrue(for501.contains("Records for UID 88 "))
        XCTAssertFalse(for501.contains("Records for UID 502 "))
        // A user with no section of their own still sees the system's.
        XCTAssertEqual(uids(BTMDumpFilter.sections(of: full, visibleTo: 777)), [-2, 0])
    }

    func testUnreadableHeadersDropTheirSection() {
        let text = """
        ========================
         Records for UID abc : 1
        ========================
         Items:
         #1:
                         Name: secret
                   Identifier: 2.com.example.secret
        ========================
         Records for UID 0 : 2
        ========================
         Items:
         #1:
                         Name: daemon
                   Identifier: 16.com.example.daemon
        """
        let kept = BTMDumpFilter.sections(of: text, visibleTo: 501)
        XCTAssertFalse(kept.contains("secret"))
        XCTAssertEqual(BTMDumpParser.parse(kept).records.map(\.name), ["daemon"])
    }

    func testHeadersAreReadStrictlyAndFailClosed() {
        XCTAssertEqual(BTMDumpFilter.headerUID("Records for UID 501 : X"), 501)
        XCTAssertEqual(BTMDumpFilter.headerUID("Records for UID -2 : X"), -2)
        XCTAssertEqual(BTMDumpFilter.headerUID("Records for UID 0"), 0)
        XCTAssertNil(BTMDumpFilter.headerUID("Records for UID 501x : X"))
        XCTAssertNil(BTMDumpFilter.headerUID("Records for UID ٥٠١ : X"), "only ASCII digits")
        XCTAssertNil(BTMDumpFilter.headerUID("Records for UID 99999999999999999999 : X"))

        // Review 2026-09-28 (C2): a header-like line inside a record (a name with
        // a line break) must not open a section — the rest is dropped, not shown.
        let text = """
        ========================
         Records for UID 502 : B
        ========================
         Items:
         #1:
                         Name: other user
         Records for UID 0 : injected
                         Name: still other user
        ========================
         Records for UID 501 : A
        ========================
         Items:
         #1:
                         Name: mine
        """
        let kept = BTMDumpFilter.sections(of: text, visibleTo: 501)
        XCTAssertFalse(kept.contains("other user"))
        XCTAssertEqual(BTMDumpParser.parse(kept).records.map(\.name), ["mine"])
    }

    func testNamelessBTMEntriesShowTheirLabelNotTheInternalIdentifier() throws {
        // Seen live 2026-09-28: a removed daemon was listed as "16.de.paranoidsecurity.lktest".
        let record = BTMRecord(sectionUID: -2, fields: ["Type": "legacy daemon (0x10010)",
                                                        "Identifier": "16.de.example.gone",
                                                        "URL": "file:///Library/LaunchDaemons/de.example.gone.plist"])
        let (items, _) = ItemCorrelator().correlate(.init(jobs: [], launchd: [], btm: [record], disabled: [:], uid: 501))
        let item = try XCTUnwrap(items.first)
        XCTAssertEqual(item.displayName, "de.example.gone")
        XCTAssertEqual(item.key, "btm:16.de.example.gone", "the key stays the identifier")
    }

    func testListenerKeyPrefixIsPinned() {
        // The app's queue tells listeners apart by it (never auto-ticked off).
        XCTAssertEqual(BackgroundItem.listenerKeyPrefix, "net:")
    }
}
