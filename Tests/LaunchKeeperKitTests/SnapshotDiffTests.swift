import XCTest
@testable import LaunchKeeperKit

// V0.6.1: inventory snapshots, diff, CSV/Markdown export, stable keys.

private func tempRoot(_ tag: String) -> String {
    FileManager.default.temporaryDirectory
        .appendingPathComponent("lk-v061-\(tag)-\(UUID().uuidString)", isDirectory: true).path
}

private func item(_ key: String, enabled: Bool = true, path: String? = nil, signature: String? = "signed",
                  running: Bool = false, label: String? = nil, metadata: [String: String] = [:]) -> BackgroundItem {
    var item = BackgroundItem(key: key, displayName: key, type: .launchDaemon, path: path, label: label ?? key,
                              executable: "/opt/\(key)/bin", domain: .system, running: running, enabled: enabled)
    item.codeSignatureStatus = signature
    item.metadata = metadata
    return item
}

final class InventorySnapshotStoreTests: XCTestCase {
    func testSaveListLatestResolveAndLoad() throws {
        let root = tempRoot("store")
        defer { try? FileManager.default.removeItem(atPath: root) }
        let store = InventorySnapshotStore(root: root)
        XCTAssertTrue(store.list().isEmpty)
        XCTAssertNil(store.resolve(nil))

        let first = try store.save(InventorySnapshot(version: "0.6.1", host: "mac", name: "baseline",
                                                     incompleteLayers: [], items: [item("a")]),
                                   at: Date(timeIntervalSince1970: 1_800_000_000))
        let second = try store.save(InventorySnapshot(version: "0.6.1", host: "mac", incompleteLayers: ["lsof"],
                                                      items: [item("a"), item("b")]),
                                    at: Date(timeIntervalSince1970: 1_800_000_100))
        XCTAssertTrue(first.hasSuffix("2027-01-15-080000Z-baseline.json"), first)
        let entries = store.list()
        XCTAssertEqual(entries.map(\.file), [second, first], "newest first")
        XCTAssertEqual(entries[0].itemCount, 2)
        XCTAssertTrue(entries[0].incomplete)
        XCTAssertEqual(entries[1].name, "baseline")
        XCTAssertEqual(store.latest()?.file, second)
        XCTAssertEqual(store.resolve("baseline"), first, "by name")
        XCTAssertEqual(store.resolve("2027-01-15-080000Z-baseline"), first, "by file name without extension")
        XCTAssertEqual(store.resolve(first), first, "by path")
        XCTAssertNil(store.resolve("nope"))
        XCTAssertEqual(try store.load(path: first).items.map(\.key), ["a"])
    }

    func testLoadsABareListJSONArray() throws {
        let root = tempRoot("bare")
        defer { try? FileManager.default.removeItem(atPath: root) }
        try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
        let path = root + "/list.json"
        try Data(JSONRenderer.encode([item("x")]).utf8).write(to: URL(fileURLWithPath: path))
        let snapshot = try InventorySnapshotStore(root: root).load(path: path)
        XCTAssertEqual(snapshot.items.map(\.key), ["x"])
        XCTAssertEqual(snapshot.name, "list.json")
    }

    func testSnapshotNameIsSanitized() {
        XCTAssertEqual(InventorySnapshotStore.safeName("before upgrade/2!"), "before-upgrade-2-")
    }
}

final class InventoryDiffTests: XCTestCase {
    func testAddedRemovedChangedAndVolatileStateIgnored() {
        let before = [item("a", enabled: true, signature: "signed", running: true),
                      item("gone"),
                      item("same", running: false)]
        let after = [item("a", enabled: false, signature: "unsigned", running: false, metadata: ["listening": "tcp/8443"]),
                     item("new", path: "/Library/LaunchDaemons/new.plist"),
                     item("same", running: true)]
        let diff = InventoryDiff.compare(before: before, after: after, beforeLabel: "snap", afterLabel: "now")
        XCTAssertEqual(diff.added.map(\.key), ["new"])
        XCTAssertEqual(diff.removed.map(\.key), ["gone"])
        XCTAssertEqual(diff.changed.map(\.key), ["a"], "running alone is not a change")
        let changes = diff.changed[0].changes
        XCTAssertEqual(changes.map(\.field), ["enabled", "signature", "listening"])
        XCTAssertEqual(changes[0].before, "true"); XCTAssertEqual(changes[0].after, "false")
        XCTAssertEqual(changes[2].before, "-"); XCTAssertEqual(changes[2].after, "tcp/8443")
        XCTAssertFalse(diff.isEmpty)
        let text = diff.renderText()
        XCTAssertTrue(text.contains("+ new [launch-items/daemon] /Library/LaunchDaemons/new.plist"), text)
        XCTAssertTrue(text.contains("- gone"), text)
        XCTAssertTrue(text.contains("    enabled: true → false"), text)
        XCTAssertTrue(text.hasSuffix("1 added, 1 removed, 1 changed"), text)

        let withState = InventoryDiff.compare(before: before, after: after, includeState: true,
                                              beforeLabel: "snap", afterLabel: "now")
        XCTAssertEqual(withState.changed.map(\.key), ["a", "same"])
        XCTAssertEqual(withState.changed[1].changes.map(\.field), ["running"])
    }

    func testNoChangesAndAppleFiltering() {
        let apple = item("com.apple.thing", signature: "apple-system")
        let same = [item("a"), apple]
        let none = InventoryDiff.compare(before: same, after: same, beforeLabel: "x", afterLabel: "y")
        XCTAssertTrue(none.isEmpty)
        XCTAssertTrue(none.renderText().contains("no changes"))
        let withApple = InventoryDiff.compare(before: [item("a")], after: same, beforeLabel: "x", afterLabel: "y")
        XCTAssertEqual(withApple.added.map(\.key), ["com.apple.thing"])
        XCTAssertTrue(withApple.filtered(includeAll: false).isEmpty, "Apple internals hidden like in list")
        XCTAssertFalse(withApple.filtered(includeAll: true).isEmpty)
    }

    func testDiffRoundTripsThroughJSON() throws {
        let diff = InventoryDiff.compare(before: [item("a")], after: [item("a", enabled: false)],
                                         beforeLabel: "x", afterLabel: "y")
        let text = try JSONRenderer.encode(diff)
        let decoded = try JSONDecoder().decode(InventoryDiff.self, from: Data(text.utf8))
        XCTAssertEqual(decoded, diff)
    }
}

final class ExportRendererTests: XCTestCase {
    func testCSVEscapesAndMarkdownTable() {
        var tricky = item("com.vendor, \"quoted\"", path: "/Library/LaunchDaemons/a|b.plist")
        tricky.displayName = "Name, with comma"
        tricky.orphanReasons = ["executable missing: /x", "second"]
        tricky.provenance = Provenance(kind: .receipt, packageIdentifier: "com.vendor.pkg", installedAt: "2026-01-01")
        let csv = ExportRenderer.csv([tricky])
        let lines = csv.components(separatedBy: "\n")
        XCTAssertEqual(lines[0], ExportRenderer.columns.joined(separator: ","))
        XCTAssertTrue(lines[1].contains("\"com.vendor, \"\"quoted\"\"\""), lines[1])
        XCTAssertTrue(lines[1].contains("\"Name, with comma\""), lines[1])
        XCTAssertTrue(lines[1].contains(",receipt,com.vendor.pkg,2026-01-01,"), lines[1])
        XCTAssertTrue(lines[1].contains("executable missing: /x; second"), lines[1])
        XCTAssertEqual(lines[1].split(separator: ",", omittingEmptySubsequences: false).count >= ExportRenderer.columns.count, true)

        let md = ExportRenderer.markdown([tricky])
        let rows = md.components(separatedBy: "\n")
        XCTAssertTrue(rows[0].hasPrefix("| ID | Category |"), rows[0])
        XCTAssertTrue(rows[1].hasPrefix("| --- |"), rows[1])
        XCTAssertTrue(rows[2].contains("`/Library/LaunchDaemons/a\\|b.plist`"), "pipes escaped: \(rows[2])")
        XCTAssertTrue(rows[2].contains("receipt (com.vendor.pkg)"), rows[2])
    }
}

final class StableKeyTests: XCTestCase {
    func testNetworkPmsetAndCronKeysCarryNoVolatileParts() {
        var network = NetworkScanner.Result()
        network.processes = [
            ListeningProcess(pid: 10, command: "python", user: "alice", executable: "/opt/py/bin/python",
                             sockets: [ListeningSocket(pid: 10, command: "python", user: "alice", proto: "tcp", address: "*:8000")]),
            ListeningProcess(pid: 11, command: "python", user: "alice", executable: "/opt/py/bin/python",
                             sockets: [ListeningSocket(pid: 11, command: "python", user: "alice", proto: "tcp", address: "*:8001")]),
        ]
        var scheduled = ScheduledScanner.Result()
        scheduled.powerEvents = [PowerEvent(index: 0, kind: "wake", when: "09/22/2026 16:38:36", owner: "com.vendor.agent", userVisible: false),
                                 PowerEvent(index: 1, kind: "wake", when: "09/23/2026 16:38:36", owner: "com.vendor.agent", userVisible: false)]
        scheduled.cron = [CronEntry(user: "alice", source: "crontab", line: 7, schedule: "0 3 * * *", command: "/opt/x/run")]
        let items = ItemCorrelator().correlate(.init(jobs: [], launchd: [], btm: [], disabled: [:], uid: 501,
                                                     scheduled: scheduled, network: network)).items
        let keys = Set(items.map(\.key))
        XCTAssertTrue(keys.contains("net:/opt/py/bin/python"), "\(keys)")
        XCTAssertTrue(keys.contains("net:/opt/py/bin/python#2"), "twins get a suffix: \(keys)")
        XCTAssertTrue(keys.contains("pmset:com.vendor.agent:wake") && keys.contains("pmset:com.vendor.agent:wake#2"), "\(keys)")
        XCTAssertTrue(keys.contains("cron:alice:crontab:/opt/x/run"), "\(keys)")
        XCTAssertEqual(items.first { $0.key == "net:/opt/py/bin/python#2" }?.metadata["net-pid"], "11")
    }
}
