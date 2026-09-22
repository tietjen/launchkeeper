import XCTest
@testable import BTMKit

/// Orphan detection must stay conservative: a missing on-disk target proves
/// breakage; anything unresolvable stays unflagged. Confidence levels matter.
final class OrphanDetectorTests: XCTestCase {
    private func apply(_ item: BackgroundItem) -> BackgroundItem {
        var items = [item]
        OrphanDetector().apply(to: &items)
        return items[0]
    }

    func testMissingAbsoluteExecutableIsHighConfidence() {
        var item = BackgroundItem(key: "de.x.gone", displayName: "gone", type: .launchDaemon)
        item.executable = "/nonexistent-xyz-dir/gone-tool"
        let result = apply(item)
        XCTAssertTrue(result.orphaned)
        XCTAssertEqual(result.orphanConfidence, .high)
        XCTAssertTrue(result.orphanReasons.contains { $0.hasPrefix("executable missing") })
    }

    func testExistingExecutableIsNotOrphaned() {
        var item = BackgroundItem(key: "de.x.ok", displayName: "ok", type: .launchDaemon)
        item.executable = "/bin/ls"           // exists on every macOS
        item.arguments = []
        let result = apply(item)
        XCTAssertFalse(result.orphaned, "healthy item must not be flagged: \(result.orphanReasons)")
    }

    func testRelativeExecutableFragmentIsNotEvidence() {
        // Spec-critical: relative "Contents/…" fragments from BTM records are
        // unresolvable by design — treating them as missing would be false positives.
        var item = BackgroundItem(key: "btm:16.com.example.app.helper", displayName: "app.helper",
                                  type: .helper)
        item.executable = "Contents/Helpers/Foo Helper"
        item.arguments = ["Contents/Frameworks/gone.framework"]
        item.btmPresent = true
        let result = apply(item)
        XCTAssertFalse(result.orphaned, "relative paths must never flag: \(result.orphanReasons)")
    }

    func testShellInterpreterWithMissingScriptArgument() {
        var item = BackgroundItem(key: "de.x.script", displayName: "script", type: .launchDaemon)
        item.executable = "/bin/bash"          // exists
        item.arguments = ["/nonexistent-xyz-dir/gone.sh"]
        let result = apply(item)
        XCTAssertTrue(result.orphaned)
        XCTAssertEqual(result.orphanConfidence, .medium)
        XCTAssertTrue(result.orphanReasons.contains { $0.hasPrefix("script argument missing") })
    }

    func testMissingParentAppBundle() {
        var item = BackgroundItem(key: "btm:helper", displayName: "Helper", type: .helper)
        item.executable = "/bin/ls"   // exists, so only the dead parent can flag
        item.parentApplication = "Ghost.app"
        item.appPresent = false
        item.running = false
        let result = apply(item)
        XCTAssertTrue(result.orphaned)
        XCTAssertEqual(result.orphanConfidence, .medium, "not running => medium")
        XCTAssertTrue(result.orphanReasons.contains("parent application bundle missing"))
    }

    func testRunningItemWithMissingParentEscalatesToHigh() {
        var item = BackgroundItem(key: "btm:helper2", displayName: "Helper2", type: .helper)
        item.parentApplication = "Ghost.app"
        item.appPresent = false
        item.running = true
        let result = apply(item)
        XCTAssertEqual(result.orphanConfidence, .high, "live process, dead parent")
    }

    /// V0.4.4: a BTM record whose plist is gone and that no launchd job backs
    /// is a LEFTOVER — the trail of a component already removed, not a broken
    /// one. One reason, low confidence, flagged for the table; the earlier
    /// "BTM entry without backing plist"/"executable missing" reasons would
    /// have presented it as an open work item right after a clean `remove`.
    func testBtmLeftoverIsOneLowConfidenceNote() {
        var item = BackgroundItem(key: "btm:16.de.x.ghost", displayName: "ghost", type: .btmEntry)
        item.btmPresent = true
        item.plistPresent = false
        item.launchdPresent = false
        item.path = "/Library/LaunchAgents/de.x.ghost.plist"   // absent by construction
        item.executable = "/Applications/Ghost.app/Contents/MacOS/ghost"   // absent too
        let result = apply(item)
        XCTAssertTrue(result.orphaned)
        XCTAssertEqual(result.orphanConfidence, .low)
        XCTAssertEqual(result.orphanReasons.count, 1, "one note, not a pile: \(result.orphanReasons)")
        XCTAssertTrue(result.orphanReasons[0].hasPrefix("BTM leftover"), result.orphanReasons[0])
        XCTAssertEqual(result.metadata["btm-leftover"], "true")
        XCTAssertTrue(TableRenderer.render([result], mode: .table).contains("LEFTOVER"))
        XCTAssertFalse(TableRenderer.render([result], mode: .table).contains("ORPHAN"))
    }

    func testPlistBackedEntryWithMissingExecutableStaysAHardOrphan() {
        // Same shape, but the plist is still on disk: a real broken component.
        var item = BackgroundItem(key: "de.x.broken", displayName: "broken", type: .launchAgentSystem)
        item.btmPresent = true
        item.plistPresent = true
        item.path = "/Library/LaunchAgents/de.x.broken.plist"
        item.executable = "/Applications/Ghost.app/Contents/MacOS/ghost"
        let result = apply(item)
        XCTAssertEqual(result.orphanConfidence, .high)
        XCTAssertTrue(result.orphanReasons.contains { $0.hasPrefix("executable missing") })
        XCTAssertNil(result.metadata["btm-leftover"])
        XCTAssertTrue(TableRenderer.render([result], mode: .table).contains("ORPHAN"))
    }

    func testLaunchdBackedBtmEntryIsNotALeftover() {
        // launchd still holds the job → the zombie shape: not a leftover,
        // the executable-missing reason stays (and `remove` points at disable).
        var item = BackgroundItem(key: "de.x.zombie", displayName: "zombie", type: .unknown)
        item.btmPresent = true
        item.launchdPresent = true
        item.loaded = true
        item.executable = "/Applications/Ghost.app/Contents/MacOS/ghost"
        let result = apply(item)
        XCTAssertEqual(result.orphanConfidence, .high)
        XCTAssertNil(result.metadata["btm-leftover"])
    }
}
