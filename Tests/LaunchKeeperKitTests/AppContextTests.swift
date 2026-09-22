import XCTest
@testable import LaunchKeeperKit

// V0.4 app-correlation tests. HERMETIC as everything else: bundle trees in a
// temp directory, mdfind through ScriptedCommandRunner, the file system via
// FileManager against the temp root. Two rules drive the suite:
//   1. App context must never manufacture evidence: relative paths are
//      skipped, a missing bundle id means no Spotlight call, a wedged or
//      erroring index degrades to "unknown" — never to "missing".
//   2. Spotlight is an INDEPENDENT second source: it may confirm a hard
//      orphan ("gone everywhere"), or soften the semantics ("relocated"),
//      but it never contradicts the file-system fact.

private func tempRoot(_ tag: String) -> String {
    FileManager.default.temporaryDirectory
        .appendingPathComponent("launchkeeper-appcontext-\(tag)-\(UUID().uuidString)", isDirectory: true).path
}

/// Creates `<root>/Applications/<name>.app` with an Info.plist
/// (CFBundleIdentifier/CFBundleName/team) — or nothing, when `exists` is
/// false (the deleted-bundle scenario).
private func makeAppBundle(at root: String, name: String, bundleID: String,
                           team: String? = "T1TEAM", exists: Bool = true) -> String {
    let fm = FileManager.default
    let bundle = "\(root)/Applications/\(name).app"
    guard exists else { return bundle }
    let contents = bundle + "/Contents"
    try? fm.createDirectory(atPath: contents, withIntermediateDirectories: true)
    var info: [String: Any] = ["CFBundleIdentifier": bundleID, "CFBundleName": name]
    if let team { info["CFBundleTeamIdentifier"] = team }
    if let data = try? PropertyListSerialization.data(fromPropertyList: info,
                                                     format: .binary, options: 0) {
        try? data.write(to: URL(fileURLWithPath: contents + "/Info.plist"))
    }
    return bundle
}

private func mdfindKey(_ bundleID: String) -> String {
    "/usr/bin/mdfind kMDItemCFBundleIdentifier == '\(bundleID)'"
}

// MARK: - Deepest-bundle extraction (string-based)

final class AppBundlePathTests: XCTestCase {
    func testExecutableDeepInsideBundleFindsDeepestApp() {
        XCTAssertEqual(
            AppContextResolver.enclosingAppBundle(
                path: "/a/Applications/Foo.app/Contents/PlugIns/Bar.appex/Contents/MacOS/Bar"),
            "/a/Applications/Foo.app")
    }

    func testPlistUnderBundleContentsResolvesToBundle() {
        XCTAssertEqual(
            AppContextResolver.enclosingAppBundle(
                path: "/a/Applications/Foo.app/Contents/Library/LaunchAgents/com.x.helper.plist"),
            "/a/Applications/Foo.app")
    }

    func testPathThatIsItselfABundleReturnsItself() {
        XCTAssertEqual(AppContextResolver.enclosingAppBundle(path: "/Applications/Foo.app"),
                       "/Applications/Foo.app")
    }

    func testPlainPathWithoutBundleIsNil() {
        XCTAssertNil(AppContextResolver.enclosingAppBundle(path: "/opt/homebrew/bin/tool"))
        XCTAssertNil(AppContextResolver.enclosingAppBundle(
            path: "/Users/j/Library/LaunchAgents/com.x.plist"))
    }

    func testRelativePathIsSkippedByDesign() {
        XCTAssertNil(AppContextResolver.enclosingAppBundle(path: "Contents/PlugIns/Thing.appex"))
        XCTAssertNil(AppContextResolver.enclosingAppBundle(path: nil))
    }

    func testAppdirSuffixDoesNotMatch() {
        XCTAssertNil(AppContextResolver.enclosingAppBundle(path: "/x/my.appdir/foo"))
    }
}

// MARK: - Resolver behavior

final class AppContextResolverTests: XCTestCase {
    private let root = tempRoot("resolver")
    private var fm = FileManager.default

    override func setUp() {
        super.setUp()
        fm = FileManager.default
    }

    private func item(exec: String?, path: String?, bundleID: String? = nil) -> BackgroundItem {
        BackgroundItem(key: "k", displayName: "k", path: path, executable: exec,
                       bundleIdentifier: bundleID)
    }

    private func resolve(_ item: BackgroundItem,
                         responses: [String: CommandResult] = [:]) -> BackgroundItem {
        var items = [item]
        var resolver = AppContextResolver(fileManager: fm,
                                          runner: ScriptedCommandRunner(responses: responses,
                                                                       defaultResult: CommandResult(
                                                                            exitCode: 127, stdout: "",
                                                                            stderr: "not scripted")))
        resolver.apply(to: &items)
        return items[0]
    }

    func testPresentBundleEnrichesItem() {
        _ = makeAppBundle(at: root, name: "Foo", bundleID: "com.test.foo")
        let out = resolve(item(exec: root + "/Applications/Foo.app/Contents/MacOS/Foo", path: nil))
        XCTAssertEqual(out.parentApplication, "Foo")
        XCTAssertTrue(out.appPresent == true)
        XCTAssertEqual(out.bundleIdentifier, "com.test.foo")
        XCTAssertEqual(out.teamIdentifier, "T1TEAM")
        XCTAssertEqual(out.metadata["app-gone-confirmed"], "present")
    }

    func testMissingBundleWithoutIdStaysUnknownAndNeverQueries() {
        _ = makeAppBundle(at: root, name: "Gone", bundleID: "com.test.gone", exists: false)
        var items = [item(exec: root + "/Applications/Gone.app/Contents/MacOS/gone",
                          path: nil)]
        var resolver = AppContextResolver(fileManager: fm,
                                          runner: ScriptedCommandRunner())
        resolver.apply(to: &items)
        let item = items[0]
        XCTAssertFalse(item.appPresent == true)
        XCTAssertEqual(item.metadata["app-gone-confirmed"], "unknown")
        XCTAssertTrue(resolver.spotlightQueries.isEmpty,
                      "no bundle id -> no Spotlight call; an id the item itself owns "
                      + "is not its parent's")
    }

    func testMissingBundleWithIdSpotlightConfirmsGone() {
        _ = makeAppBundle(at: root, name: "Gone", bundleID: "com.test.gone", exists: false)
        let out = resolve(item(exec: root + "/Applications/Gone.app/Contents/MacOS/gone",
                               path: nil, bundleID: "com.test.gone"),
                          responses: [mdfindKey("com.test.gone"):
                                      CommandResult(exitCode: 0, stdout: "", stderr: "")])
        XCTAssertFalse(out.appPresent == true)
        XCTAssertEqual(out.metadata["app-gone-confirmed"], "missing")
    }

    func testMissingBundleWithIdSpotlightFindsItElsewhere() {
        _ = makeAppBundle(at: root, name: "Gone", bundleID: "com.test.gone", exists: false)
        let out = resolve(item(exec: root + "/Applications/Gone.app/Contents/MacOS/gone",
                               path: nil, bundleID: "com.test.gone"),
                          responses: [mdfindKey("com.test.gone"):
                                      CommandResult(exitCode: 0,
                                                    stdout: "/Other/Place/Gone.app\n", stderr: "")])
        XCTAssertTrue(out.appPresent == true,
                      "installed at a different location -> the app exists; "
                      + "only its former home is gone")
        XCTAssertEqual(out.metadata["app-gone-confirmed"], "relocated")
        XCTAssertEqual(out.metadata["app-spotlight"], "/Other/Place/Gone.app")
    }

    func testMdfindTimeoutDegradesToUnknownNeverMissing() {
        _ = makeAppBundle(at: root, name: "Gone", bundleID: "com.test.gone", exists: false)
        let out = resolve(item(exec: root + "/Applications/Gone.app/Contents/MacOS/gone",
                               path: nil, bundleID: "com.test.gone"),
                          responses: [mdfindKey("com.test.gone"):
                                      CommandResult(exitCode: -2, stdout: "",
                                                    stderr: "timeout")])
        XCTAssertFalse(out.appPresent == true)
        XCTAssertEqual(out.metadata["app-gone-confirmed"], "unknown",
                       "a wedged index is NOT evidence the app is gone — "
                       + "it must not manufacture an orphan signal")
        XCTAssertEqual(AppContextResolver(fileManager: fm,
                                          runner: ScriptedCommandRunner(responses: [:]))
            .spotlightAvailable, nil)
    }

    func testMdfindErrorDegradesToUnknown() {
        _ = makeAppBundle(at: root, name: "Gone", bundleID: "com.test.gone", exists: false)
        let out = resolve(item(exec: root + "/Applications/Gone.app/Contents/MacOS/gone",
                               path: nil, bundleID: "com.test.gone"),
                          responses: [mdfindKey("com.test.gone"):
                                      CommandResult(exitCode: 64, stdout: "",
                                                    stderr: "index error")])
        XCTAssertEqual(out.metadata["app-gone-confirmed"], "unknown")
    }

    func testSpotlightQueryIsCachedAcrossItems() {
        _ = makeAppBundle(at: root, name: "Gone", bundleID: "com.test.gone", exists: false)
        var items = [
            item(exec: root + "/Applications/Gone.app/Contents/MacOS/gone",
                 path: nil, bundleID: "com.test.gone"),
            item(exec: root + "/Applications/Gone.app/Contents/PlugIns/H.appex/MacOS/h",
                 path: nil, bundleID: "com.test.gone"),
        ]
        var resolver = AppContextRunnerHolder.make(responses: [mdfindKey("com.test.gone"):
            CommandResult(exitCode: 0, stdout: "", stderr: "")])
        resolver.apply(to: &items)
        XCTAssertEqual(resolver.spotlightQueries, ["com.test.gone"],
                       "one DISTINCT bundle id -> exactly one mdfind, no repeated process")
    }

    func testRelativePathLeavesItemUntouched() {
        let out = resolve(item(exec: "Contents/PlugIns/Thing.appex", path: "Contents/x"))
        XCTAssertNil(out.parentApplication)
        XCTAssertNil(out.appPresent)
        XCTAssertNil(out.metadata["app-gone-confirmed"])
    }
}

/// Tiny helper so the cache test can keep the same runner instance the
/// resolver used (ScriptedCommandRunner is a value type; the resolver copies
/// its responses but the QUERY LOG lives on the resolver).
private enum AppContextRunnerHolder {
    static func make(responses: [String: CommandResult]) -> AppContextResolver {
        AppContextResolver(runner: ScriptedCommandRunner(responses: responses,
                                                         defaultResult: CommandResult(
                                                             exitCode: 127, stdout: "",
                                                             stderr: "not scripted")))
    }
}

// MARK: - Integration with OrphanDetector

final class AppContextOrphanIntegrationTests: XCTestCase {
    private let root = tempRoot("orphan")

    func testSpotlightConfirmationAddsHardOrphanReason() {
        let fm = FileManager.default
        _ = makeAppBundle(at: root, name: "Gone", bundleID: "com.test.gone", exists: false)
        var items = [BackgroundItem(key: "gone", displayName: "gone",
                                    executable: root + "/Applications/Gone.app/Contents/MacOS/gone",
                                    bundleIdentifier: "com.test.gone")]
        var resolver = AppContextResolver(fileManager: fm,
                                          runner: ScriptedCommandRunner(responses: [
                                              mdfindKey("com.test.gone"):
                                                  CommandResult(exitCode: 0, stdout: "",
                                                                stderr: "")]))
        resolver.apply(to: &items)
        OrphanDetector(fileManager: fm).apply(to: &items)

        XCTAssertTrue(items[0].orphaned)
        XCTAssertEqual(items[0].orphanConfidence, .high)
        XCTAssertTrue(items[0].orphanReasons.contains { $0.contains("not found via Spotlight") },
                      "actual: \(items[0].orphanReasons)")
    }

    func testRelocatedAppDoesNotTriggerBundleMissingReason() {
        let fm = FileManager.default
        _ = makeAppBundle(at: root, name: "Gone", bundleID: "com.test.gone", exists: false)
        var items = [BackgroundItem(key: "gone", displayName: "gone",
                                    executable: root + "/Applications/Gone.app/Contents/MacOS/gone",
                                    bundleIdentifier: "com.test.gone")]
        var resolver = AppContextResolver(fileManager: fm,
                                          runner: ScriptedCommandRunner(responses: [
                                              mdfindKey("com.test.gone"):
                                                  CommandResult(exitCode: 0,
                                                                stdout: "/Other/Gone.app\n",
                                                                stderr: "")]))
        resolver.apply(to: &items)
        OrphanDetector(fileManager: fm).apply(to: &items)

        // The configured path IS dead (file-system fact) — but the app exists
        // elsewhere, so the bundle-missing semantic must not be reported.
        XCTAssertTrue(items[0].orphaned)
        XCTAssertFalse(items[0].orphanReasons.contains { $0.contains("bundle missing") },
                       "actual: \(items[0].orphanReasons)")
        XCTAssertFalse(items[0].orphanReasons.contains { $0.contains("Spotlight") },
                       "actual: \(items[0].orphanReasons)")
    }

    func testUnknownConfirmationAddsNoSpotlightReason() {
        let fm = FileManager.default
        _ = makeAppBundle(at: root, name: "Gone", bundleID: "com.test.gone", exists: false)
        var items = [BackgroundItem(key: "gone", displayName: "gone",
                                    executable: root + "/Applications/Gone.app/Contents/MacOS/gone",
                                    bundleIdentifier: "com.test.gone")]
        var resolver = AppContextResolver(fileManager: fm,
                                          runner: ScriptedCommandRunner(
                                              responses: [mdfindKey("com.test.gone"):
                                                  CommandResult(exitCode: -2, stdout: "",
                                                                stderr: "timeout")]))
        resolver.apply(to: &items)
        OrphanDetector(fileManager: fm).apply(to: &items)

        XCTAssertFalse(items[0].orphanReasons.contains { $0.contains("Spotlight") },
                       "a failed index is not evidence — actual: \(items[0].orphanReasons)")
    }
}

// MARK: - Table: dynamic APP column

final class TableAppColumnTests: XCTestCase {
    private func plain() -> BackgroundItem {
        BackgroundItem(key: "plain", displayName: "plain-service",
                       executable: "/opt/homebrew/bin/thing")
    }

    private func withApp() -> BackgroundItem {
        var item = BackgroundItem(key: "helper", displayName: "helper",
                                  executable: "/Applications/Foo.app/Contents/MacOS/Foo")
        item.parentApplication = "Foo"
        item.appPresent = true
        return item
    }

    func testAppColumnAppearsWhenAnyItemHasAParent() {
        let out = TableRenderer.render([plain(), withApp()], mode: .table)
        XCTAssertTrue(out.contains("APP"), "actual:\n\(out)")
        XCTAssertTrue(out.contains("Foo"), "actual:\n\(out)")
    }

    func testAppColumnAbsentWhenNoItemHasAParent() {
        let out = TableRenderer.render([plain(), plain()], mode: .table)
        XCTAssertFalse(out.contains("APP"), "a column of dashes would be noise:\n\(out)")
    }

    func testOrphansModeIsUnchanged() {
        var item = withApp()
        item.orphaned = true
        item.orphanReasons = ["executable missing: /Applications/Foo.app/Contents/MacOS/Foo"]
        let out = TableRenderer.render([item], mode: .orphans)
        XCTAssertFalse(out.contains("APP"), "orphans mode keeps its compact layout:\n\(out)")
    }
}