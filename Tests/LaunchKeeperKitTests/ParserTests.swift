import XCTest
@testable import LaunchKeeperKit

final class BTMDumpParserTests: XCTestCase {
    private var text: String { Fixtures.text("dumpbtm-nosudo.txt") }

    func testFixturesPresent() {
        XCTAssertTrue(Fixtures.exists("dumpbtm-nosudo.txt"), "fixture missing: dumpbtm-nosudo.txt")
        XCTAssertTrue(Fixtures.exists("launchctl-gui.txt"), "fixture missing: launchctl-gui.txt")
        XCTAssertTrue(Fixtures.exists("disabled-gui.txt"), "fixture missing: disabled-gui.txt")
    }

    func testRealDumpParsesRecords() {
        let (records, warnings) = BTMDumpParser.parse(text)
        XCTAssertGreaterThan(records.count, 50, "real dump must yield many records")
        // Known noisy field must be preserved, not flagged as unparsable.
        XCTAssertFalse(warnings.contains { $0.contains("Assoc. Bundle IDs") },
                       "Assoc. Bundle IDs must not warn: \(warnings.prefix(5))")
        XCTAssertTrue(warnings.isEmpty, "clean real dump should produce no warnings: \(warnings)")
    }

    func testKnownRecordFields() {
        let (records, _) = BTMDumpParser.parse(text)
        let guardRec = records.first { $0.identifier == "16.de.example.automount-guard" }
        guard let rec = guardRec else {
            return XCTFail("automount-guard record missing from real dump")
        }
        XCTAssertEqual(rec.typeDescription, "legacy daemon")
        XCTAssertEqual(rec.url, "/Library/LaunchDaemons/de.example.automount-guard.plist")
        XCTAssertEqual(rec.executablePath, "/usr/local/bin/automount-guard.sh")
        XCTAssertEqual(rec.isEnabled, true)
        // The record sits inside the leading "Records for UID -2" section.
        XCTAssertEqual(rec.sectionUID, -2)
    }

    func testRelativeExecutablePathIgnored() {
        let (records, _) = BTMDumpParser.parse(text)
        for rec in records {
            if let exec = rec.executablePath {
                XCTAssertTrue(exec.hasPrefix("/"), "relative exec leaked through: \(exec)")
            }
        }
    }

    func testSyntheticSectionChildrenAndMalformedLine() {
        let sample = """
        Records for UID 501 : FFFF-AAAA
         #1:
                      Name: thing
                      Type: login item (0x4)
                Disposition: [enabled, allowed, notified] (0xb)
                Identifier: 4.com.example.thing
            Parent Identifier: 4.com.example.app
            Embedded Item Identifiers:
              #1: 4.com.example.child
        this line is complete garbage
        """
        let (records, warnings) = BTMDumpParser.parse(sample)
        XCTAssertEqual(records.count, 1)
        let rec = records[0]
        XCTAssertEqual(rec.sectionUID, 501)
        XCTAssertEqual(rec.typeDescription, "login item")
        XCTAssertEqual(rec.parentIdentifier, "4.com.example.app")
        XCTAssertEqual(rec.trailingBlock, ["4.com.example.child"])
        // Malformed line must not abort the parse, unknown fields kept.
        XCTAssertEqual(rec.fields["Name"], "thing")
    }
}

final class LaunchctlParserTests: XCTestCase {
    func testRealGuiDump() {
        let records = LaunchctlParser.parsePrint(Fixtures.text("launchctl-gui.txt"), domainKind: "gui")
        XCTAssertGreaterThan(records.count, 100)

        // Not-running line shape: "0   0   com.vendorkit...Updater" (pid token 0).
        let shipIt = records.first { $0.label == "com.vendorkit.a1b2c3d4e5f6g7h.Updater" }
        XCTAssertNotNil(shipIt)
        XCTAssertNil(shipIt?.pid, "pid token 0 means not running")
        XCTAssertEqual(shipIt?.stateToken, "0")

        let sync = records.first { $0.label == "com.apple.syncdefaultsd" }
        XCTAssertEqual(sync?.pid, 30475)
        XCTAssertEqual(sync?.stateToken, "(pe)")
    }

    func testInstanceServiceFilter() {
        XCTAssertTrue(LaunchctlParser.isInstanceService(
            "com.apple.neagent.878568F8-CCE5-4157-8315-22F20DC8FB0A"))
        XCTAssertFalse(LaunchctlParser.isInstanceService("com.apple.lskdd"))
        XCTAssertFalse(LaunchctlParser.isInstanceService("de.example.automount-guard"))
        // Third-party app updater must stay visible despite its numeric middle part.
        XCTAssertFalse(LaunchctlParser.isInstanceService("com.vendorkit.a1b2c3d4e5f6g7h.Updater"))
    }

    func testDisabledParsing() {
        let disabled = LaunchctlParser.parseDisabled(Fixtures.text("disabled-gui.txt"))
        XCTAssertEqual(disabled["com.searchco.updater.agent"], false)
        XCTAssertEqual(disabled["com.whale.helper"], true)
        XCTAssertFalse(disabled.isEmpty)
    }
}

final class PlistReaderTests: XCTestCase {
    func testProgramArgumentsExtraction() {
        let dict: [String: Any] = [
            "Label": "com.example.script",
            "ProgramArguments": ["/bin/bash", "/opt/tools/x.sh"],
            "RunAtLoad": true,
            "ThrottleInterval": 30,
        ]
        let job = PlistReader.extractJob(dict: dict)
        XCTAssertEqual(job.program, "/bin/bash")
        XCTAssertEqual(job.arguments, ["/opt/tools/x.sh"])
        XCTAssertTrue(job.runAtLoad)
        XCTAssertTrue(job.unknownKeys.contains("ThrottleInterval"),
                      "unknown keys must be preserved")
    }

    func testMalformedFileThrows() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("launchkeeper-tests-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let bad = dir.appendingPathComponent("com.example.bad.plist")
        try Data("this is not a plist at all".utf8).write(to: bad)
        XCTAssertThrowsError(try PlistReader.readDictionary(fromFile: bad.path))
        try? FileManager.default.removeItem(at: dir)
    }
}
/// V0.4.1: `URL:` arrives percent-encoded on macOS 26 and as a plain path on
/// macOS 27. Either way the record must expose the on-disk path — a `%20`
/// that survives into a file probe is a guaranteed false negative.
final class BTMURLNormalizationTests: XCTestCase {
    private func record(url: String, exec: String? = nil) -> BTMRecord {
        var fields = ["Name": "x", "Type": "app (0x2)", "URL": url]
        if let exec { fields["Executable Path"] = exec }
        return BTMRecord(sectionUID: 501, fields: fields)
    }

    func testPercentEncodedFileURLIsDecoded() {
        XCTAssertEqual(record(url: "file:///Applications/My%20App.app/").url,
                       "/Applications/My App.app")
        XCTAssertEqual(record(url: "file:///Users/j/Library/LaunchAgents/Some%20Vendor%20Agent.plist").url,
                       "/Users/j/Library/LaunchAgents/Some Vendor Agent.plist")
    }

    func testRelativeEncodedFragmentIsDecodedButStaysRelative() {
        XCTAssertEqual(record(url: "Contents/PlugIns/Vendor%20QL%20Extension.appex").url,
                       "Contents/PlugIns/Vendor QL Extension.appex")
    }

    func testMacOS27PlainPathIsUnchanged() {
        XCTAssertEqual(record(url: "/Applications/Vendor.app").url, "/Applications/Vendor.app")
        XCTAssertEqual(record(url: "Contents/PlugIns/Vendor QL Extension.appex").url,
                       "Contents/PlugIns/Vendor QL Extension.appex")
    }

    func testNullAndEmptyStayNil() {
        XCTAssertNil(record(url: "(null)").url)
        XCTAssertNil(record(url: "").url)
    }

    func testExecutablePathIsDecodedAndStillAbsoluteOnly() {
        XCTAssertEqual(record(url: "x", exec: "/Applications/My%20App.app/Contents/MacOS/helper").executablePath,
                       "/Applications/My App.app/Contents/MacOS/helper")
        XCTAssertNil(record(url: "x", exec: "Contents/MacOS/helper").executablePath)
    }

    func testUndecodableInputIsKeptVerbatim() {
        // A lone "%" is not a valid escape; the raw path is better than nothing.
        XCTAssertEqual(record(url: "/tmp/100%").url, "/tmp/100%")
    }
}
