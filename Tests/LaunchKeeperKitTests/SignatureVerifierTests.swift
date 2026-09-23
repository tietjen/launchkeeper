import XCTest
@testable import LaunchKeeperKit

// V0.6.2: inspect --verify.

private func tempRoot(_ tag: String) -> String {
    FileManager.default.temporaryDirectory
        .appendingPathComponent("lk-v062-\(tag)-\(UUID().uuidString)", isDirectory: true).path
}

final class SignatureVerifierTests: XCTestCase {
    func testBinaryAcceptedWithChainRuntimeAndHash() throws {
        let root = tempRoot("bin")
        defer { try? FileManager.default.removeItem(atPath: root) }
        try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
        let binary = root + "/tool"
        try Data("hello".utf8).write(to: URL(fileURLWithPath: binary))
        let runner = ScriptedCommandRunner(responses: [
            "/usr/bin/codesign --verify --strict -v \(binary)":
                CommandResult(exitCode: 0, stdout: "", stderr: "\(binary): valid on disk\n\(binary): satisfies its Designated Requirement\n"),
            "/usr/bin/codesign -dvvv \(binary)": CommandResult(exitCode: 0, stdout: "", stderr: """
                Executable=\(binary)
                Identifier=org.example.tool
                Format=Mach-O universal (x86_64 arm64)
                CodeDirectory v=20500 size=1234 flags=0x10000(runtime) hashes=30+7 location=embedded
                CDHash=47ad04af2712c945cb63fc4d2163c163d185657d
                Authority=Developer ID Application: Example Corp (EXAMPLE123)
                Authority=Developer ID Certification Authority
                Authority=Apple Root CA
                Timestamp=23. Sep 2026 at 13:16:29
                TeamIdentifier=EXAMPLE123
                Runtime Version=15.5.0
                """),
            "/usr/sbin/spctl --assess -vv --type install \(binary)":
                CommandResult(exitCode: 0, stdout: "", stderr: "\(binary): accepted\nsource=Notarized Developer ID\norigin=Developer ID Application: Example Corp (EXAMPLE123)\n"),
        ])
        let result = SignatureVerifier(runner: runner).verify(path: binary)
        XCTAssertTrue(result.sealValid)
        XCTAssertEqual(result.sealDetail, "satisfies its Designated Requirement")
        XCTAssertEqual(result.identifier, "org.example.tool")
        XCTAssertEqual(result.teamIdentifier, "EXAMPLE123")
        XCTAssertTrue(result.hardenedRuntime)
        XCTAssertFalse(result.adhoc)
        XCTAssertEqual(result.authorities.count, 3)
        XCTAssertEqual(result.authorities.first, "Developer ID Application: Example Corp (EXAMPLE123)")
        XCTAssertEqual(result.assessment, "accepted")
        XCTAssertEqual(result.assessmentSource, "Notarized Developer ID")
        XCTAssertEqual(result.sha256, "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", "sha256 of 'hello'")
        XCTAssertEqual(result.hashedFile, binary)
        let text = result.renderText()
        XCTAssertTrue(text.contains("seal:       valid"), text)
        XCTAssertTrue(text.contains("gatekeeper: accepted — Notarized Developer ID"), text)
        XCTAssertTrue(text.contains("runtime:    hardened"), text)
    }

    func testBundleRejectedAdhocHashesTheMainExecutable() throws {
        let root = tempRoot("bundle")
        defer { try? FileManager.default.removeItem(atPath: root) }
        let app = root + "/Thing.app"
        try FileManager.default.createDirectory(atPath: app + "/Contents/MacOS", withIntermediateDirectories: true)
        try Data("main".utf8).write(to: URL(fileURLWithPath: app + "/Contents/MacOS/Thing"))
        try PropertyListSerialization.data(fromPropertyList: ["CFBundleExecutable": "Thing"], format: .xml, options: 0)
            .write(to: URL(fileURLWithPath: app + "/Contents/Info.plist"))
        let runner = ScriptedCommandRunner(responses: [
            "/usr/bin/codesign --verify --strict -v \(app)":
                CommandResult(exitCode: 1, stdout: "", stderr: "\(app): a sealed resource is missing or invalid\n"),
            "/usr/bin/codesign -dvvv \(app)": CommandResult(exitCode: 0, stdout: "", stderr: """
                Identifier=Thing
                Format=app bundle with Mach-O thin (arm64)
                CodeDirectory v=20400 size=500 flags=0x2(adhoc) hashes=10+3 location=embedded
                Signature=adhoc
                TeamIdentifier=not set
                """),
            "/usr/sbin/spctl --assess -vv --type execute \(app)":
                CommandResult(exitCode: 3, stdout: "", stderr: "\(app): rejected\nsource=no usable signature\n"),
        ])
        let result = SignatureVerifier(runner: runner).verify(path: app)
        XCTAssertFalse(result.sealValid)
        XCTAssertEqual(result.sealDetail, "a sealed resource is missing or invalid")
        XCTAssertTrue(result.adhoc)
        XCTAssertFalse(result.hardenedRuntime)
        XCTAssertNil(result.teamIdentifier)
        XCTAssertTrue(result.authorities.isEmpty)
        XCTAssertEqual(result.assessment, "rejected")
        XCTAssertEqual(result.assessmentSource, "no usable signature")
        XCTAssertEqual(result.hashedFile, app + "/Contents/MacOS/Thing", "bundles hash their main executable")
        XCTAssertNotNil(result.sha256)
        let text = result.renderText()
        XCTAssertTrue(text.contains("seal:       INVALID — a sealed resource is missing or invalid"), text)
        XCTAssertTrue(text.contains("authority:  none"), text)
        XCTAssertTrue(text.contains("of \(app)/Contents/MacOS/Thing"), text)
    }

    func testMissingFile() {
        let result = SignatureVerifier(runner: ScriptedCommandRunner()).verify(path: "/nonexistent/x")
        XCTAssertFalse(result.sealValid)
        XCTAssertEqual(result.sealDetail, "file missing")
        XCTAssertEqual(result.assessment, "unavailable")
        XCTAssertNil(result.sha256)
    }
}
