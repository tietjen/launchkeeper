import Foundation

/// Loads the captured real-system fixtures (macOS 26.6.2, captured live,
/// no sudo). Lives in Tests/Fixtures next to the test target.
enum Fixtures {
    static var directory: String {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()   // BTMKitTests
            .deletingLastPathComponent()   // Tests
            .appendingPathComponent("Fixtures").path
    }

    static func exists(_ name: String) -> Bool {
        FileManager.default.fileExists(atPath: directory + "/" + name)
    }

    static func text(_ name: String) -> String {
        (try? String(contentsOfFile: directory + "/" + name, encoding: .utf8)) ?? ""
    }
}