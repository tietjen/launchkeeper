import Foundation

/// Append-only operation log — required by the spec from V0.2 on:
/// `[<ISO8601>] btmctl <operation> <target> <status>`
/// Statuses: planned | applied-ok | applied-fail(<detail>) | refused(<reason>).
/// Rotation: TODO(size-based) once the log matters operationally.
public struct AuditLog {
    public var url: URL

    public init(directory: String) {
        self.url = URL(fileURLWithPath: directory, isDirectory: true)
            .appendingPathComponent("operations.log")
    }

    /// Pure formatter, so the line format stays directly testable.
    public static func formatLine(timestamp: Date = Date(), tool: String = "btmctl",
                                  operation: String, target: String, status: String) -> String {
        let formatter = ISO8601DateFormatter()
        return "[\(formatter.string(from: timestamp))] \(tool) \(operation) \(target) \(status)"
    }

    /// Never throws: a lost audit line must not break the operation it logs,
    /// but the failure is returned for callers that care.
    @discardableResult
    public func append(operation: String, target: String, status: String,
                       timestamp: Date = Date()) -> String? {
        let line = Self.formatLine(timestamp: timestamp, operation: operation,
                                   target: target, status: status) + "\n"
        let directory = url.deletingLastPathComponent()
        do {
            if !FileManager.default.fileExists(atPath: directory.path) {
                try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
            }
            if FileManager.default.fileExists(atPath: url.path) {
                let handle = try FileHandle(forWritingTo: url)
                defer { try? handle.close() }
                try handle.seekToEnd()
                try handle.write(contentsOf: Data(line.utf8))
            } else {
                try Data(line.utf8).write(to: url)
            }
            return nil
        } catch {
            return "audit write failed: \(error.localizedDescription)"
        }
    }

    /// Test helper + CLI display: current file contents.
    public func readAll() -> String {
        (try? String(contentsOf: url, encoding: .utf8)) ?? ""
    }
}