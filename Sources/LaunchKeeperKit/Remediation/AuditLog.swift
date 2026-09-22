import Foundation

/// Append-only operation log — required by the spec from V0.2 on:
/// `[<ISO8601>] launchkeeper <operation> <target> <status>`
/// Statuses: planned | applied-ok | applied-fail(<detail>) | refused(<reason>).
/// Rotation: TODO(size-based) once the log matters operationally.
public struct AuditLog {
    public var url: URL

    public init(directory: String) {
        self.url = URL(fileURLWithPath: directory, isDirectory: true)
            .appendingPathComponent("operations.log")
        Self.carryOverLegacyLog(to: url, directory: directory)
    }

    /// One-time carry-over from the btmctl era (V0.5.0): when this is the
    /// standard launchkeeper log directory, the new log does not exist yet
    /// and the old one does, the old contents become the head of the new
    /// log, closed by a marker line. The old file stays untouched — an
    /// append-only history must survive a rename.
    private static func carryOverLegacyLog(to url: URL, directory: String) {
        let suffix = "/Library/Logs/" + LaunchKeeperPaths.productName
        guard directory.hasSuffix(suffix) else { return }
        let home = String(directory.dropLast(suffix.count))
        let legacy = URL(fileURLWithPath: LaunchKeeperPaths.legacyLogs(home: home), isDirectory: true)
            .appendingPathComponent("operations.log")
        let fm = FileManager.default
        guard !fm.fileExists(atPath: url.path), fm.fileExists(atPath: legacy.path),
              var carried = try? Data(contentsOf: legacy) else { return }
        carried.append(Data((formatLine(operation: "migrate", target: legacy.path,
                                        status: "carried-over") + "\n").utf8))
        try? fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? carried.write(to: url)
    }

    /// Pure formatter, so the line format stays directly testable.
    public static func formatLine(timestamp: Date = Date(), tool: String = "launchkeeper",
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