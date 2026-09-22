import Foundation

/// Where launchkeeper keeps its own state. The btmctl-era locations stay
/// readable: the audit log is carried over once, backups are found in
/// either root — a rename must never orphan a user's undo history.
public enum LaunchKeeperPaths {
    public static let productName = "launchkeeper"
    public static let legacyProductName = "btmctl"

    public static func logs(home: String) -> String {
        home + "/Library/Logs/\(productName)"
    }
    public static func legacyLogs(home: String) -> String {
        home + "/Library/Logs/\(legacyProductName)"
    }
    public static func backups(home: String) -> String {
        home + "/Library/Application Support/\(productName)/backups"
    }
    public static func legacyBackups(home: String) -> String {
        home + "/Library/Application Support/\(legacyProductName)/backups"
    }
    public static func btmSnapshots(home: String) -> String {
        home + "/Library/Application Support/\(productName)/btm-snapshots"
    }
}
