import Foundation

/// Path helpers shared by analysis and (later) operations.
public enum PathUtils {
    /// Follows one or more symlink hops (bounded), then standardizes.
    /// Result reflects what `exists`/`stat` would actually act on.
    public static func canonicalize(_ path: String, fileManager: FileManager = .default, maxHops: Int = 8) -> String {
        var current = (path as NSString).isAbsolutePath ? path : ("./" + path)
        var hops = 0
        while hops < maxHops {
            guard let link = try? fileManager.destinationOfSymbolicLink(atPath: current) else { break }
            let resolved: String
            if (link as NSString).isAbsolutePath {
                resolved = link
            } else {
                resolved = URL(fileURLWithPath: (current as NSString).deletingLastPathComponent)
                    .appendingPathComponent(link).standardized.path
            }
            if resolved == current { break }
            current = resolved
            hops += 1
        }
        return (current as NSString).standardizingPath
    }

    /// True if the final component resolves (broken symlinks and missing files => false).
    public static func exists(_ path: String, fileManager: FileManager = .default) -> Bool {
        fileManager.fileExists(atPath: path)
    }

    /// Writable "temp or hidden" territory — only ever a REVIEW hint, never guilt.
    public static func isTempOrHiddenPath(_ raw: String) -> Bool {
        let path = (raw as NSString).standardizingPath
        let prefixes = ["/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/"]
        if prefixes.contains(where: { path.hasPrefix($0) }) { return true }
        return path.split(separator: "/").contains { $0.hasPrefix(".") && $0.count > 1 }
    }

    /// Interpreters that commonly front persistence (REVIEW hint when owning a service).
    public static let shellInterpreters: Set<String> = [
        "/bin/bash", "/bin/sh", "/bin/zsh", "/bin/dash", "/bin/csh", "/bin/tcsh", "/bin/ksh",
        "/usr/bin/osascript", "/usr/bin/python", "/usr/bin/python3", "/usr/local/bin/python",
        "/usr/local/bin/python3", "/opt/homebrew/bin/python", "/opt/homebrew/bin/python3",
        "/usr/bin/perl", "/usr/bin/ruby", "/opt/homebrew/bin/node", "/usr/local/bin/node",
    ]

    /// SIP-protected territory. V0.1 only CLASSIFIES this (read-only); V0.3+ will block on it.
    public static func isSystemOwnedPath(_ path: String) -> Bool {
        path.hasPrefix("/System/") || path.hasPrefix("/usr/") || path.hasPrefix("/bin/")
            || path.hasPrefix("/sbin/") || path.hasPrefix("/usr/libexec/")
    }

    /// Owner name + whether the backing file is writable by its owner being non-root.
    public static func ownerInfo(_ path: String, fileManager: FileManager = .default) -> (name: String, writableByUser: Bool)? {
        guard let attrs = try? fileManager.attributesOfItem(atPath: path) else { return nil }
        let owner = (attrs[.ownerAccountName] as? String) ?? "unknown"
        let uid = (attrs[.ownerAccountID] as? NSNumber)?.int32Value ?? -1
        return (owner, uid != 0 && uid >= 0)
    }
}