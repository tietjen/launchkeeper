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
    /// Apple's own platform binaries: /System, /usr (not /usr/local), /bin,
    /// /sbin. Used to hide Apple's listening daemons from the default view.
    public static func isApplePlatformPath(_ path: String) -> Bool {
        if path.hasPrefix("/usr/local/") || path.hasPrefix("/opt/") { return false }
        return isSystemOwnedPath(path)
    }

    public static func isSystemOwnedPath(_ path: String) -> Bool {
        path.hasPrefix("/System/") || path.hasPrefix("/usr/") || path.hasPrefix("/bin/")
            || path.hasPrefix("/sbin/") || path.hasPrefix("/usr/libexec/")
    }

    /// V0.12.1: the first directory on the way to `path` (from `/` down to
    /// its parent) that a non-root user could change: not owned by root, or
    /// writable by everyone (sticky 1777 included). Components are resolved
    /// (`stat`, not `lstat`), so `/tmp` is judged as `/private/tmp`. Group
    /// write (root:admin — /Applications, /Library/Preferences) is accepted:
    /// only administrators can use it, and they can become root anyway.
    /// Stops at the first component that does not exist (root creates the
    /// rest). Root moving files through such a chain is a rename/symlink race
    /// (review 2026-09-27, C-2/S1/S2).
    /// - Parameters:
    ///   - path: The path root is about to move or create.
    ///   - rootPrefix: Offline-root prefix (`DiskView.rootPrefix`), "" live.
    /// - Returns: The offending directory, or `nil` when the chain is safe.
    public static func userWritableAncestor(of path: String, rootPrefix: String = "") -> String? {
        var walked = ""
        for component in (path as NSString).deletingLastPathComponent.split(separator: "/") {
            walked += "/" + component
            var info = stat()
            guard stat(rootPrefix + walked, &info) == 0 else { return nil }
            if info.st_uid != 0 || info.st_mode & S_IWOTH != 0 { return walked }
        }
        return nil
    }

    /// Owner name + whether the backing file is writable by its owner being non-root.
    public static func ownerInfo(_ path: String, fileManager: FileManager = .default) -> (name: String, writableByUser: Bool)? {
        guard let attrs = try? fileManager.attributesOfItem(atPath: path) else { return nil }
        let owner = (attrs[.ownerAccountName] as? String) ?? "unknown"
        let uid = (attrs[.ownerAccountID] as? NSNumber)?.int32Value ?? -1
        return (owner, uid != 0 && uid >= 0)
    }
}