import Foundation

// V0.8.0 — receipt-based uninstall. Pure analysis: given a package's BOM and
// the disk as it is now, which paths are provably the package's, unchanged,
// and nobody else's? Only those move (to the quarantine, never `rm`).
// Everything else stays and is reported with the reason.

/// What the analysis concluded about one BOM path.
public enum UninstallStatus: Equatable, Sendable {
    /// On disk and exactly as installed (size + CRC, or link target) — moves.
    case intact
    /// A directory whose entire on-disk content is intact package content — moves.
    case removableDirectory
    /// Not on disk anymore.
    case missing
    /// On disk but not as installed — somebody's work, stays.
    case modified(String)
    /// Readable only by root — unproven, stays unless verified as root.
    case unreadable
    /// Intact, but inside a bundle that does not move as a whole — bundles
    /// move whole or not at all (a half-taken app is worse than either).
    case keptWithBundle(String)
    /// A directory holding something the package did not install — stays.
    case foreignContent(String)
    /// Listed by other receipts or a shared root (/Applications, /Library/…) — stays.
    case shared
    /// Never touched by policy (/System, /usr, receipts DB, symlinked parent …).
    case protected(String)

    public var label: String {
        switch self {
        case .intact: return "intact"
        case .removableDirectory: return "removable-directory"
        case .missing: return "missing"
        case .modified: return "modified"
        case .unreadable: return "unreadable"
        case .keptWithBundle: return "kept-with-bundle"
        case .foreignContent: return "foreign-content"
        case .shared: return "shared"
        case .protected: return "protected"
        }
    }

    public var detail: String? {
        switch self {
        case .modified(let why), .foreignContent(let why), .protected(let why): return why
        case .unreadable: return "readable only by root — --verify-as-root proves it (sudo)"
        case .keptWithBundle(let bundle): return "inside \(bundle), which changed since install and stays whole"
        default: return nil
        }
    }

    var moves: Bool { self == .intact || self == .removableDirectory }
}

public struct UninstallPath: Equatable, Sendable {
    public var path: String
    public var kind: BOMEntry.Kind
    public var status: UninstallStatus
}

public struct UninstallAnalysis: Sendable {
    public var packageIdentifier: String
    public var version: String?
    public var paths: [UninstallPath]
    /// Top-most moving paths (a whole bundle moves as one), deepest-first
    /// order is irrelevant: no root lies inside another.
    public var moveRoots: [String]
    /// `pkgutil --forget` is allowed: nothing exclusive of this package stays on disk.
    public var canForget: Bool
    public var forgetBlockers: [String]
    public var warnings: [String]

    public func count(_ label: String) -> Int { paths.filter { $0.status.label == label }.count }
    /// Files and links inside the move roots.
    public var movingFiles: [String] {
        paths.filter { $0.status == .intact }.map(\.path)
    }
}

/// The disk seen through an optional prefix: tests analyse a temp tree as if
/// it were "/", the real run uses "" — logical paths stay the same.
public struct DiskView {
    public var fileManager: FileManager
    public var rootPrefix: String

    public init(fileManager: FileManager = .default, rootPrefix: String = "") {
        self.fileManager = fileManager
        self.rootPrefix = rootPrefix
    }

    public func disk(_ path: String) -> String { rootPrefix + path }

    /// lstat — never follows a symlink.
    public func type(_ path: String) -> FileAttributeType? {
        (try? fileManager.attributesOfItem(atPath: disk(path)))?[.type] as? FileAttributeType
    }

    public func exists(_ path: String) -> Bool { type(path) != nil }
}

public enum PackageUninstallAnalyzer {
    /// Territory no uninstall ever touches, whatever a BOM claims.
    static let protectedPrefixes = ["/System/", "/usr/", "/bin/", "/sbin/", "/private/var/db/receipts/",
                                    "/var/db/receipts/", "/Library/Apple/", "/cores/", "/dev/", "/Volumes/"]
    static let unprotectedUnder = ["/usr/local/"]
    static let bundleExtensions: Set<String> = ["app", "framework", "bundle", "plugin", "appex", "kext", "prefPane",
                                                "qlgenerator", "mdimporter", "saver", "jdk", "xpc", "systemextension"]

    static func isProtected(_ path: String) -> Bool {
        let probe = path + "/"
        if unprotectedUnder.contains(where: { probe.hasPrefix($0) }) { return false }
        return protectedPrefixes.contains { probe.hasPrefix($0) }
    }

    /// `/etc`, `/var`, `/tmp` are firmlink-style symlinks into /private —
    /// the only symlinked parents an install path may legitimately have.
    static func normalizedPrivate(_ path: String) -> String {
        for top in ["/etc", "/var", "/tmp"] where path == top || path.hasPrefix(top + "/") {
            return "/private" + path
        }
        return path
    }

    /// `claimants(path)`: every package id (Apple's included) that lists a
    /// path — the non-Apple index alone missed that Apple's data template
    /// lists /Library/Printers/PPDs (live, 2026-09-26). Asked for every
    /// directory before it may move as a whole.
    /// `rootChecksums`: CRCs of root-only files, read via `sudo -n cksum`.
    public static func analyze(packageIdentifier: String, version: String?, volume: String, location: String,
                               bom: [BOMEntry], index: ReceiptIndex, disk: DiskView,
                               claimants: ((String) -> Set<String>)? = nil,
                               rootChecksums: [String: UInt32] = [:]) -> UninstallAnalysis {
        var warnings: [String] = []
        var status: [String: UninstallStatus] = [:]
        var kinds: [String: BOMEntry.Kind] = [:]

        func sharedWithOthers(_ path: String) -> Bool {
            if ReceiptIndex.isSharedRoot(path) || index.shared.contains(path) { return true }
            if let owner = index.owners[path], owner != packageIdentifier { return true }
            return false
        }

        func parentProblem(_ path: String) -> String? {
            let parent = (path as NSString).deletingLastPathComponent
            guard parent != "/" else { return nil }
            let resolved = PathUtils.canonicalize(disk.disk(parent), fileManager: disk.fileManager)
            let resolvedLogical = disk.rootPrefix.isEmpty ? resolved
                : (resolved.hasPrefix(PathUtils.canonicalize(disk.rootPrefix, fileManager: disk.fileManager))
                   ? String(resolved.dropFirst(PathUtils.canonicalize(disk.rootPrefix, fileManager: disk.fileManager).count))
                   : resolved)
            return normalizedPrivate(resolvedLogical) == normalizedPrivate(parent) ? nil
                : "a parent directory is a symlink (→ \(resolvedLogical))"
        }

        // ---- files and links first, on their own merits. The BOM root
        // "." is the install location: a directory of its own when the
        // package installs INTO something (a .jdk bundle, /opt/<tool>).
        let installRoot = location.trimmingCharacters(in: CharacterSet(charactersIn: "/")).isEmpty
        let installLocationPath = ReceiptInfoParser.absolutePath(volume: volume, location: location, relative: "")
        let entries = bom.filter { !$0.isAppleDouble && (!$0.relativePath.isEmpty || !installRoot) }
        for entry in entries {
            let path = ReceiptInfoParser.absolutePath(volume: volume, location: location, relative: entry.relativePath)
            kinds[path] = entry.kind
            if isProtected(path) {
                status[path] = .protected("protected system territory")
                continue
            }
            // /Applications, /Library, /usr/local …: everybody's.
            if path.split(separator: "/").count < 2 { status[path] = .shared; continue }
            if entry.kind == .directory { continue }
            if sharedWithOthers(path) { status[path] = .shared; continue }
            guard let type = disk.type(path) else { status[path] = .missing; continue }
            if let problem = parentProblem(path) { status[path] = .protected(problem); continue }
            switch entry.kind {
            case .file:
                guard type == .typeRegular else { status[path] = .modified("no longer a regular file"); continue }
                let size = (try? disk.fileManager.attributesOfItem(atPath: disk.disk(path)))?[.size] as? UInt64
                guard size == entry.size else {
                    status[path] = .modified("size \(size.map(String.init) ?? "?") ≠ \(entry.size.map(String.init) ?? "?")")
                    continue
                }
                guard let crc = POSIXChecksum.checksum(fileAtPath: disk.disk(path)) ?? rootChecksums[path] else {
                    status[path] = .unreadable; continue
                }
                status[path] = crc == entry.crc ? .intact : .modified("content changed (checksum)")
            case .symlink:
                guard type == .typeSymbolicLink,
                      let target = try? disk.fileManager.destinationOfSymbolicLink(atPath: disk.disk(path)) else {
                    status[path] = .modified("no longer a symlink"); continue
                }
                status[path] = target == entry.linkTarget ? .intact : .modified("link points elsewhere (\(target))")
            case .other:
                status[path] = .protected("device or special file")
            case .directory:
                break
            }
        }

        // ---- directories bottom-up: removable only when every child on
        // disk is itself moving content of this package.
        let directories = entries.filter { $0.kind == .directory }
            .map { ReceiptInfoParser.absolutePath(volume: volume, location: location, relative: $0.relativePath) }
            .sorted { $0.split(separator: "/").count > $1.split(separator: "/").count }
        for path in directories where status[path] == nil {
            if sharedWithOthers(path) { status[path] = .shared; continue }
            guard let type = disk.type(path) else { status[path] = .missing; continue }
            if let problem = parentProblem(path) { status[path] = .protected(problem); continue }
            guard type == .typeDirectory else { status[path] = .modified("no longer a directory"); continue }
            let children = (try? disk.fileManager.contentsOfDirectory(atPath: disk.disk(path))) ?? []
            let staying = children.map { path + "/" + $0 }.filter { status[$0]?.moves != true }
            // A folder that only keeps shared folders is part of a shared
            // structure itself (receipts list every ancestor).
            let foreign = staying.filter { status[$0] != .shared }
            if !staying.isEmpty, foreign.isEmpty {
                status[path] = .shared
            } else if foreign.isEmpty {
                // Last and most expensive question (one pkgutil call), only
                // for a directory that would otherwise move as a whole.
                if let claimants, !claimants(path).subtracting([packageIdentifier]).isEmpty {
                    status[path] = .shared
                } else {
                    status[path] = .removableDirectory
                }
            } else {
                let names = foreign.prefix(3).map { ($0 as NSString).lastPathComponent }.joined(separator: ", ")
                status[path] = .foreignContent("\(foreign.count) item(s) not (intact) from this package: \(names)"
                                               + (foreign.count > 3 ? ", …" : ""))
            }
        }

        // Bundles move whole or not at all: anything inside a bundle that
        // stays (changed since install, shared, unproven) stays with it.
        // Live 2026-09-26: a self-updated AusweisApp would otherwise have
        // lost 235 of its files and kept 415 — a broken app.
        func isBundle(_ path: String) -> Bool { Self.bundleExtensions.contains((path as NSString).pathExtension) }
        for path in status.keys.sorted() where status[path]!.moves {
            var probe = (path as NSString).deletingLastPathComponent
            while probe != "/" && !probe.isEmpty {
                if isBundle(probe), let outer = status[probe], !outer.moves {
                    status[path] = .keptWithBundle(probe)
                    break
                }
                probe = (probe as NSString).deletingLastPathComponent
            }
        }
        var reported = Set<String>()
        for case .keptWithBundle(let bundle) in status.values where !reported.contains(bundle) {
            // Name only the outermost changed bundle.
            let outermost = status.keys.filter { bundle.hasPrefix($0 + "/") && isBundle($0) && status[$0]?.moves == false }
            if !outermost.isEmpty { continue }
            reported.insert(bundle)
            warnings.append("\(bundle) changed since install (\(status[bundle]!.label)) — nothing inside it moves; "
                + "bundles move whole or not at all. Remove the app itself by hand if you want it gone")
        }

        let paths = status.keys.sorted().map { UninstallPath(path: $0, kind: kinds[$0] ?? .other, status: status[$0]!) }
        let moving = Set(paths.filter { $0.status.moves }.map(\.path))
        let roots = moving.filter { !moving.contains(($0 as NSString).deletingLastPathComponent) }.sorted()

        // Top-level locations (two levels deep: /Library/<Vendor>, /opt/<tool>)
        // never move, even when only this receipt lists them — a nearly
        // empty standard folder must not travel. If one would be left
        // empty, say so.
        for path in paths where path.kind == .directory && path.status == .shared {
            guard index.owners[path.path] == packageIdentifier || path.path == installLocationPath,
                  !index.shared.contains(path.path),
                  !ReceiptIndex.sharedRoots.contains(path.path), path.path.split(separator: "/").count == 2,
                  let children = try? disk.fileManager.contentsOfDirectory(atPath: disk.disk(path.path)),
                  children.allSatisfy({ moving.contains(path.path + "/" + $0) }) else { continue }
            warnings.append("\(path.path) stays (empty afterwards): top-level locations are never moved "
                + "automatically — remove it by hand if it is really this package's")
        }

        // Forget only when nothing exclusive of the package stays behind —
        // otherwise the receipt is the last record of whose files those are.
        var blockers: [String] = []
        let modified = paths.filter { if case .modified = $0.status { return true }; return false }
        if !modified.isEmpty { blockers.append("\(modified.count) modified path(s) stay on disk") }
        let foreign = paths.filter { if case .foreignContent = $0.status { return true }; return false }
        if !foreign.isEmpty { blockers.append("\(foreign.count) package directory(ies) keep foreign content") }
        let unreadable = paths.filter { $0.status == .unreadable }
        if !unreadable.isEmpty {
            blockers.append("\(unreadable.count) root-only file(s) unproven (--verify-as-root checks them)")
        }
        let withBundle = paths.filter { if case .keptWithBundle = $0.status { return true }; return false }
        if !withBundle.isEmpty { blockers.append("\(withBundle.count) path(s) stay inside a changed bundle") }
        let guarded = paths.filter {
            if case .protected(let why) = $0.status, why.hasPrefix("a parent directory is a symlink") { return true }
            return false
        }
        if !guarded.isEmpty { blockers.append("\(guarded.count) path(s) behind a symlinked parent stay") }

        return UninstallAnalysis(packageIdentifier: packageIdentifier, version: version, paths: paths,
                                 moveRoots: roots, canForget: blockers.isEmpty, forgetBlockers: blockers,
                                 warnings: warnings)
    }
}
