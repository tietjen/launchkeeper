import Foundation

/// The first write operations (V0.2) live here, deliberately SEPARATE from the
/// read-only scan pipeline (ScanCoordinator stays write-free by design).
/// Rule from the spec: inventory and destructive operations never share a path.

public enum RemediationOperation: String, Codable {
    case disable, enable, backup, restore, remove
}

public enum GateDecision: Equatable {
    case allowed
    case denied(reason: String)
}

/// Fail-closed allowlist for launchctl remediation. A target is a GATED
/// exception, never the default: anything not explicitly allowed is refused.
public enum RemediationGate {

    /// `disable`/`enable`/`remove` consult this gate; `backup`/`restore` guard
    /// themselves inside BackupService (allowlist dirs + /System blocklist).
    /// For `remove` this is only the FIRST half — the file rules continue in
    /// `evaluateRemove`, which runs right after, on the same item.
    public static func evaluate(operation: RemediationOperation, item: BackgroundItem) -> GateDecision {
        guard operation == .disable || operation == .enable || operation == .remove else { return .allowed }

        guard let label = item.label, !label.isEmpty else {
            return .denied(reason: "no launchd label — nothing reversible to act on")
        }
        // Apple-owned components are read-only, always — even for `enable`.
        if label.hasPrefix("com.apple.") {
            return .denied(reason: "Apple system component (com.apple.*) — read-only by policy")
        }
        // A Background Task Management leftover — record present, no launch
        // plist, no launchd job — has nothing to unload, override or delete.
        // `enable` is the one exception: it may drop a dangling override
        // (V0.4.3, after `remove` of a disabled agent left one behind).
        if item.btmPresent, !item.plistPresent, !item.launchdPresent,
           !(operation == .enable && !item.enabled) {
            return .denied(reason: "only a Background Task Management record remains (no launch "
                + "plist, no launchd job) — nothing here to \(operation.rawValue). sfltool has "
                + "no per-item delete; the record is inert and BTM drops it in its own "
                + "housekeeping (seen live within minutes after the plist went), "
                + "otherwise `btmctl resetbtm`")
        }
        // Defense in depth: /System territory is refused even with --apply/sudo.
        for probe in [item.path, item.executable].compactMap({ $0 }) {
            if PathUtils.canonicalize(probe).hasPrefix("/System") {
                return .denied(reason: "backed by /System — refused even with --apply")
            }
        }
        return .allowed
    }

    /// V0.3 file-removal policy — deliberately in the SAME gate, so "one gate,
    /// no bypass" stays literally true. Runs after `evaluate` (the Apple and
    /// /System rules above cover `remove` too). Four independent locks, all
    /// fail-closed. The last one is what keeps btmctl from becoming an
    /// `rm`-wrapper: a working component gets DISABLED (reversible), never
    /// deleted — anything that is not provably broken is not touched.
    public static func evaluateRemove(item: BackgroundItem,
                                      fileManager: FileManager = .default,
                                      launchDirs: [String]) -> GateDecision {
        // Lock 1: only a launch-dir .plist may ever be the target of a delete.
        guard let path = item.path, path.hasPrefix("/"), path.hasSuffix(".plist") else {
            return .denied(reason: "no backing launch .plist — remove deletes plists inside launch directories, nothing else")
        }
        // Lock 2: allowlisted directory (exact parent — subdirs and `..`
        // tricks land outside and are refused).
        let parent = (path as NSString).deletingLastPathComponent
        guard launchDirs.contains(parent) else {
            return .denied(reason: "backing file is not inside a launch directory — outside the allowlist nothing may be deleted")
        }
        // Lock 3: never follow a symlink out of the allowlist. A link whose
        // target escapes the launch dirs would delete outside it.
        let canonical = PathUtils.canonicalize(path, fileManager: fileManager)
        let canonicalParent = (canonical as NSString).deletingLastPathComponent
        if canonical != path, !launchDirs.contains(canonicalParent) {
            return .denied(reason: "backing file is a symlink resolving outside the launch directories")
        }
        // Lock 4: orphaned only.
        guard item.orphaned else {
            return .denied(reason: "not orphaned — a working component must be disabled (reversible), not deleted")
        }
        return .allowed
    }
}

/// Result of resolving one CLI argument against a fresh scan. Users address
/// entries by display id or name fragment — never by raw label or path, so no
/// user string ever travels into a command line (injection safety).
public enum TargetResolution {
    case unique(BackgroundItem)
    case none(needle: String)
    case ambiguous(needle: String, candidates: [String])
}

public enum TargetResolver {
    /// Same addressing rules as `inspect`: numeric = display id, otherwise a
    /// case-insensitive fragment over displayName / label / key.
    public static func resolve(_ needle: String, in items: [BackgroundItem]) -> TargetResolution {
        let trimmed = needle.trimmingCharacters(in: .whitespaces)
        let lower = trimmed.lowercased()
        var candidates: [BackgroundItem] = []
        if !lower.isEmpty, lower.allSatisfy({ $0.isNumber }), let n = Int(lower) {
            candidates = items.filter { $0.id == String(format: "%02d", n) }
        }
        if candidates.isEmpty {
            candidates = items.filter {
                $0.displayName.lowercased().contains(lower)
                    || $0.label?.lowercased().contains(lower) == true
                    || $0.key.lowercased().contains(lower)
            }
        }
        switch candidates.count {
        case 0: return .none(needle: trimmed)
        case 1: return .unique(candidates[0])
        default:
            return .ambiguous(needle: trimmed,
                              candidates: candidates.prefix(8).map { "[\($0.id)] \($0.displayName)" })
        }
    }
}