import Foundation

/// The first write operations (V0.2) live here, deliberately SEPARATE from the
/// read-only scan pipeline (ScanCoordinator stays write-free by design).
/// Rule from the spec: inventory and destructive operations never share a path.

public enum RemediationOperation: String, Codable {
    case disable, enable, backup, restore
}

public enum GateDecision: Equatable {
    case allowed
    case denied(reason: String)
}

/// Fail-closed allowlist for launchctl remediation. A target is a GATED
/// exception, never the default: anything not explicitly allowed is refused.
public enum RemediationGate {

    /// Only `disable`/`enable` consult this gate; `backup`/`restore` guard
    /// themselves inside BackupService (allowlist dirs + /System blocklist).
    public static func evaluate(operation: RemediationOperation, item: BackgroundItem) -> GateDecision {
        guard operation == .disable || operation == .enable else { return .allowed }

        guard let label = item.label, !label.isEmpty else {
            return .denied(reason: "no launchd label — nothing reversible to act on")
        }
        // Apple-owned components are read-only, always — even for `enable`.
        if label.hasPrefix("com.apple.") {
            return .denied(reason: "Apple system component (com.apple.*) — read-only by policy")
        }
        // Defense in depth: /System territory is refused even with --apply/sudo.
        for probe in [item.path, item.executable].compactMap({ $0 }) {
            if PathUtils.canonicalize(probe).hasPrefix("/System") {
                return .denied(reason: "backed by /System — refused even with --apply")
            }
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