import Foundation

/// The Autoruns-style tab an item belongs to. One category per scanner;
/// the list, the JSON and (later) the GUI sidebar group by it.
public enum ItemCategory: String, Codable, CaseIterable, Sendable {
    /// LaunchAgents / LaunchDaemons and their live launchd jobs.
    case launchItems = "launch-items"
    /// Background Task Management: login items and SMAppService registrations.
    case loginItems = "login-items"
    /// App extensions (QuickLook, Spotlight, dock tiles, share/action/widgets …).
    case appExtensions = "app-extensions"
    case systemExtensions = "system-extensions"
    case privilegedHelpers = "privileged-helpers"
    case scheduled
    case legacy
    case shellStartup = "shell-startup"
    case pluginDirectories = "plugin-directories"
    case network
    case profiles
    case privacy

    /// Human title, as the sidebar / table header would show it.
    public var title: String {
        switch self {
        case .launchItems: return "Launch Items"
        case .loginItems: return "Login Items & Background"
        case .appExtensions: return "App Extensions"
        case .systemExtensions: return "System Extensions & Kexts"
        case .privilegedHelpers: return "Privileged Helper Tools"
        case .scheduled: return "Scheduled"
        case .legacy: return "Legacy Persistence"
        case .shellStartup: return "Shell Startup"
        case .pluginDirectories: return "Plug-in Directories"
        case .network: return "Network"
        case .profiles: return "Profiles / MDM"
        case .privacy: return "Privacy (TCC)"
        }
    }
}

/// What launchkeeper can do with an item — the control matrix as DATA, so
/// the CLI, the JSON and the GUI give the same answer. Computed from the
/// same gate that the mutating commands consult; never a promise the gate
/// would not keep.
public enum ControlLevel: String, Codable, Sendable {
    /// disable / enable through a launchd override (undo is one command).
    case reversible
    /// reversible AND `remove` would pass its locks (orphaned launch plist).
    case removable
    /// nothing launchkeeper may change — the reason says who can.
    case displayOnly = "display-only"
}

public struct Controllability: Codable, Equatable, Sendable {
    public var level: ControlLevel
    /// Commands that apply, in the tool's vocabulary ("disable", "enable", "remove").
    public var actions: [String]
    /// One sentence: why this level, or where the switch lives instead.
    public var reason: String

    public init(level: ControlLevel, actions: [String], reason: String) {
        self.level = level
        self.actions = actions
        self.reason = reason
    }
}

/// Where an item came from. V0.5 resolves the cheap signals (Apple,
/// Homebrew, Mac App Store receipt); package receipts follow in V0.6.
public enum ProvenanceKind: String, Codable, Sendable {
    case apple
    case homebrew
    case appStore = "app-store"
    case receipt
    case manual
    case unknown
}

public struct Provenance: Codable, Equatable, Sendable {
    public var kind: ProvenanceKind
    /// Evidence in one line (label prefix, receipt path, package id …).
    public var detail: String?

    public init(kind: ProvenanceKind, detail: String? = nil) {
        self.kind = kind
        self.detail = detail
    }
}
