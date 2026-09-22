import Foundation

/// One normalized background component as seen across ALL sources.
/// A single item may be backed by several plists, launchd jobs and BTM records —
/// correlation is deliberately many-to-one (a BTM entry is NOT one plist).
public struct BackgroundItem: Codable {
    /// Display id, assigned per scan run ("01", "02", ...), stable only within a run.
    public var id: String
    /// Stable identity across sources within one run: used by `inspect`.
    public var key: String
    public var displayName: String
    public var type: ItemType
    public var sources: [SourceEvidence]

    public var path: String?            // primary backing file (plist or executable)
    public var label: String?           // launchd service label when known
    public var executable: String?      // resolved from plist ProgramArguments or BTM Executable Path
    public var arguments: [String]
    public var owner: String            // username owning the backing file
    public var uid: Int
    public var domain: ItemDomain

    public var bundleIdentifier: String?
    public var parentApplication: String?
    public var developer: String?
    public var teamIdentifier: String?
    public var codeSignatureStatus: String?

    public var loaded: Bool             // present in `launchctl print`
    public var running: Bool            // live PID in launchd output
    public var pid: Int?
    public var enabled: Bool            // from print-disabled override table (default: true)

    public var orphaned: Bool
    public var orphanConfidence: Confidence?
    public var orphanReasons: [String]

    public var riskFlags: [String]      // "REVIEW RECOMMENDED" hints only — never a malware claim

    public var btmPresent: Bool
    public var launchdPresent: Bool
    public var plistPresent: Bool
    public var appPresent: Bool?        // parent app / login-item app exists on disk
    public var metadata: [String: String]

    // V0.5: the Autoruns-style dimensions.
    public var category: ItemCategory
    public var control: Controllability?
    public var provenance: Provenance?

    public init(
        id: String = "",
        key: String,
        displayName: String,
        type: ItemType = .unknown,
        sources: [SourceEvidence] = [],
        path: String? = nil,
        label: String? = nil,
        executable: String? = nil,
        arguments: [String] = [],
        owner: String = "unknown",
        uid: Int = -1,
        domain: ItemDomain = .mixed,
        bundleIdentifier: String? = nil,
        parentApplication: String? = nil,
        developer: String? = nil,
        teamIdentifier: String? = nil,
        codeSignatureStatus: String? = nil,
        loaded: Bool = false,
        running: Bool = false,
        pid: Int? = nil,
        enabled: Bool = true,
        orphaned: Bool = false,
        orphanConfidence: Confidence? = nil,
        orphanReasons: [String] = [],
        riskFlags: [String] = [],
        btmPresent: Bool = false,
        launchdPresent: Bool = false,
        plistPresent: Bool = false,
        appPresent: Bool? = nil,
        metadata: [String: String] = [:],
        category: ItemCategory = .launchItems,
        control: Controllability? = nil,
        provenance: Provenance? = nil
    ) {
        self.id = id
        self.key = key
        self.displayName = displayName
        self.type = type
        self.sources = sources
        self.path = path
        self.label = label
        self.executable = executable
        self.arguments = arguments
        self.owner = owner
        self.uid = uid
        self.domain = domain
        self.bundleIdentifier = bundleIdentifier
        self.parentApplication = parentApplication
        self.developer = developer
        self.teamIdentifier = teamIdentifier
        self.codeSignatureStatus = codeSignatureStatus
        self.loaded = loaded
        self.running = running
        self.pid = pid
        self.enabled = enabled
        self.orphaned = orphaned
        self.orphanConfidence = orphanConfidence
        self.orphanReasons = orphanReasons
        self.riskFlags = riskFlags
        self.btmPresent = btmPresent
        self.launchdPresent = launchdPresent
        self.plistPresent = plistPresent
        self.appPresent = appPresent
        self.metadata = metadata
        self.category = category
        self.control = control
        self.provenance = provenance
    }
}

public enum ItemType: String, Codable {
    case launchAgentUser = "user-agent"
    case launchAgentSystem = "system-agent"
    case launchDaemon = "daemon"
    case loginItem = "login-item"
    case smappservice = "smappservice"
    case btmEntry = "btm-entry"
    case appExtension = "app-extension"
    case helper
    case script
    case unknown
}

public enum ItemDomain: String, Codable {
    case user
    case system
    case mixed
}

public enum Confidence: String, Codable {
    case high
    case medium
    case low
}

public enum EvidenceKind: String, Codable {
    case plist
    case launchd
    case btm
    case signature
    case pluginkit
}

public struct SourceEvidence: Codable, Equatable {
    public var kind: EvidenceKind
    public var detail: String
    public var confidence: Confidence

    public init(kind: EvidenceKind, detail: String, confidence: Confidence) {
        self.kind = kind
        self.detail = detail
        self.confidence = confidence
    }
}

/// The launchd domain a job lives in — what `launchctl` targets take.
public enum LaunchdDomainKind: String, Codable {
    case gui, system
}

extension BackgroundItem {
    /// Where the JOB runs, as opposed to `domain`, which records where the
    /// EVIDENCE came from. Ground truth is the live launchd read (the
    /// `launchd-state` metadata names the domain the job was printed from).
    /// Without it the plist kind decides: agents — in ~/Library or in
    /// /Library — run in the user's gui domain, daemons in system.
    ///
    /// The distinction matters: a /Library/LaunchAgents agent is `mixed`
    /// (root-owned file, user-session job). V0.4.1 planned it as
    /// `system/<label>` via sudo — a target that did not exist and a
    /// password prompt nobody needed (V0.4.2).
    public var launchdDomainKind: LaunchdDomainKind {
        if let state = metadata["launchd-state"] {
            if state.hasPrefix("gui") { return .gui }
            if state.hasPrefix("system") { return .system }
        }
        switch type {
        case .launchAgentUser, .launchAgentSystem, .loginItem, .smappservice:
            return .gui
        case .launchDaemon:
            return .system
        case .btmEntry, .appExtension, .helper, .script, .unknown:
            return domain == .system ? .system : .gui
        }
    }
}
