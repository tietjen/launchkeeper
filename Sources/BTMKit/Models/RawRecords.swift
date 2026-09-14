import Foundation

/// Raw observation from scanning one plist on disk.
public struct LaunchJobRecord: Equatable {
    public var label: String            // file name without .plist
    public var path: String
    public var domain: ItemDomain       // user directory -> .user, /Library -> .system
    public var kind: ItemType           // agent vs daemon (by directory)
    public var program: String?         // Program or ProgramArguments[0]
    public var arguments: [String]      // ProgramArguments[1...]
    public var runAtLoad: Bool
    public var keepAlive: Bool
    public var ownerName: String
    public var malformed: Bool          // unreadable / not a plist / no usable keys
    public var parsedKeys: [String]     // unknown plist keys preserved

    public init(label: String, path: String, domain: ItemDomain, kind: ItemType,
                program: String?, arguments: [String], runAtLoad: Bool, keepAlive: Bool,
                ownerName: String, malformed: Bool, parsedKeys: [String] = []) {
        self.label = label
        self.path = path
        self.domain = domain
        self.kind = kind
        self.program = program
        self.arguments = arguments
        self.runAtLoad = runAtLoad
        self.keepAlive = keepAlive
        self.ownerName = ownerName
        self.malformed = malformed
        self.parsedKeys = parsedKeys
    }
}

/// One line inside a `launchctl print <domain>` services block.
public struct LaunchdServiceRecord: Equatable {
    public var label: String
    public var domainKind: String       // "gui" | "system"
    public var pid: Int?                // nil when not running
    public var stateToken: String       // "-", "0", "1", "(pe)", ...

    public init(label: String, domainKind: String, pid: Int?, stateToken: String) {
        self.label = label
        self.domainKind = domainKind
        self.pid = pid
        self.stateToken = stateToken
    }
}

/// One `Items:` record from `sfltool dumpbtm`, kept as lenient key/value.
public struct BTMRecord: Equatable {
    public var sectionUID: Int
    public var fields: [String: String] // "Name", "Type", "Disposition", "URL", ...
    public var trailingBlock: [String]  // e.g. Embedded Item Identifiers children

    public init(sectionUID: Int, fields: [String: String], trailingBlock: [String] = []) {
        self.sectionUID = sectionUID
        self.fields = fields
        self.trailingBlock = trailingBlock
    }

    public var name: String { fields["Name"] ?? "" }
    public var typeDescription: String { fields["Type"]?.components(separatedBy: "(").first?.trimmingCharacters(in: .whitespaces) ?? "" }
    public var identifier: String { fields["Identifier"] ?? "" }
    public var url: String? {
        guard let raw = fields["URL"], !raw.isEmpty, raw != "(null)" else { return nil }
        return raw.replacingOccurrences(of: "file://", with: "")
    }
    /// Only absolute paths count — relative "Contents/…" fragments are kept in
    /// `fields` verbatim but must not drive existence or signature checks.
    public var executablePath: String? {
        guard let raw = fields["Executable Path"], raw.hasPrefix("/") else { return nil }
        return raw
    }
    public var bundleIdentifier: String? { fields["Bundle Identifier"] }
    public var teamIdentifier: String? { fields["Team Identifier"] }
    public var developerName: String? {
        let d = fields["Developer Name"]
        guard let d, !d.isEmpty, d != "(null)" else { return nil }
        return d
    }
    public var parentIdentifier: String? { fields["Parent Identifier"] }

    /// `[enabled, allowed, notified] (0xb)` -> ["enabled","allowed","notified"]
    public var dispositionTokens: [String] {
        guard let d = fields["Disposition"],
              let open = d.firstIndex(of: "["), let close = d.lastIndex(of: "]") else { return [] }
        return d[d.index(after: open)..<close]
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespaces) }
    }
    public var isEnabled: Bool? {
        guard dispositionTokens.contains("disabled") else {
            return dispositionTokens.contains("enabled") ? true : nil
        }
        return false
    }
    /// True for record types that can have a launchd/plist backing.
    public var isServiceLike: Bool {
        ["legacy agent", "legacy daemon", "daemon", "agent"].contains(typeDescription)
    }
}

/// Result of `codesign -dvvv` for one path.
public struct CodeSignatureRecord: Equatable {
    public var path: String
    public var status: String           // signed | adhoc | unsigned | apple-system | unavailable
    public var identifier: String?
    public var teamIdentifier: String?
    public var authority0: String?

    public init(path: String, status: String, identifier: String? = nil,
                teamIdentifier: String? = nil, authority0: String? = nil) {
        self.path = path
        self.status = status
        self.identifier = identifier
        self.teamIdentifier = teamIdentifier
        self.authority0 = authority0
    }
}
