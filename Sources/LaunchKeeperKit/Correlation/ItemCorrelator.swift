import Foundation

/// Merges plists, launchd output and BTM records into normalized BackgroundItems.
///
/// Design rule: a BTM entry is NOT one plist. A BTM record can aggregate a
/// SMAppService helper, a launchd job and a login item at once, so every merge
/// carries a confidence and all evidence is kept in `sources`.
public struct ItemCorrelator {
    public struct Input {
        public var jobs: [LaunchJobRecord]
        public var launchd: [LaunchdServiceRecord]
        public var btm: [BTMRecord]
        public var disabled: [String: Bool]
        public var uid: Int
        /// V0.5.4: app extensions from `pluginkit -mAvv`.
        public var extensions: [AppExtensionRecord]
        public init(jobs: [LaunchJobRecord], launchd: [LaunchdServiceRecord],
                    btm: [BTMRecord], disabled: [String: Bool], uid: Int,
                    extensions: [AppExtensionRecord] = []) {
            self.jobs = jobs; self.launchd = launchd; self.btm = btm
            self.disabled = disabled; self.uid = uid; self.extensions = extensions
        }
    }

    public var fileManager: FileManager
    public init(fileManager: FileManager = .default) { self.fileManager = fileManager }

    public func correlate(_ input: Input) -> (items: [BackgroundItem], uncorrelated: [String]) {
        var accum: [String: BackgroundItem] = [:]
        var uncorrelated: [String] = []

        func markDomain(_ item: inout BackgroundItem, _ isUser: Bool) {
            item.metadata[isUser ? "domain-user" : "domain-system"] = "true"
        }

        // ---- Pass 1: plists seed the inventory.
        for job in input.jobs {
            var item = accum[job.label]
                ?? BackgroundItem(key: job.label, displayName: job.label, type: job.kind, label: job.label)
            if !item.plistPresent {
                item.plistPresent = true
                item.path = job.path
                item.owner = job.ownerName
                item.uid = (job.domain == .user) ? input.uid : 0
            }
            if job.kind == .launchDaemon { item.type = .launchDaemon }
            markDomain(&item, job.domain == .user)
            item.executable = item.executable ?? job.program
            if item.arguments.isEmpty { item.arguments = job.arguments }
            item.sources.append(SourceEvidence(kind: .plist, detail: job.path, confidence: .high))
            if job.runAtLoad { item.metadata["runAtLoad"] = "true" }
            if job.keepAlive { item.metadata["keepAlive"] = "true" }
            // An override exists independently of a loaded job: an unloaded
            // agent with `print-disabled` = disabled is disabled (V0.4.3 —
            // without this, `remove` did not know to drop the stale override).
            if isDisabled(label: job.label, in: input.disabled) { item.enabled = false }
            accum[job.label] = item
        }

        // ---- Pass 2: live launchd state.
        for rec in input.launchd where !LaunchctlParser.isInstanceService(rec.label) {
            var item: BackgroundItem
            if let existing = accum[rec.label] {
                item = existing
            } else {
                // Apple runtime bookkeeping and per-app launch registrations
                // (`application.<bundleid>…`) would flood the table; only
                // non-noise launchd entries without any plist become their own item.
                guard !rec.label.hasPrefix("com.apple."),
                      !rec.label.hasPrefix("application.") else { continue }
                item = BackgroundItem(key: rec.label, displayName: rec.label, type: .unknown, label: rec.label)
                item.owner = rec.domainKind == "gui" ? "user" : "root"
            }
            item.loaded = true
            item.running = rec.pid != nil
            item.pid = rec.pid
            item.launchdPresent = true
            markDomain(&item, rec.domainKind == "gui")
            item.sources.append(SourceEvidence(
                kind: .launchd,
                detail: "\(rec.domainKind): \(rec.label)" + (rec.pid.map { " pid:\($0)" } ?? ""),
                confidence: .high))
            item.metadata["launchd-state"] = "\(rec.domainKind) \(rec.stateToken)"
            if isDisabled(label: rec.label, in: input.disabled) { item.enabled = false }
            accum[rec.label] = item
        }

        // ---- Pass 3: BTM records attach to items (many-to-one) or stand alone.
        var appMap: [String: BTMRecord] = [:]
        for rec in input.btm where rec.typeDescription == "app" {
            appMap[rec.identifier] = rec
        }

        for rec in input.btm {
            guard rec.typeDescription != "developer", rec.typeDescription != "app" else { continue }

            var matchKey: String?
            var confidence: Confidence = .medium

            // Only launchd-shaped records correlate with plists and jobs. A
            // login item, QuickLook or Spotlight registration is its OWN
            // component even when its bundle id core equals a launch agent's
            // label (live: Docker's LoginItems helper vs. com.docker.helper) —
            // merging it made the login item vanish from the inventory (V0.5.1).
            let launchdShaped = rec.isServiceLike || rec.url?.hasSuffix(".plist") == true
            if launchdShaped, let url = rec.url, url.hasSuffix(".plist") {
                let label = (url as NSString).lastPathComponent
                    .replacingOccurrences(of: ".plist", with: "")
                if accum[label] != nil { matchKey = label; confidence = .high }
            }
            if launchdShaped, matchKey == nil {
                let core = stripIdentifierPrefix(rec.identifier)
                if !core.isEmpty, accum[core] != nil { matchKey = core; confidence = .high }
            }
            if launchdShaped, matchKey == nil, let exec = rec.executablePath {
                let canon = PathUtils.canonicalize(exec, fileManager: fileManager)
                if let hit = accum.first(where: { entry in
                    (entry.value.executable.map { PathUtils.canonicalize($0, fileManager: fileManager) } == canon)
                        || entry.value.arguments.contains { PathUtils.canonicalize($0, fileManager: fileManager) == canon }
                }) {
                    matchKey = hit.key
                    confidence = .medium
                }
            }

            // Parent application from BTM aggregation.
            func applyParent(to item: inout BackgroundItem) {
                if let parentId = rec.parentIdentifier, let parent = appMap[parentId] {
                    item.parentApplication = parent.name.isEmpty ? parent.identifier : parent.name
                    var appPath: String?
                    if let url = parent.url, url.hasPrefix("/") {
                        appPath = url
                    } else if !parent.name.isEmpty {
                        appPath = "/Applications/\(parent.name).app"
                    }
                    if let appPath {
                        let candidate = appPath + "/" + (rec.url ?? "")
                        let probe = (rec.url?.hasPrefix("/") == true) ? appPath
                            : (fileManager.fileExists(atPath: appPath) ? candidate : nil)
                        if let probe { item.appPresent = fileManager.fileExists(atPath: probe) }
                        // Absolute location of the record's own bundle — what
                        // pluginkit reports as Path, so the two can merge.
                        if let url = rec.url {
                            item.metadata["btm-bundle-path"] = url.hasPrefix("/") ? url : candidate
                        }
                    }
                }
            }

            if var item = matchKey.flatMap({ accum[$0] }) {
                item.btmPresent = true
                item.sources.append(SourceEvidence(kind: .btm,
                    detail: "btm: \(rec.identifier) [\(rec.typeDescription)]", confidence: confidence))
                item.teamIdentifier = item.teamIdentifier ?? rec.teamIdentifier
                item.bundleIdentifier = item.bundleIdentifier ?? rec.bundleIdentifier
                item.developer = item.developer ?? rec.developerName
                if item.executable == nil { item.executable = rec.executablePath }
                item.metadata["btm-disposition"] = rec.fields["Disposition"] ?? ""
                item.metadata["btm-type"] = rec.typeDescription
                item.metadata["btm-identifier"] = rec.identifier
                if let parent = rec.parentIdentifier { item.metadata["btm-parent"] = parent }
                if rec.isEnabled == false { item.enabled = false }
                applyParent(to: &item)
                if (rec.isServiceLike || rec.url?.hasSuffix(".plist") == true), matchKey == nil {
                    uncorrelated.append(rec.identifier)
                }
                accum[matchKey!] = item
                continue
            }

            // No correlation: standalone BTM entry (login items, orphan helpers,
            // shell-based services whose plist is already gone). Same identifier
            // registered under several UIDs merges into ONE item.
            let standaloneKey = "btm:" + (rec.identifier.isEmpty
                ? "uid\(rec.sectionUID):" + (rec.fields["UUID"] ?? rec.url ?? rec.name)
                : rec.identifier)
            if let existing = accum[standaloneKey] {
                var merged = existing
                merged.sources.append(SourceEvidence(kind: .btm,
                    detail: "btm: \(rec.identifier) uid:\(rec.sectionUID)", confidence: .low))
                if rec.sectionUID != merged.uid, merged.uid >= 0, rec.sectionUID > merged.uid {
                    merged.uid = rec.sectionUID
                }
                accum[standaloneKey] = merged
                continue
            }
            var item = BackgroundItem(
                key: standaloneKey,
                displayName: rec.name.isEmpty ? rec.identifier : rec.name,
                type: rec.typeDescription == "login item" ? .loginItem : .btmEntry)
            item.btmPresent = true
            let derivedLabel = stripIdentifierPrefix(rec.identifier)
            if derivedLabel.contains(".") { item.label = derivedLabel }
            item.path = rec.url
            item.executable = rec.executablePath
            item.domain = rec.sectionUID > 0 ? .user : .system
            item.owner = "unknown"
            item.uid = rec.sectionUID
            item.developer = rec.developerName
            item.teamIdentifier = rec.teamIdentifier
            item.bundleIdentifier = rec.bundleIdentifier
            item.metadata["btm-disposition"] = rec.fields["Disposition"] ?? ""
            item.metadata["btm-type"] = rec.typeDescription
            item.metadata["btm-identifier"] = rec.identifier
            if let parent = rec.parentIdentifier { item.metadata["btm-parent"] = parent }
            item.category = Self.category(forBTMType: rec.typeDescription)
            if let enabled = rec.isEnabled { item.enabled = enabled }
            if let label = item.label, isDisabled(label: label, in: input.disabled) { item.enabled = false }
            item.sources.append(SourceEvidence(kind: .btm,
                detail: "btm: \(rec.identifier) [\(rec.typeDescription)] uid:\(rec.sectionUID)",
                confidence: .low))
            applyParent(to: &item)
            if rec.isServiceLike || rec.url?.hasSuffix(".plist") == true {
                uncorrelated.append(rec.identifier.isEmpty ? (rec.url ?? rec.name) : rec.identifier)
            }
            accum[standaloneKey] = item
        }

        // ---- Pass 4: app extensions (pluginkit). BTM already lists some of
        // them (QuickLook, Spotlight, dock tiles): those merge by their
        // bundle path, or by the bundle's file name when BTM only had the
        // relative URL. The rest become their own items. `-A` lists every
        // version of an identifier — one item, versions in metadata.
        var byBundlePath: [String: String] = [:]
        var byBundleName: [String: String] = [:]
        for (key, item) in accum where item.btmPresent && !item.plistPresent && !item.launchdPresent {
            if let path = item.metadata["btm-bundle-path"] {
                byBundlePath[PathUtils.canonicalize(path, fileManager: fileManager)] = key
            }
            if let path = item.path {
                byBundleName[(path as NSString).lastPathComponent] = key
            }
        }
        var extensionKeys: [String: String] = [:]
        for ext in input.extensions {
            if let key = extensionKeys[ext.identifier] {
                let versions = accum[key]?.metadata["ext-versions"] ?? ""
                accum[key]?.metadata["ext-versions"] = versions.isEmpty ? ext.version : versions + ", " + ext.version
                continue
            }
            var key: String?
            if let path = ext.path {
                key = byBundlePath[PathUtils.canonicalize(path, fileManager: fileManager)]
                    ?? byBundleName[(path as NSString).lastPathComponent]
            }
            var item: BackgroundItem
            if let key, let existing = accum[key] {
                item = existing
            } else {
                key = "ext:" + ext.identifier
                item = BackgroundItem(key: key!, displayName: ext.identifier, type: .appExtension,
                                      path: ext.path, owner: "user", uid: input.uid, domain: .user,
                                      category: .appExtensions)
            }
            item.type = .appExtension
            item.category = .appExtensions
            if let path = ext.path, !(item.path?.hasPrefix("/") ?? false) { item.path = path }
            item.metadata["ext-election"] = ext.election.rawValue
            item.metadata["ext-version"] = ext.version
            if let sdk = ext.sdk { item.metadata["ext-sdk"] = sdk }
            if let name = ext.displayName { item.metadata["ext-display-name"] = name }
            if let parent = ext.parentBundle { item.metadata["ext-parent-bundle"] = parent }
            if let parentName = ext.parentName, item.parentApplication == nil { item.parentApplication = parentName }
            if item.bundleIdentifier == nil { item.bundleIdentifier = ext.identifier }
            if !ext.enabled { item.enabled = false }
            markDomain(&item, true)
            item.sources.append(SourceEvidence(
                kind: .pluginkit,
                detail: "pluginkit: \(ext.identifier) [\(ext.election.rawValue)]" + (ext.sdk.map { " \($0)" } ?? ""),
                confidence: .high))
            accum[key!] = item
            extensionKeys[ext.identifier] = key!
        }

        // ---- Finalize: domain derivation + deterministic ids.
        var items: [BackgroundItem] = []
        for entry in accum.values {
            var item = entry
            let user = item.metadata["domain-user"] == "true"
            let sys = item.metadata["domain-system"] == "true"
            switch (user, sys) {
            case (true, true): item.domain = .mixed
            case (false, true): item.domain = .system
            case (true, false): item.domain = .user
            case (false, false): break   // standalone BTM items keep their section-derived domain
            }
            items.append(item)
        }
        items.sort { lhs, rhs in
            if lhs.domain != rhs.domain { return domainRank(lhs.domain) < domainRank(rhs.domain) }
            return lhs.key < rhs.key
        }
        for i in items.indices {
            items[i].id = String(format: "%02d", i + 1)
        }
        return (items, uncorrelated)
    }

    /// Category of a BTM-only record by its BTM type: launchd-shaped records
    /// stay Launch Items, login items are Login Items, everything else
    /// (QuickLook, Spotlight, dock tiles, app extensions) is an App Extension.
    static func category(forBTMType type: String) -> ItemCategory {
        switch type {
        case "legacy agent", "legacy daemon", "agent", "daemon": return .launchItems
        case "login item", "background app refresh": return .loginItems
        default: return .appExtensions
        }
    }

    private func domainRank(_ domain: ItemDomain) -> Int {
        switch domain { case .user: 0; case .system: 1; case .mixed: 2 }
    }

    private func stripIdentifierPrefix(_ identifier: String) -> String {
        // "16.de.example.zet-watchdog" -> "de.example.zet-watchdog"
        guard let dot = identifier.firstIndex(of: ".") else { return identifier }
        let prefix = identifier[identifier.startIndex..<dot]
        guard !prefix.isEmpty, prefix.allSatisfy({ $0.isNumber }) else { return identifier }
        return String(identifier[identifier.index(after: dot)...])
    }

    /// Enabled-state lookup tolerating Team-ID-prefixed keys
    /// ("ABCDE12345.com.example.browser-helper" for label com.example.browser-helper).
    private func isDisabled(label: String, in map: [String: Bool]) -> Bool {
        if map[label] == false { return true }
        return map.contains { key, value in
            !value && key.hasSuffix("." + label)
        }
    }
}