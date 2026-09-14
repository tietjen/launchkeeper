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
        public init(jobs: [LaunchJobRecord], launchd: [LaunchdServiceRecord],
                    btm: [BTMRecord], disabled: [String: Bool], uid: Int) {
            self.jobs = jobs; self.launchd = launchd; self.btm = btm
            self.disabled = disabled; self.uid = uid
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

            if let url = rec.url, url.hasSuffix(".plist") {
                let label = (url as NSString).lastPathComponent
                    .replacingOccurrences(of: ".plist", with: "")
                if accum[label] != nil { matchKey = label; confidence = .high }
            }
            if matchKey == nil {
                let core = stripIdentifierPrefix(rec.identifier)
                if !core.isEmpty, accum[core] != nil { matchKey = core; confidence = .high }
            }
            if matchKey == nil, let exec = rec.executablePath {
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