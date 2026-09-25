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
        /// V0.5.5: system extensions, kexts, privileged helper tools.
        public var systemExtensions: [SystemExtensionRecord]
        public var kexts: [KernelExtensionRecord]
        public var helpers: [PrivilegedHelperRecord]
        /// V0.5.6: scheduled, legacy persistence, plugin directories.
        public var scheduled: ScheduledScanner.Result
        public var legacy: LegacyScanner.Result
        public var plugins: [PluginBundleRecord]
        /// V0.5.7: shell startup files, listening sockets + firewall rules.
        public var shell: [ShellStartupRecord]
        public var network: NetworkScanner.Result
        public init(jobs: [LaunchJobRecord], launchd: [LaunchdServiceRecord],
                    btm: [BTMRecord], disabled: [String: Bool], uid: Int,
                    extensions: [AppExtensionRecord] = [],
                    systemExtensions: [SystemExtensionRecord] = [], kexts: [KernelExtensionRecord] = [],
                    helpers: [PrivilegedHelperRecord] = [],
                    scheduled: ScheduledScanner.Result = .init(), legacy: LegacyScanner.Result = .init(),
                    plugins: [PluginBundleRecord] = [],
                    shell: [ShellStartupRecord] = [], network: NetworkScanner.Result = .init()) {
            self.jobs = jobs; self.launchd = launchd; self.btm = btm
            self.disabled = disabled; self.uid = uid; self.extensions = extensions
            self.systemExtensions = systemExtensions; self.kexts = kexts; self.helpers = helpers
            self.scheduled = scheduled; self.legacy = legacy; self.plugins = plugins
            self.shell = shell; self.network = network
        }
    }

    public var fileManager: FileManager
    let home: String
    public init(fileManager: FileManager = .default, home: String = NSHomeDirectory()) {
        self.fileManager = fileManager; self.home = home
    }

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
            if let schedule = job.schedule { item.metadata["schedule"] = schedule }
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
            item.metadata["ext-identifier"] = ext.identifier
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

        // ---- Pass 5: system extensions + kernel extensions. Nothing else
        // describes them; they are their own items in the system domain.
        for ext in input.systemExtensions {
            let key = "sysext:" + ext.bundleIdentifier
            var item = BackgroundItem(key: key, displayName: ext.bundleIdentifier, type: .systemExtension,
                                      path: ext.installedPath, owner: "root", uid: 0, domain: .system,
                                      bundleIdentifier: ext.bundleIdentifier, teamIdentifier: ext.teamIdentifier,
                                      loaded: ext.active, running: ext.active, enabled: ext.enabled,
                                      category: .systemExtensions)
            item.metadata["sysext-kind"] = ext.kind
            item.metadata["sysext-state"] = ext.state
            item.metadata["sysext-name"] = ext.name
            if let version = ext.version { item.metadata["sysext-version"] = version }
            if let pane = ext.pane { item.metadata["sysext-pane"] = pane }
            if let host = ext.hostAppPath {
                item.parentApplication = ((host as NSString).lastPathComponent as NSString).deletingPathExtension
                item.appPresent = true
                item.metadata["sysext-host-app"] = host
            } else {
                item.metadata["sysext-host-app"] = "not found"
            }
            markDomain(&item, false)
            item.sources.append(SourceEvidence(
                kind: .systemExtension,
                detail: "systemextensionsctl: \(ext.bundleIdentifier) [\(ext.kind)] \(ext.state)", confidence: .high))
            accum[key] = item
        }
        for kext in input.kexts {
            let key = "kext:" + kext.bundleIdentifier
            var item = BackgroundItem(key: key, displayName: kext.bundleIdentifier, type: .kernelExtension,
                                      path: kext.path, owner: "root", uid: 0, domain: .system,
                                      bundleIdentifier: kext.bundleIdentifier,
                                      loaded: kext.loaded, running: kext.loaded, enabled: true,
                                      category: .systemExtensions)
            if let version = kext.version { item.metadata["kext-version"] = version }
            item.metadata["kext-loaded"] = kext.loaded ? "true" : "false"
            markDomain(&item, false)
            item.sources.append(SourceEvidence(
                kind: .systemExtension,
                detail: "kext: \(kext.bundleIdentifier)" + (kext.loaded ? " loaded" : " installed, not loaded"),
                confidence: .high))
            accum[key] = item
        }

        // ---- Pass 6: privileged helper tools. The SMJobBless daemon's plist
        // names the helper binary as Program — that item becomes the helper's
        // item. A helper no daemon points at is its own item, and a leftover:
        // nothing can start it.
        for helper in input.helpers {
            let canonical = PathUtils.canonicalize(helper.path, fileManager: fileManager)
            let match = accum.first { entry in
                entry.value.executable.map { PathUtils.canonicalize($0, fileManager: fileManager) == canonical } == true
            }
            let key: String
            var item: BackgroundItem
            if let match {
                key = match.key
                item = match.value
            } else {
                key = "helper:" + helper.name
                item = BackgroundItem(key: key, displayName: helper.name, type: .privilegedHelper,
                                      path: helper.path, executable: helper.path, owner: "root", uid: 0,
                                      domain: .system, enabled: true, category: .privilegedHelpers)
                markDomain(&item, false)
            }
            item.category = .privilegedHelpers
            if item.bundleIdentifier == nil { item.bundleIdentifier = helper.bundleIdentifier }
            if let version = helper.version { item.metadata["helper-version"] = version }
            item.metadata["helper-path"] = helper.path
            if !helper.authorizedClients.isEmpty {
                item.metadata["helper-clients"] = helper.authorizedClients.joined(separator: ", ")
            }
            if !helper.hasInfoPlist { item.metadata["helper-info-plist"] = "missing" }
            if let client = helper.authorizedClients.first {
                if let app = helper.clientAppPath {
                    if item.parentApplication == nil {
                        item.parentApplication = ((app as NSString).lastPathComponent as NSString).deletingPathExtension
                    }
                    item.appPresent = true
                    item.metadata["helper-client-app"] = app
                } else {
                    // A Spotlight miss is not evidence: it does not index
                    // /Library/Application Support, and clients are often
                    // nested bundles (an uninstaller inside the app). The
                    // client is named for display; appPresent stays as it was.
                    if item.parentApplication == nil { item.parentApplication = client }
                    item.metadata["helper-client-app"] = "not found via Spotlight"
                }
            }
            item.sources.append(SourceEvidence(
                kind: .helperTool,
                detail: "helper: \(helper.path)"
                    + (helper.authorizedClients.isEmpty ? "" : " clients: " + helper.authorizedClients.joined(separator: ", ")),
                confidence: .high))
            accum[key] = item
        }

        // ---- Pass 7: scheduled work outside launchd — cron, at, pmset,
        // periodic. Each is its own item; a cron command with an absolute
        // path is the executable (so "executable missing" applies).
        // Keys carry no pid, index or line number (V0.6.1): a snapshot diff
        // must find the same entry again. Twins get "#2", "#3" ….
        func uniqueKey(_ base: String) -> String {
            guard accum[base] != nil else { return base }
            var n = 2
            while accum[base + "#\(n)"] != nil { n += 1 }
            return base + "#\(n)"
        }
        func firstExecutable(_ command: String) -> String? {
            guard let token = command.split(separator: " ").first.map(String.init) else { return nil }
            return token.hasPrefix("/") ? token : nil
        }
        for entry in input.scheduled.cron {
            let key = uniqueKey("cron:\(entry.user):\(entry.source):\(entry.command)")
            let isUser = entry.source == "crontab"
            var item = BackgroundItem(key: key, displayName: entry.command.count > 72
                                        ? String(entry.command.prefix(69)) + "..." : entry.command,
                                      type: .cronJob, path: isUser ? nil : entry.source,
                                      executable: firstExecutable(entry.command),
                                      owner: entry.user, uid: isUser ? input.uid : 0,
                                      domain: isUser ? .user : .system, enabled: true, category: .scheduled)
            item.metadata["schedule"] = "cron " + entry.schedule
            item.metadata["cron-source"] = isUser ? "crontab -l (\(entry.user))" : entry.source
            item.metadata["cron-line"] = String(entry.line)
            item.metadata["cron-command"] = entry.command
            markDomain(&item, isUser)
            item.sources.append(SourceEvidence(kind: .cron,
                detail: "\(item.metadata["cron-source"]!) line \(entry.line): \(entry.schedule)", confidence: .high))
            accum[key] = item
        }
        for job in input.scheduled.atJobs {
            let key = "at:" + job.id
            var item = BackgroundItem(key: key, displayName: "at job \(job.id) (\(job.when))", type: .atJob,
                                      owner: job.owner, uid: input.uid, domain: .user, enabled: true,
                                      category: .scheduled)
            item.metadata["schedule"] = "at " + job.when
            item.metadata["at-queue"] = job.queue
            markDomain(&item, true)
            item.sources.append(SourceEvidence(kind: .at, detail: "atq: job \(job.id) queue \(job.queue) at \(job.when)",
                                               confidence: .high))
            accum[key] = item
        }
        for event in input.scheduled.powerEvents {
            let key = uniqueKey("pmset:\(event.owner):\(event.kind)")
            var item = BackgroundItem(key: key, displayName: event.owner, type: .powerEvent,
                                      owner: "root", uid: 0, domain: .system, enabled: true, category: .scheduled)
            item.metadata["schedule"] = "\(event.kind) at \(event.when)"
            item.metadata["power-kind"] = event.kind
            item.metadata["power-visible"] = event.userVisible ? "true" : "false"
            markDomain(&item, false)
            item.sources.append(SourceEvidence(kind: .pmset, detail: "pmset -g sched: \(event.kind) at \(event.when)",
                                               confidence: .high))
            accum[key] = item
        }
        for script in input.scheduled.periodic {
            let key = "periodic:\(script.period):\(script.name)"
            var item = BackgroundItem(key: key, displayName: script.name, type: .periodicScript,
                                      path: script.path, executable: script.path, owner: "root", uid: 0,
                                      domain: .system, enabled: true, category: .scheduled)
            item.metadata["schedule"] = "periodic " + script.period
            markDomain(&item, false)
            item.sources.append(SourceEvidence(kind: .periodic, detail: "periodic \(script.period): \(script.path)",
                                               confidence: .high))
            accum[key] = item
        }

        // ---- Pass 8: legacy persistence. loginwindow hooks, StartupItems,
        // rc.local & friends, emond rules.
        for hook in input.legacy.hooks {
            let isUser = hook.domain == .user
            let key = "hook:\(hook.kind):\(isUser ? "user" : "system")"
            var item = BackgroundItem(key: key, displayName: "\(hook.kind) → \(hook.script)", type: .loginHook,
                                      path: hook.source, executable: hook.script,
                                      owner: isUser ? "user" : "root", uid: isUser ? input.uid : 0,
                                      domain: hook.domain, enabled: true, category: .legacy)
            item.metadata["hook-kind"] = hook.kind
            markDomain(&item, isUser)
            item.sources.append(SourceEvidence(kind: .legacy, detail: "\(hook.kind) in \(hook.source)", confidence: .high))
            accum[key] = item
        }
        for startup in input.legacy.startupItems {
            let key = "startupitem:" + startup.name
            var item = BackgroundItem(key: key, displayName: startup.name, type: .startupItem,
                                      path: startup.directory, executable: startup.script, owner: "root", uid: 0,
                                      domain: .system, enabled: true, category: .legacy)
            if let description = startup.description { item.metadata["startup-description"] = description }
            if !startup.provides.isEmpty { item.metadata["startup-provides"] = startup.provides.joined(separator: ", ") }
            if !startup.hasParameters { item.metadata["startup-parameters"] = "missing" }
            markDomain(&item, false)
            item.sources.append(SourceEvidence(kind: .legacy, detail: "StartupItem: \(startup.directory)", confidence: .high))
            accum[key] = item
        }
        for file in input.legacy.files {
            let key = "legacy:\(file.kind):\(file.path)"
            let type: ItemType = file.kind == "emond-rule" ? .emondRule : .rcScript
            var item = BackgroundItem(key: key, displayName: (file.path as NSString).lastPathComponent, type: type,
                                      path: file.path, executable: type == .rcScript ? file.path : nil,
                                      owner: "root", uid: 0, domain: .system, enabled: true, category: .legacy)
            item.metadata["legacy-kind"] = file.kind
            markDomain(&item, false)
            item.sources.append(SourceEvidence(kind: .legacy, detail: "\(file.kind): \(file.path)", confidence: .high))
            accum[key] = item
        }

        // ---- Pass 9: plugin directories. One item per bundle.
        for plugin in input.plugins {
            let key = "plugin:\(plugin.kind):\(plugin.name)"
            let isUser = plugin.domain == .user
            var item = BackgroundItem(key: key, displayName: plugin.name, type: .plugin, path: plugin.path,
                                      owner: isUser ? "user" : "root", uid: isUser ? input.uid : 0,
                                      domain: plugin.domain, bundleIdentifier: plugin.bundleIdentifier,
                                      loaded: plugin.wiredIntoLogin ?? false, enabled: true,
                                      category: .pluginDirectories)
            item.metadata["plugin-kind"] = plugin.kind
            if let version = plugin.version { item.metadata["plugin-version"] = version }
            if let wired = plugin.wiredIntoLogin {
                item.metadata["auth-login-mechanism"] = wired ? "referenced by system.login.console" : "not referenced by system.login.console"
            }
            markDomain(&item, isUser)
            item.sources.append(SourceEvidence(kind: .plugin, detail: "\(plugin.kind): \(plugin.path)", confidence: .high))
            accum[key] = item
        }

        // ---- Pass 10: shell startup files. One item per file; sourced
        // files (depth 1) and PATH additions are items of their own.
        func shortHome(_ path: String) -> String {
            path.hasPrefix(home + "/") ? "~" + path.dropFirst(home.count) : path
        }
        for file in input.shell {
            let key = "shell:" + file.path
            let isUser = file.domain == .user
            var item = BackgroundItem(key: key, displayName: shortHome(file.path),
                                      type: file.kind == "paths" ? .pathEntry : .shellProfile, path: file.path,
                                      owner: isUser ? "user" : "root", uid: isUser ? input.uid : 0,
                                      domain: file.domain, enabled: true, category: .shellStartup)
            item.metadata["shell-kind"] = file.kind
            item.metadata["shell-size"] = String(file.size)
            item.metadata["shell-lines"] = String(file.lines)
            if let modified = file.modified { item.metadata["shell-modified"] = modified }
            if !file.sourced.isEmpty { item.metadata[file.kind == "paths" ? "path-entries" : "shell-sources"] = file.sourced.joined(separator: ", ") }
            if !file.unresolved.isEmpty { item.metadata["shell-sources-unresolved"] = file.unresolved.joined(separator: ", ") }
            if !file.missingSources.isEmpty {
                item.metadata[file.kind == "paths" ? "path-entries-missing" : "shell-sources-missing"] = file.missingSources.joined(separator: ", ")
            }
            if !file.hints.isEmpty { item.metadata["shell-launch-hints"] = file.hints.joined(separator: "; ") }
            if let by = file.sourcedBy { item.metadata["shell-sourced-by"] = by }
            markDomain(&item, isUser)
            item.sources.append(SourceEvidence(kind: .shell, detail: "\(file.kind): \(file.path)", confidence: .high))
            accum[key] = item
        }

        // ---- Pass 11: network. One item per listening process, linked to
        // the inventory entry whose executable it is; firewall rules merge
        // into the process they name or stand alone.
        func ownerKey(forExecutable exec: String) -> String? {
            let canonical = PathUtils.canonicalize(exec, fileManager: fileManager)
            if let hit = accum.first(where: { entry in
                entry.value.category != .network
                    && entry.value.executable.map { PathUtils.canonicalize($0, fileManager: fileManager) == canonical } == true
            }) { return hit.key }
            // An app bundle's process: the entry that names the bundle —
            // V0.4 app context, a BTM component's bundle path, or the login
            // item whose path IS the app.
            return accum.first(where: { entry in
                guard entry.value.category != .network else { return false }
                let candidates = [entry.value.metadata["app-bundle"], entry.value.metadata["btm-bundle-path"],
                                  entry.value.path.flatMap { $0.hasSuffix(".app") ? $0 : nil }]
                return candidates.contains { $0.map { exec.hasPrefix($0 + "/") } == true }
            })?.key
        }
        var networkKeyByExecutable: [String: String] = [:]
        for process in input.network.processes {
            let key = uniqueKey("net:" + (process.executable ?? process.command))
            let isRoot = process.user == "root"
            let listening = process.sockets.map { socket -> String in
                var text = "\(socket.proto)/\(socket.port.map(String.init) ?? socket.address)"
                if socket.loopbackOnly { text += " (loopback)" }
                return text
            }.joined(separator: ", ")
            var item = BackgroundItem(key: key, displayName: "\(process.command) (pid \(process.pid))", type: .listener,
                                      path: process.executable, executable: process.executable,
                                      owner: process.user, uid: isRoot ? 0 : input.uid,
                                      domain: isRoot ? .system : .user, loaded: true, running: true, enabled: true,
                                      category: .network)
            item.metadata["listening"] = listening
            item.metadata["net-pid"] = String(process.pid)
            if process.executable == nil { item.metadata["net-executable"] = "unresolved" }
            if let exec = process.executable, let owner = ownerKey(forExecutable: exec) {
                item.metadata["network-entry"] = owner
                accum[owner]?.metadata["listening"] = listening
                if let label = accum[owner]?.label { item.label = nil; item.metadata["network-entry-label"] = label }
            }
            markDomain(&item, !isRoot)
            item.sources.append(SourceEvidence(kind: .lsof, detail: "lsof: pid \(process.pid) \(listening)", confidence: .high))
            if let exec = process.executable { networkKeyByExecutable[exec] = key }
            accum[key] = item
        }
        for rule in input.network.firewall {
            if let key = networkKeyByExecutable[rule.path] {
                accum[key]?.metadata["firewall"] = rule.action + " incoming connections"
                accum[key]?.sources.append(SourceEvidence(kind: .firewall, detail: "socketfilterfw: \(rule.action) \(rule.path)",
                                                          confidence: .high))
                continue
            }
            let key = "fw:" + rule.path
            var item = BackgroundItem(key: key, displayName: (rule.path as NSString).lastPathComponent, type: .firewallRule,
                                      path: rule.path, executable: rule.path, owner: "root", uid: 0, domain: .system,
                                      enabled: true, category: .network)
            item.metadata["firewall"] = rule.action + " incoming connections"
            if let owner = ownerKey(forExecutable: rule.path) { item.metadata["network-entry"] = owner }
            markDomain(&item, false)
            item.sources.append(SourceEvidence(kind: .firewall, detail: "socketfilterfw: \(rule.action) \(rule.path)",
                                               confidence: .high))
            accum[key] = item
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