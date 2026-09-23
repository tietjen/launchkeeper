import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Read-only V0.1 pipeline: scanners -> correlation -> analysis.
/// This type contains NO write or delete logic of any kind; every command it
/// runs is a read (`launchctl print*`, `sfltool dumpbtm`, `codesign -dvvv`).
public struct ScanOptions: Sendable {
    public var includeUser: Bool
    public var includeSystem: Bool
    public var scanBTM: Bool
    public var scanSignatures: Bool
    /// App extensions via `pluginkit -mAvv` (V0.5.4). Contributes items, so
    /// a failure marks the inventory incomplete.
    public var scanExtensions: Bool
    /// System extensions + kexts (systemextensionsctl, kmutil, /Library/Extensions) (V0.5.5).
    public var scanSystemExtensions: Bool
    /// /Library/PrivilegedHelperTools with embedded Info.plists (V0.5.5).
    public var scanHelpers: Bool
    /// cron, at, pmset power events, periodic scripts (V0.5.6).
    public var scanScheduled: Bool
    /// loginwindow hooks, StartupItems, rc.local, emond rules (V0.5.6).
    public var scanLegacy: Bool
    /// Plugin directories: authorization, HAL, Spotlight, QuickLook, … (V0.5.6).
    public var scanPlugins: Bool
    /// Shell startup files and what they source (V0.5.7).
    public var scanShell: Bool
    /// Listening sockets (lsof) and Application Firewall rules (V0.5.7).
    public var scanNetwork: Bool
    /// Package receipts via pkgutil for provenance (V0.6). Enrichment only.
    public var scanReceipts: Bool
    public init(includeUser: Bool = true, includeSystem: Bool = true,
                scanBTM: Bool = true, scanSignatures: Bool = true, scanExtensions: Bool = true,
                scanSystemExtensions: Bool = true, scanHelpers: Bool = true,
                scanScheduled: Bool = true, scanLegacy: Bool = true, scanPlugins: Bool = true,
                scanShell: Bool = true, scanNetwork: Bool = true, scanReceipts: Bool = true) {
        self.scanShell = scanShell
        self.scanNetwork = scanNetwork
        self.scanReceipts = scanReceipts
        self.includeUser = includeUser
        self.includeSystem = includeSystem
        self.scanBTM = scanBTM
        self.scanSignatures = scanSignatures
        self.scanExtensions = scanExtensions
        self.scanSystemExtensions = scanSystemExtensions
        self.scanHelpers = scanHelpers
        self.scanScheduled = scanScheduled
        self.scanLegacy = scanLegacy
        self.scanPlugins = scanPlugins
    }
}

public struct ScanReport {
    public var items: [BackgroundItem]
    public var uncorrelated: [String]
    public var warnings: [String]
    /// Environment/self-check lines for `launchkeeper doctor`.
    public var checks: [String]
    /// Sources that contribute ITEMS and did not answer in this run
    /// (`launchctl print <domain>`, `sfltool dumpbtm`). Display ids are
    /// positional, so a run missing one of these numbers the inventory
    /// differently from a complete run — numeric addressing is unsafe then
    /// (V0.4.5). Sources that only enrich (print-disabled, codesign, mdfind)
    /// are not listed: they never change the item set.
    public var incompleteLayers: [String]
    /// V0.6: the package receipt index, when pkgutil answered.
    public var receiptIndex: ReceiptIndex?
    /// App / developer rows of Background Task Management (V0.5).
    public var btmContainers: [BTMContainer]
    public init(items: [BackgroundItem], uncorrelated: [String],
                warnings: [String], checks: [String] = [], incompleteLayers: [String] = [],
                btmContainers: [BTMContainer] = []) {
        self.items = items; self.uncorrelated = uncorrelated
        self.warnings = warnings; self.checks = checks
        self.incompleteLayers = incompleteLayers
        self.btmContainers = btmContainers
    }
}

/// Everything a scan needs, injectable so tests never touch the real system.
public struct ScanEnvironment {
    public var runner: CommandRunner
    public var fileManager: FileManager
    public var home: String
    public var uid: Int
    public init(runner: CommandRunner = SystemCommandRunner(),
                fileManager: FileManager = .default,
                home: String = NSHomeDirectory(),
                uid: Int = Int(getuid())) {
        self.runner = runner; self.fileManager = fileManager
        self.home = home; self.uid = uid
    }
}

public struct ScanCoordinator {
    public var environment: ScanEnvironment
    public init(environment: ScanEnvironment = ScanEnvironment()) {
        self.environment = environment
    }

    public func perform(options: ScanOptions = ScanOptions()) -> ScanReport {
        let env = environment
        var warnings: [String] = []
        var checks: [String] = []
        var incomplete: [String] = []

        let version = ProcessInfo.processInfo.operatingSystemVersion
        checks.append("macOS \(version.majorVersion).\(version.minorVersion).\(version.patchVersion)")

        // ---- Stage 1: plists (read-only).
        var dirs = LaunchJobScanner.defaultDirectories(home: env.home)
        if !options.includeUser { dirs.removeAll { $0.domain == .user } }
        if !options.includeSystem { dirs.removeAll { $0.domain == .system } }
        let jobScanner = LaunchJobScanner(directories: dirs, fileManager: env.fileManager)
        let (jobs, plistWarnings) = jobScanner.scan()
        warnings.append(contentsOf: plistWarnings)
        checks.append("plist sources: \(dirs.count) dirs, \(jobs.count) jobs read")

        // ---- Stage 2: live launchd state.
        var launchd: [LaunchdServiceRecord] = []
        var disabled: [String: Bool] = [:]
        for (kind, isOn) in [("gui", options.includeUser), ("system", options.includeSystem)] where isOn {
            let target = kind == "gui" ? "gui/\(env.uid)" : "system"
            let printResult = env.runner.run(command: "/bin/launchctl", arguments: ["print", target])
            if printResult.exitCode == 0 {
                let services = LaunchctlParser.parsePrint(printResult.stdout, domainKind: kind)
                launchd.append(contentsOf: services)
                checks.append("launchctl print \(target): ok (\(services.count) service lines)")
            } else {
                warnings.append("launchctl print \(target) failed (exit \(printResult.exitCode)) — "
                    + "live state incomplete")
                checks.append("launchctl print \(target): FAILED (exit \(printResult.exitCode))")
                incomplete.append("launchctl print \(target)")
            }
            let disabledResult = env.runner.run(
                command: "/bin/launchctl", arguments: ["print-disabled", target])
            if disabledResult.exitCode == 0 {
                for (key, value) in LaunchctlParser.parseDisabled(disabledResult.stdout) {
                    disabled[key] = value
                }
                checks.append("launchctl print-disabled \(target): ok")
            } else {
                warnings.append("launchctl print-disabled \(target) failed — "
                    + "enabled/disabled state unknown")
                checks.append("launchctl print-disabled \(target): FAILED (exit \(disabledResult.exitCode))")
            }
        }

        // ---- Stage 3: BTM. Failure degrades gracefully: empty records + warning.
        var btm: [BTMRecord] = []
        var containers: [BTMContainer] = []
        if options.scanBTM {
            // One attempt, no blind retry: sfltool either answers within seconds
            // or is stuck — cold start after an OS upgrade, sandbox, permissions.
            // A blind second attempt only doubles the dead wait; the warning
            // names the causes and the user decides. Budget: LAUNCHKEEPER_BTM_TIMEOUT.
            let environment = ProcessInfo.processInfo.environment
            // 150 s: the FIRST dumpbtm after the daemon sat idle took 76 s and 97 s
            // live (2026-09-22, macOS 27 — BTM re-validates every registered bundle,
            // large apps dominate), the next one 1–5 s. 45 s cut that off.
            let budget = (environment["LAUNCHKEEPER_BTM_TIMEOUT"] ?? environment["BTMCTL_BTM_TIMEOUT"])
                .flatMap { Double($0) } ?? 150
            // A cold daemon answers after a minute; without a word the scan
            // looks frozen. The hint fires only if the call is still running
            // after 5 s (test doubles answer instantly and never see it).
            let hint = DispatchWorkItem {
                FileHandle.standardError.write(Data(("waiting for sfltool dumpbtm — the BTM daemon's "
                    + "first answer after idle can take a minute or two (budget \(Int(budget)) s)\n").utf8))
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + 5, execute: hint)
            let result = env.runner.run(command: "/usr/bin/sfltool",
                                        arguments: ["dumpbtm"], timeout: budget)
            hint.cancel()
            if result.exitCode == 0 {
                let (records, parseWarnings) = BTMDumpParser.parse(result.stdout)
                btm = records
                containers = BTMContainerIndex.build(from: records)
                checks.append("sfltool dumpbtm: ok (\(records.count) records)")
                checks.append("btm containers: \(containers.count) app/developer rows")
                if records.isEmpty {
                    warnings.append("sfltool dumpbtm produced no parsable records")
                }
                warnings.append(contentsOf: parseWarnings.prefix(20))
            } else if result.exitCode == -2 {
                // The tool cannot tell WHY it timed out: the first run after a
                // macOS upgrade warms up the BTM daemon (store migration — seen
                // live on the 26 → 27 upgrade: 45 s timeout, 3 s on the next
                // run), while a sandboxed or permission-blocked call never
                // answers. Name both causes, claim neither.
                warnings.append("sfltool dumpbtm timed out after \(Int(budget))s — "
                    + "BTM layer not scanned. Typical causes: the first call after the "
                    + "BTM daemon sat idle or after a macOS upgrade (it can take a minute or "
                    + "two, the next call takes seconds — simply run again) or a "
                    + "blocked call (sandbox/permissions). Check with `sfltool dumpbtm` "
                    + "yourself; raise the budget with LAUNCHKEEPER_BTM_TIMEOUT=<seconds>")
                checks.append("sfltool dumpbtm: FAILED (timeout \(Int(budget))s)")
                incomplete.append("sfltool dumpbtm")
            } else {
                warnings.append("sfltool dumpbtm failed (exit \(result.exitCode)) — "
                    + "BTM layer not scanned")
                checks.append("sfltool dumpbtm: FAILED (exit \(result.exitCode))")
                incomplete.append("sfltool dumpbtm")
            }
        } else {
            checks.append("sfltool dumpbtm: skipped")
        }

        // ---- Stage 3b: app extensions (pluginkit -mAvv). Contributes items.
        var extensions: [AppExtensionRecord] = []
        if options.scanExtensions {
            let scan = PluginKitScanner(runner: env.runner).scan()
            if scan.exitCode == 0 {
                extensions = scan.records
                let elected = extensions.filter { $0.election == .use }.count
                checks.append("pluginkit: ok (\(extensions.count) extensions, \(elected) elected)")
                warnings.append(contentsOf: scan.warnings.prefix(10))
            } else {
                warnings.append(contentsOf: scan.warnings)
                checks.append("pluginkit: FAILED (exit \(scan.exitCode))")
                incomplete.append("pluginkit")
            }
        } else {
            checks.append("pluginkit: skipped")
        }

        // ---- Stage 3c: system extensions + kexts. Contribute items.
        var systemExtensions: [SystemExtensionRecord] = []
        var kexts: [KernelExtensionRecord] = []
        if options.scanSystemExtensions {
            let result = SystemExtensionScanner(runner: env.runner, fileManager: env.fileManager, home: env.home).scan()
            systemExtensions = result.extensions
            kexts = result.kexts
            checks.append(contentsOf: result.checks)
            warnings.append(contentsOf: result.warnings)
            incomplete.append(contentsOf: result.failed)
        } else {
            checks.append("system extensions: skipped")
        }

        // ---- Stage 3d: privileged helper tools. Contribute items.
        var helpers: [PrivilegedHelperRecord] = []
        if options.scanHelpers {
            let result = PrivilegedHelperScanner(runner: env.runner, fileManager: env.fileManager).scan()
            helpers = result.helpers
            checks.append(contentsOf: result.checks)
            warnings.append(contentsOf: result.warnings)
            incomplete.append(contentsOf: result.failed)
        } else {
            checks.append("privileged helpers: skipped")
        }

        // ---- Stage 3e: scheduled (cron, at, pmset, periodic). Contribute items.
        var scheduled = ScheduledScanner.Result()
        if options.scanScheduled {
            scheduled = ScheduledScanner(runner: env.runner, fileManager: env.fileManager).scan()
            checks.append(contentsOf: scheduled.checks)
            warnings.append(contentsOf: scheduled.warnings)
            incomplete.append(contentsOf: scheduled.failed)
        } else {
            checks.append("scheduled: skipped")
        }

        // ---- Stage 3f: legacy persistence. File reads only.
        var legacy = LegacyScanner.Result()
        if options.scanLegacy {
            legacy = LegacyScanner(fileManager: env.fileManager, home: env.home).scan()
            checks.append(contentsOf: legacy.checks)
            warnings.append(contentsOf: legacy.warnings)
        } else {
            checks.append("legacy: skipped")
        }

        // ---- Stage 3g: plugin directories.
        var plugins = PluginDirectoryScanner.Result()
        if options.scanPlugins {
            plugins = PluginDirectoryScanner(runner: env.runner, fileManager: env.fileManager, home: env.home).scan()
            checks.append(contentsOf: plugins.checks)
            warnings.append(contentsOf: plugins.warnings)
        } else {
            checks.append("plugin directories: skipped")
        }

        // ---- Stage 3h: shell startup files. File reads only.
        var shell = ShellStartupScanner.Result()
        if options.scanShell {
            // --user-only keeps the scan inside $HOME: no /etc files, no paths.d.
            shell = options.includeSystem
                ? ShellStartupScanner(fileManager: env.fileManager, home: env.home).scan()
                : ShellStartupScanner(fileManager: env.fileManager, home: env.home, systemFiles: [], pathsDirectories: []).scan()
            checks.append(contentsOf: shell.checks)
            warnings.append(contentsOf: shell.warnings)
        } else {
            checks.append("shell startup: skipped")
        }

        // ---- Stage 3i: network — listening sockets + firewall rules. Contribute items.
        var network = NetworkScanner.Result()
        if options.scanNetwork {
            network = NetworkScanner(runner: env.runner).scan()
            checks.append(contentsOf: network.checks)
            warnings.append(contentsOf: network.warnings)
            incomplete.append(contentsOf: network.failed)
        } else {
            checks.append("network: skipped")
        }
        if !incomplete.isEmpty {
            warnings.append("inventory incomplete (\(incomplete.joined(separator: ", "))) — display "
                + "ids are positional per scan and will not match a complete run: address "
                + "entries by label, not by number, until the scan is complete")
        }

        // ---- Stage 4: correlation.
        let correlator = ItemCorrelator(fileManager: env.fileManager, home: env.home)
        let (items, uncorrelated) = correlator.correlate(ItemCorrelator.Input(
            jobs: jobs, launchd: launchd, btm: btm, disabled: disabled, uid: env.uid,
            extensions: extensions, systemExtensions: systemExtensions, kexts: kexts, helpers: helpers,
            scheduled: scheduled, legacy: legacy, plugins: plugins.plugins, shell: shell.files, network: network))

        // ---- Stage 5: signatures (enrichment).
        var enriched = items
        if options.scanSignatures {
            let signatures = SignatureScanner()
            for index in enriched.indices {
                // Bundles (system extensions, kexts) are signed as a whole:
                // codesign takes the bundle path.
                let item = enriched[index]
                let bundleTypes: Set<ItemType> = [.systemExtension, .kernelExtension, .plugin]
                let bundle = bundleTypes.contains(item.type) ? item.path : nil
                guard let exec = item.executable ?? bundle, !exec.isEmpty else { continue }
                let record = signatures.status(for: exec, runner: env.runner)
                enriched[index].codeSignatureStatus = record.status
                if let id = record.identifier { enriched[index].metadata["signature-identifier"] = id }
                if let team = record.teamIdentifier { enriched[index].metadata["signature-team"] = team }
                if let authority = record.authority0 { enriched[index].metadata["signature-authority"] = authority }
                enriched[index].sources.append(SourceEvidence(
                    kind: .signature, detail: "\(record.status): \(record.path)", confidence: .high))
            }
        }

        // ---- Stage 6: analysis.
        var analyzed = enriched
        // App context BEFORE orphan detection: the resolver's
        // app-gone-confirmed flag is what OrphanDetector rule 4 consumes.
        // Read-only (file probes + mdfind), degrades to "unknown" when the
        // Spotlight index is unavailable.
        var appResolver = AppContextResolver(fileManager: env.fileManager, runner: env.runner)
        appResolver.apply(to: &analyzed)
        let withParentApp = analyzed.filter { $0.parentApplication != nil }.count
        if withParentApp > 0 || !appResolver.spotlightQueries.isEmpty {
            let spotlightState: String
            switch appResolver.spotlightAvailable {
            case .some(true): spotlightState = "ok"
            case .some(false): spotlightState = "UNAVAILABLE (queries degraded to unknown)"
            case nil: spotlightState = "not needed"
            }
            checks.append("app context: \(withParentApp) items with parent app, "
                + "\(appResolver.spotlightQueries.count) Spotlight lookups (\(spotlightState))")
        }
        OrphanDetector(fileManager: env.fileManager).apply(to: &analyzed)
        RiskAnalyzer(fileManager: env.fileManager).apply(to: &analyzed)
        // V0.5: control matrix + provenance, after orphan detection (both read it).
        ControlAnalyzer(fileManager: env.fileManager,
                        launchDirs: BackupEnvironment(fileManager: env.fileManager, home: env.home).launchDirs)
            .apply(to: &analyzed)
        // ---- Stage 6b: package receipts (V0.6). Enrichment: a failed
        // pkgutil leaves provenance at what the paths say.
        var receiptIndex: ReceiptIndex?
        if options.scanReceipts {
            let receipts = ReceiptScanner(runner: env.runner).scan()
            checks.append(contentsOf: receipts.checks)
            warnings.append(contentsOf: receipts.warnings)
            if !receipts.failed { receiptIndex = receipts.index }
        } else {
            checks.append("pkgutil: skipped")
        }
        ProvenanceResolver(fileManager: env.fileManager, receipts: receiptIndex).apply(to: &analyzed)

        let orphanCount = analyzed.filter { $0.orphaned }.count
        checks.append("\(analyzed.count) items, \(orphanCount) orphaned, "
            + "\(uncorrelated.count) BTM entries uncorrelated")

        var report = ScanReport(items: analyzed, uncorrelated: uncorrelated,
                          warnings: warnings, checks: checks, incompleteLayers: incomplete,
                          btmContainers: containers)
        report.receiptIndex = receiptIndex
        return report
    }
}
