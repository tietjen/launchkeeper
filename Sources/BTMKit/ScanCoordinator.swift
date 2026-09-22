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
    public init(includeUser: Bool = true, includeSystem: Bool = true,
                scanBTM: Bool = true, scanSignatures: Bool = true) {
        self.includeUser = includeUser
        self.includeSystem = includeSystem
        self.scanBTM = scanBTM
        self.scanSignatures = scanSignatures
    }
}

public struct ScanReport {
    public var items: [BackgroundItem]
    public var uncorrelated: [String]
    public var warnings: [String]
    /// Environment/self-check lines for `btmctl doctor`.
    public var checks: [String]
    /// Sources that contribute ITEMS and did not answer in this run
    /// (`launchctl print <domain>`, `sfltool dumpbtm`). Display ids are
    /// positional, so a run missing one of these numbers the inventory
    /// differently from a complete run — numeric addressing is unsafe then
    /// (V0.4.5). Sources that only enrich (print-disabled, codesign, mdfind)
    /// are not listed: they never change the item set.
    public var incompleteLayers: [String]
    public init(items: [BackgroundItem], uncorrelated: [String],
                warnings: [String], checks: [String] = [], incompleteLayers: [String] = []) {
        self.items = items; self.uncorrelated = uncorrelated
        self.warnings = warnings; self.checks = checks
        self.incompleteLayers = incompleteLayers
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
        if options.scanBTM {
            // One attempt, no blind retry: sfltool either answers within seconds
            // or is stuck — cold start after an OS upgrade, sandbox, permissions.
            // A blind second attempt only doubles the dead wait; the warning
            // names the causes and the user decides. Budget: BTMCTL_BTM_TIMEOUT.
            let budget = ProcessInfo.processInfo.environment["BTMCTL_BTM_TIMEOUT"]
                .flatMap { Double($0) } ?? 45
            let result = env.runner.run(command: "/usr/bin/sfltool",
                                        arguments: ["dumpbtm"], timeout: budget)
            if result.exitCode == 0 {
                let (records, parseWarnings) = BTMDumpParser.parse(result.stdout)
                btm = records
                checks.append("sfltool dumpbtm: ok (\(records.count) records)")
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
                    + "BTM layer not scanned. Typical causes: first run after a macOS "
                    + "upgrade (the BTM daemon is migrating its store — simply run "
                    + "again) or a blocked call (sandbox/permissions). Check with "
                    + "`sfltool dumpbtm` yourself; raise the budget with "
                    + "BTMCTL_BTM_TIMEOUT=<seconds>")
                checks.append("sfltool dumpbtm: FAILED (timeout \(Int(budget))s)")
                incomplete.append("sfltool dumpbtm")
            } else {
                warnings.append("sfltool dumpbtm failed (exit \(result.exitCode)) — "
                    + "BTM layer not scanned")
                checks.append("sfltool dumpbtm: FAILED (exit \(result.exitCode))")
                incomplete.append("sfltool dumpbtm")
            }
            if !incomplete.isEmpty {
                warnings.append("inventory incomplete (\(incomplete.joined(separator: ", "))) — display "
                    + "ids are positional per scan and will not match a complete run: address "
                    + "entries by label, not by number, until the scan is complete")
            }
        } else {
            checks.append("sfltool dumpbtm: skipped")
        }

        // ---- Stage 4: correlation.
        let correlator = ItemCorrelator(fileManager: env.fileManager)
        let (items, uncorrelated) = correlator.correlate(ItemCorrelator.Input(
            jobs: jobs, launchd: launchd, btm: btm, disabled: disabled, uid: env.uid))

        // ---- Stage 5: signatures (enrichment).
        var enriched = items
        if options.scanSignatures {
            let signatures = SignatureScanner()
            for index in enriched.indices {
                guard let exec = enriched[index].executable, !exec.isEmpty else { continue }
                let record = signatures.status(for: exec, runner: env.runner)
                enriched[index].codeSignatureStatus = record.status
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

        let orphanCount = analyzed.filter { $0.orphaned }.count
        checks.append("\(analyzed.count) items, \(orphanCount) orphaned, "
            + "\(uncorrelated.count) BTM entries uncorrelated")

        return ScanReport(items: analyzed, uncorrelated: uncorrelated,
                          warnings: warnings, checks: checks, incompleteLayers: incomplete)
    }
}
