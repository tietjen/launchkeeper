import Foundation

// V0.8 orchestration: gate → analysis → plan → (dry-run | quarantine +
// execute + verify) → audit. Same promises as every write path since V0.2:
// dry-run by default, argv only (`--` before every path), sudo only through
// the interactive seam, success only when a re-read of the disk agrees.

public struct CleanupEnvironment {
    public var runner: CommandRunner
    public var disk: DiskView
    public var home: String
    public var quarantineRoot: String
    /// Logical directory of the receipts database.
    public var receiptsDirectory: String
    public var interactiveTimeout: TimeInterval
    /// `purge` of a big tree can take a while.
    public var purgeTimeout: TimeInterval

    public init(runner: CommandRunner = SystemCommandRunner(), disk: DiskView = DiskView(),
                home: String = NSHomeDirectory(), quarantineRoot: String? = nil,
                receiptsDirectory: String = "/var/db/receipts",
                interactiveTimeout: TimeInterval = 180, purgeTimeout: TimeInterval = 1800) {
        self.runner = runner
        self.disk = disk
        self.home = home
        self.quarantineRoot = quarantineRoot ?? LaunchKeeperPaths.quarantine(home: home)
        self.receiptsDirectory = receiptsDirectory
        self.interactiveTimeout = interactiveTimeout
        self.purgeTimeout = purgeTimeout
    }
}

public struct CleanupResult {
    public var operation: String
    public var target: String
    public var status: RemediationStatus
    public var messages: [String]
    public var plan: [PlannedCommand]
    public var executed: [String]
    public var analysis: UninstallAnalysis?
    public var quarantine: String?
    public var undoHint: String?

    public var auditStatus: String {
        switch status {
        case .planned: return "planned"
        case .appliedOk: return "applied-ok"
        case .appliedFailed(let detail): return "applied-fail(\(detail))"
        case .refused(let reason): return "refused(\(reason))"
        }
    }
}

public struct CleanupEngine {
    public var environment: CleanupEnvironment
    public var audit: AuditLog

    public init(environment: CleanupEnvironment = CleanupEnvironment(), audit: AuditLog? = nil) {
        self.environment = environment
        self.audit = audit ?? AuditLog(directory: LaunchKeeperPaths.logs(home: environment.home))
    }

    public var store: QuarantineStore {
        QuarantineStore(root: environment.quarantineRoot, fileManager: environment.disk.fileManager)
    }

    /// Arguments per `mv` — far below ARG_MAX even with long bundle paths.
    static let batchSize = 200

    // MARK: - gate

    /// Exact package identifiers only (decision 2026-09-22): no fragments,
    /// no display ids — the receipt is addressed by the name pkgutil knows.
    public static func evaluatePackage(_ identifier: String) -> GateDecision {
        guard !identifier.isEmpty, !identifier.hasPrefix("-"), !identifier.hasPrefix("."),
              !identifier.contains("/"), !identifier.contains(where: { $0.isWhitespace }) else {
            return .denied(reason: "'\(identifier)' is not a package identifier — use the exact id from "
                + "`launchkeeper receipts`")
        }
        if identifier.hasPrefix("com.apple.") {
            return .denied(reason: "Apple package (com.apple.*) — never uninstalled by policy")
        }
        return .allowed
    }

    // MARK: - uninstall

    /// `verifyAsRoot`: prove root-only files with `sudo -n cksum` (one
    /// `sudo -v` prompt first). --apply always does it, so a dry-run with
    /// this flag shows exactly what --apply will move.
    public func uninstall(packageIdentifier id: String, apply: Bool, verifyAsRoot: Bool = false) -> CleanupResult {
        let target = "pkg:" + id
        func finish(_ status: RemediationStatus, _ messages: [String], plan: [PlannedCommand] = [],
                    executed: [String] = [], analysis: UninstallAnalysis? = nil, quarantine: String? = nil,
                    undo: String? = nil) -> CleanupResult {
            let result = CleanupResult(operation: "uninstall", target: target, status: status, messages: messages,
                                       plan: plan, executed: executed, analysis: analysis,
                                       quarantine: quarantine, undoHint: undo)
            audit.append(operation: "uninstall", target: target + (quarantine.map { " → \($0)" } ?? ""),
                         status: result.auditStatus)
            return result
        }
        if case .denied(let reason) = Self.evaluatePackage(id) {
            return finish(.refused(reason), ["refused: \(reason)", "this is a hard gate — no flag bypasses it"])
        }
        let runner = environment.runner
        let infoRun = runner.run(command: "/usr/sbin/pkgutil", arguments: ["--pkg-info-plist", id], timeout: 20)
        guard infoRun.exitCode == 0, let info = ReceiptInfoParser.parse(infoRun.stdout) else {
            return finish(.refused("no such package receipt"),
                          ["refused: no receipt '\(id)' — exact ids: `launchkeeper receipts --all`"])
        }
        guard info.volume == "/" else {
            return finish(.refused("receipt for another volume (\(info.volume))"),
                          ["refused: only packages installed on / are uninstalled"])
        }
        let bomPath = environment.receiptsDirectory + "/" + id + ".bom"
        let bomRun = runner.run(command: "/usr/bin/lsbom", arguments: [environment.disk.disk(bomPath)], timeout: 60)
        guard bomRun.exitCode == 0 else {
            return finish(.refused("bill of materials unreadable"),
                          ["refused: lsbom \(bomPath) failed (exit \(bomRun.exitCode)) — without the BOM "
                           + "nothing can be proven unchanged"])
        }
        let (bom, bomWarnings) = BOMParser.parse(bomRun.stdout)
        let receipts = ReceiptScanner(runner: runner).scan()
        guard !receipts.failed else {
            return finish(.refused("receipt index unavailable"),
                          ["refused: pkgutil could not index the other receipts — shared paths cannot be told apart"])
        }
        let claims = ClaimCache(runner: runner)
        func analyze(_ checksums: [String: UInt32]) -> UninstallAnalysis {
            PackageUninstallAnalyzer.analyze(packageIdentifier: id, version: info.version, volume: info.volume,
                                             location: info.location, bom: bom, index: receipts.index,
                                             disk: environment.disk, claimants: claims.claimants,
                                             rootChecksums: checksums)
        }
        var analysis = analyze([:])
        var rootNotes: [String] = []
        let unreadable = analysis.paths.filter { $0.status == .unreadable }.map(\.path)
        if !unreadable.isEmpty {
            if apply || verifyAsRoot {
                switch rootChecksums(unreadable) {
                case .success(let sums):
                    analysis = analyze(sums)
                    rootNotes.append("verified as root: \(sums.count) of \(unreadable.count) root-only file(s)")
                case .failure(let refusal):
                    return finish(.refused(refusal.reason), ["refused: \(refusal.reason) — nothing moved"],
                                  analysis: analysis)
                }
            } else {
                rootNotes.append("\(unreadable.count) root-only file(s) unproven and staying — "
                    + "--verify-as-root proves them now (sudo), --apply always does")
            }
        }
        var messages = bomWarnings.prefix(5).map { "warning: \($0)" } + analysis.warnings.map { "warning: \($0)" }
            + rootNotes
        if !analysis.canForget {
            messages.append("receipt stays: " + analysis.forgetBlockers.joined(separator: "; "))
        }
        guard !analysis.moveRoots.isEmpty || analysis.canForget else {
            return finish(.refused("nothing to uninstall"),
                          messages + ["refused: nothing of '\(id)' can be moved and the receipt must stay"],
                          analysis: analysis)
        }

        // The plan uses the quarantine name it WILL have; dry-run shows it.
        let name = store.makeName(kind: "uninstall", subject: id)
        let plan = uninstallPlan(analysis: analysis, quarantine: name)
        guard apply else {
            messages.append("dry-run: nothing moved (add --apply). Moves go to the quarantine, "
                + "restorable with `launchkeeper quarantine restore`")
            return finish(.planned, messages, plan: plan, analysis: analysis)
        }

        // --apply: manifest + receipt copies BEFORE the first move.
        let fm = environment.disk.fileManager
        var manifest = QuarantineManifest(
            name: name, kind: "uninstall", createdAt: ISO8601DateFormatter().string(from: Date()),
            toolVersion: QuarantineStore.toolVersion, packageIdentifier: id, version: info.version,
            moves: analysis.moveRoots.map { root in
                QuarantineMove(original: root, quarantined: store.quarantinedPath(name, original: root),
                               kind: analysis.paths.first(where: { $0.path == root })?.kind.rawValue ?? "other")
            },
            receiptCopies: [], forgot: false, status: "planned", notes: messages)
        if let failure = store.write(manifest) {
            return finish(.refused(failure.reason), ["refused: \(failure.reason) — nothing moved"])
        }
        if analysis.canForget {
            let receiptDir = store.directory(name) + "/receipt"
            do {
                try fm.createDirectory(atPath: receiptDir, withIntermediateDirectories: true)
                for suffix in [".bom", ".plist"] {
                    let source = environment.disk.disk(environment.receiptsDirectory + "/" + id + suffix)
                    let copy = receiptDir + "/" + id + suffix
                    try fm.copyItem(atPath: source, toPath: copy)
                    guard fm.contents(atPath: copy) == fm.contents(atPath: source) else {
                        throw ControlRefusal("receipt copy differs")
                    }
                    manifest.receiptCopies.append(copy)
                }
            } catch {
                return finish(.refused("cannot save the receipt"),
                              ["refused: could not copy the receipt into the quarantine (\(error)) — nothing moved"],
                              quarantine: name)
            }
            _ = store.write(manifest)
        }
        audit.append(operation: "quarantine", target: name, status: "created")

        let (executed, failure) = run(plan, timeout: environment.interactiveTimeout)
        var problems = failure.map { [$0] } ?? []
        for move in manifest.moves {
            if environment.disk.exists(move.original) { problems.append("still in place: \(move.original)") }
            if (try? fm.attributesOfItem(atPath: move.quarantined)) == nil {
                problems.append("not in the quarantine: \(move.quarantined)")
            }
        }
        if analysis.canForget, failure == nil {
            let check = runner.run(command: "/usr/sbin/pkgutil", arguments: ["--pkg-info", id], timeout: 20)
            if check.exitCode == 0 { problems.append("pkgutil still knows '\(id)'") } else { manifest.forgot = true }
        }
        let undo = "launchkeeper quarantine restore \(name)"
        if problems.isEmpty {
            manifest.status = "applied-ok"
            _ = store.write(manifest)
            messages.append("verified: \(manifest.moves.count) path(s) in the quarantine, gone from their place"
                + (manifest.forgot ? "; receipt forgotten (copy kept)" : ""))
            return finish(.appliedOk, messages, plan: plan, executed: executed, analysis: analysis,
                          quarantine: name, undo: undo)
        }
        manifest.status = "applied-fail(\(problems.count))"
        manifest.notes += problems
        _ = store.write(manifest)
        return finish(.appliedFailed(problems.first!), messages + problems, plan: plan, executed: executed,
                      analysis: analysis, quarantine: name, undo: undo)
    }

    /// Root-only files: one interactive `sudo -v`, then `sudo -n cksum` in
    /// batches (non-interactive, output captured). Paths from the BOM only.
    func rootChecksums(_ paths: [String]) -> Result<[String: UInt32], ControlRefusal> {
        let runner = environment.runner
        guard runner.runInteractive(command: "/usr/bin/sudo", arguments: ["-v"],
                                    timeout: environment.interactiveTimeout) == 0 else {
            return .failure(ControlRefusal("sudo authentication failed — root-only files cannot be proven"))
        }
        var sums: [String: UInt32] = [:]
        let byDisk = Dictionary(uniqueKeysWithValues: paths.map { (environment.disk.disk($0), $0) })
        let diskPaths = byDisk.keys.sorted()
        for start in stride(from: 0, to: diskPaths.count, by: Self.batchSize) {
            let batch = Array(diskPaths[start..<min(start + Self.batchSize, diskPaths.count)])
            let result = runner.run(command: "/usr/bin/sudo", arguments: ["-n", "/usr/bin/cksum", "--"] + batch,
                                    timeout: 120)
            // "<crc> <size> <path>" — the path may contain spaces.
            for line in result.stdout.components(separatedBy: "\n") {
                let parts = line.split(separator: " ", maxSplits: 2, omittingEmptySubsequences: false)
                guard parts.count == 3, let crc = UInt32(parts[0]), let logical = byDisk[String(parts[2])] else { continue }
                sums[logical] = crc
            }
        }
        return .success(sums)
    }

    /// `sudo mkdir -p` the parent inside the quarantine, then `sudo mv` the
    /// roots that share it — one pair per parent, batched. Paths come from
    /// the BOM and the analysis, never from the user; `--` guards them.
    func uninstallPlan(analysis: UninstallAnalysis, quarantine name: String) -> [PlannedCommand] {
        var plan: [PlannedCommand] = []
        let byParent = Dictionary(grouping: analysis.moveRoots) { ($0 as NSString).deletingLastPathComponent }
        for parent in byParent.keys.sorted() {
            let destination = store.quarantinedPath(name, original: parent)
            plan.append(PlannedCommand(command: "/usr/bin/sudo", arguments: ["/bin/mkdir", "-p", "--", destination],
                                       description: "quarantine directory for \(parent)"))
            let roots = byParent[parent]!.sorted()
            for start in stride(from: 0, to: roots.count, by: Self.batchSize) {
                let batch = roots[start..<min(start + Self.batchSize, roots.count)]
                plan.append(PlannedCommand(command: "/usr/bin/sudo",
                    arguments: ["/bin/mv", "--"] + batch.map { environment.disk.disk($0) } + [destination + "/"],
                    description: "move \(batch.count) item(s) from \(parent) into the quarantine"))
            }
        }
        if analysis.canForget {
            plan.append(PlannedCommand(command: "/usr/bin/sudo",
                                       arguments: ["/usr/sbin/pkgutil", "--forget", analysis.packageIdentifier],
                                       description: "forget the receipt (a copy of .bom/.plist is kept in the quarantine)"))
        }
        return plan
    }

    // MARK: - leftover items (V0.8.1)

    /// `remove` for a provable leftover file (gate already passed): re-check
    /// it on disk, ask every receipt whether Apple claims it, then move it
    /// into the quarantine — one `sudo mkdir -p` + one `sudo mv`.
    public func quarantineItem(_ item: BackgroundItem, apply: Bool) -> CleanupResult {
        func result(_ status: RemediationStatus, _ messages: [String], plan: [PlannedCommand] = [],
                    executed: [String] = [], quarantine: String? = nil, undo: String? = nil) -> CleanupResult {
            CleanupResult(operation: "remove", target: "file:" + (item.path ?? item.key), status: status,
                          messages: messages, plan: plan, executed: executed, analysis: nil,
                          quarantine: quarantine, undoHint: undo)
        }
        guard let path = item.path else { return result(.refused("no path"), ["refused: no path to move"]) }
        let disk = environment.disk
        let expected: FileAttributeType = item.type == .startupItem ? .typeDirectory : .typeRegular
        guard let type = disk.type(path) else {
            return result(.refused("not on disk anymore"), ["refused: \(path) is not on disk anymore"])
        }
        guard type == expected else {
            return result(.refused("unexpected file type"),
                          ["refused: \(path) is a \(type.rawValue), expected \(expected.rawValue) — never followed"])
        }
        let claims = ClaimCache(runner: environment.runner).claimants(path)
        if let apple = claims.first(where: { $0.hasPrefix("com.apple.") }) {
            return result(.refused("claimed by Apple (\(apple))"), ["refused: an Apple receipt lists \(path)"])
        }
        var messages: [String] = []
        if let owner = claims.sorted().first {
            messages.append("note: receipt \(owner) lists this file — `launchkeeper uninstall \(owner)` "
                + "would take the rest of that package as well")
        }
        // paths.d: every entry must still be gone NOW, not only at scan time.
        if item.type == .pathEntry {
            let text = (disk.fileManager.contents(atPath: disk.disk(path))).map { String(decoding: $0, as: UTF8.self) } ?? ""
            let entries = text.components(separatedBy: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
                .filter { !$0.isEmpty && !$0.hasPrefix("#") }
            let alive = entries.filter { disk.exists($0) }
            guard !entries.isEmpty, alive.isEmpty else {
                return result(.refused("a PATH entry exists"),
                              ["refused: \(alive.first ?? "an entry") exists — only a file whose every entry is gone is a leftover"])
            }
        }

        let name = store.makeName(kind: "remove", subject: (path as NSString).lastPathComponent)
        let parent = (path as NSString).deletingLastPathComponent
        let destination = store.quarantinedPath(name, original: parent)
        let plan = [
            PlannedCommand(command: "/usr/bin/sudo", arguments: ["/bin/mkdir", "-p", "--", destination],
                           description: "quarantine directory for \(parent)"),
            PlannedCommand(command: "/usr/bin/sudo", arguments: ["/bin/mv", "--", disk.disk(path), destination + "/"],
                           description: "move the leftover into the quarantine (restorable)"),
        ]
        guard apply else {
            return result(.planned, messages + ["dry-run: nothing moved (add --apply)"], plan: plan,
                          undo: "launchkeeper quarantine restore <the new quarantine entry>")
        }
        var manifest = QuarantineManifest(
            name: name, kind: "remove", createdAt: ISO8601DateFormatter().string(from: Date()),
            toolVersion: QuarantineStore.toolVersion, packageIdentifier: nil, version: nil,
            moves: [QuarantineMove(original: path, quarantined: store.quarantinedPath(name, original: path),
                                   kind: item.type.rawValue)],
            receiptCopies: [], forgot: false, status: "planned", notes: [item.key] + item.orphanReasons)
        if let failure = store.write(manifest) {
            return result(.refused(failure.reason), ["refused: \(failure.reason) — nothing moved"])
        }
        audit.append(operation: "quarantine", target: name, status: "created")
        let (executed, failure) = run(plan, timeout: environment.interactiveTimeout)
        var problems = failure.map { [$0] } ?? []
        if disk.exists(path) { problems.append("still in place: \(path)") }
        if (try? disk.fileManager.attributesOfItem(atPath: manifest.moves[0].quarantined)) == nil {
            problems.append("not in the quarantine: \(manifest.moves[0].quarantined)")
        }
        let undo = "launchkeeper quarantine restore \(name)"
        manifest.status = problems.isEmpty ? "applied-ok" : "applied-fail(\(problems.count))"
        _ = store.write(manifest)
        guard problems.isEmpty else {
            return result(.appliedFailed(problems[0]), messages + problems, plan: plan, executed: executed,
                          quarantine: name, undo: undo)
        }
        return result(.appliedOk, messages + ["verified: \(path) is in the quarantine (\(name))"], plan: plan,
                      executed: executed, quarantine: name, undo: undo)
    }

    // MARK: - app leftovers (V0.8.2)

    public func leftoverScanner() -> AppLeftoverScanner {
        AppLeftoverScanner(disk: environment.disk, home: environment.home)
    }

    /// `leftovers <bundle-id>`: re-scan that one id NOW, require the gone
    /// verdict of all sources, then move every leftover path into the
    /// quarantine — as the user for ~/Library, via sudo for /Library.
    public func removeAppLeftovers(bundleIdentifier id: String, sources: AppPresenceSources,
                                   apply: Bool) -> CleanupResult {
        let target = "app:" + id
        func finish(_ status: RemediationStatus, _ messages: [String], plan: [PlannedCommand] = [],
                    executed: [String] = [], quarantine: String? = nil, undo: String? = nil) -> CleanupResult {
            let result = CleanupResult(operation: "leftovers", target: target, status: status, messages: messages,
                                       plan: plan, executed: executed, analysis: nil, quarantine: quarantine,
                                       undoHint: undo)
            audit.append(operation: "leftovers", target: target + (quarantine.map { " → \($0)" } ?? ""),
                         status: result.auditStatus)
            return result
        }
        guard AppLeftoverLocations.isBundleIdentifier(id), !AppLeftoverLocations.isExcluded(id) else {
            return finish(.refused("not a bundle identifier"),
                          ["refused: '\(id)' is not a (non-Apple) bundle identifier — exact ids: `launchkeeper leftovers`"])
        }
        let scanner = leftoverScanner()
        let paths = scanner.candidates()[id] ?? []
        guard !paths.isEmpty else {
            return finish(.refused("no leftovers"), ["refused: nothing named '\(id)' in the leftover locations"])
        }
        let candidate = scanner.verdict(id, paths: paths, sources: sources)
        switch candidate.presence {
        case .noAppEvidence:
            return finish(.refused("no sign it was an app"),
                          ["refused: no app found — but nothing shows '\(id)' ever was one (no container, saved "
                           + "state, WebKit data or app preferences); a tool's or framework's data stays"])
        case .present(let why):
            return finish(.refused("app present (\(why))"),
                          ["refused: the app is not gone — \(why). Leftovers of installed apps are their data"])
        case .unknown(let why):
            return finish(.refused("presence unknown"), ["refused: \(why)"])
        case .gone(let proofs):
            var messages = ["app gone: " + proofs.joined(separator: "; "),
                            "was an app: " + candidate.appEvidence.joined(separator: ", ")]
            let total = paths.reduce(UInt64(0)) { $0 + $1.bytes }
            messages.append("\(paths.count) path(s), \(ByteCountFormatter.string(fromByteCount: Int64(total), countStyle: .file))")
            let name = store.makeName(kind: "leftovers", subject: id)
            var plan: [PlannedCommand] = []
            for path in paths {
                let parent = (path.path as NSString).deletingLastPathComponent
                let destination = store.quarantinedPath(name, original: parent)
                let mkdir = ["/bin/mkdir", "-p", "--", destination]
                let mv = ["/bin/mv", "--", environment.disk.disk(path.path), destination + "/"]
                if path.needsRoot {
                    plan.append(PlannedCommand(command: "/usr/bin/sudo", arguments: mkdir, description: "quarantine directory"))
                    plan.append(PlannedCommand(command: "/usr/bin/sudo", arguments: mv,
                                               description: "move \(path.kind) (\(path.bytes) bytes) — via sudo"))
                } else {
                    plan.append(PlannedCommand(command: mkdir[0], arguments: Array(mkdir.dropFirst()),
                                               description: "quarantine directory"))
                    plan.append(PlannedCommand(command: mv[0], arguments: Array(mv.dropFirst()),
                                               description: "move \(path.kind) (\(path.bytes) bytes)"))
                }
            }
            guard apply else {
                return finish(.planned, messages + ["dry-run: nothing moved (add --apply)"], plan: plan)
            }
            var manifest = QuarantineManifest(
                name: name, kind: "app-leftovers", createdAt: ISO8601DateFormatter().string(from: Date()),
                toolVersion: QuarantineStore.toolVersion, packageIdentifier: nil, version: nil,
                moves: paths.map { QuarantineMove(original: $0.path,
                                                  quarantined: store.quarantinedPath(name, original: $0.path),
                                                  kind: $0.kind) },
                receiptCopies: [], forgot: false, status: "planned", notes: [id] + proofs)
            if let failure = store.write(manifest) {
                return finish(.refused(failure.reason), ["refused: \(failure.reason) — nothing moved"])
            }
            audit.append(operation: "quarantine", target: name, status: "created")
            let (executed, failure) = run(plan, timeout: environment.interactiveTimeout)
            var problems = failure.map { [$0] } ?? []
            for move in manifest.moves {
                if environment.disk.exists(move.original) { problems.append("still in place: \(move.original)") }
                if (try? environment.disk.fileManager.attributesOfItem(atPath: move.quarantined)) == nil {
                    problems.append("not in the quarantine: \(move.original)")
                }
            }
            let undo = "launchkeeper quarantine restore \(name)"
            manifest.status = problems.isEmpty ? "applied-ok" : "applied-fail(\(problems.count))"
            _ = store.write(manifest)
            guard problems.isEmpty else {
                return finish(.appliedFailed(problems[0]), messages + problems
                              + ["containers of other apps may need App Data / Full Disk Access for your terminal"],
                              plan: plan, executed: executed, quarantine: name, undo: undo)
            }
            return finish(.appliedOk, messages + ["verified: \(paths.count) path(s) in the quarantine"], plan: plan,
                          executed: executed, quarantine: name, undo: undo)
        }
    }

    // MARK: - restore

    public func restore(name: String, apply: Bool) -> CleanupResult {
        let target = "quarantine:" + name
        func finish(_ status: RemediationStatus, _ messages: [String], plan: [PlannedCommand] = [],
                    executed: [String] = []) -> CleanupResult {
            let result = CleanupResult(operation: "quarantine-restore", target: target, status: status,
                                       messages: messages, plan: plan, executed: executed, analysis: nil,
                                       quarantine: name, undoHint: nil)
            audit.append(operation: "quarantine-restore", target: name, status: result.auditStatus)
            return result
        }
        guard var manifest = store.load(name) else {
            return finish(.refused("no such quarantine"), ["refused: no quarantine '\(name)' — see `launchkeeper quarantine list`"])
        }
        let fm = environment.disk.fileManager
        var plan: [PlannedCommand] = []
        var messages: [String] = []
        var restoring: [QuarantineMove] = []
        for move in manifest.moves {
            let inQuarantine = (try? fm.attributesOfItem(atPath: move.quarantined)) != nil
            if !inQuarantine { messages.append("skipped (not in the quarantine): \(move.original)"); continue }
            if environment.disk.exists(move.original) {
                messages.append("skipped (something is at the original place again — never overwritten): \(move.original)")
                continue
            }
            let parent = (move.original as NSString).deletingLastPathComponent
            if !environment.disk.exists(parent) {
                plan.append(PlannedCommand(command: "/usr/bin/sudo",
                                           arguments: ["/bin/mkdir", "-p", "--", environment.disk.disk(parent)],
                                           description: "recreate \(parent)"))
            }
            plan.append(PlannedCommand(command: "/usr/bin/sudo",
                                       arguments: ["/bin/mv", "--", move.quarantined, environment.disk.disk(move.original)],
                                       description: "move back to \(move.original)"))
            restoring.append(move)
        }
        var receiptBack = false
        if manifest.forgot, let id = manifest.packageIdentifier {
            let known = environment.runner.run(command: "/usr/sbin/pkgutil", arguments: ["--pkg-info", id], timeout: 20)
            if known.exitCode != 0 {
                for copy in manifest.receiptCopies {
                    let destination = environment.disk.disk(environment.receiptsDirectory + "/"
                                                            + (copy as NSString).lastPathComponent)
                    plan.append(PlannedCommand(command: "/usr/bin/sudo", arguments: ["/bin/cp", "-p", "--", copy, destination],
                                               description: "put the receipt back"))
                }
                receiptBack = true
            }
        }
        guard !plan.isEmpty else {
            return finish(.refused("nothing to restore"), messages + ["refused: nothing left to move back"])
        }
        guard apply else {
            return finish(.planned, messages + ["dry-run: nothing moved (add --apply)"], plan: plan)
        }
        let (executed, failure) = run(plan, timeout: environment.interactiveTimeout)
        var problems = failure.map { [$0] } ?? []
        for move in restoring {
            if !environment.disk.exists(move.original) { problems.append("not back: \(move.original)") }
            if (try? fm.attributesOfItem(atPath: move.quarantined)) != nil { problems.append("still quarantined: \(move.original)") }
        }
        if receiptBack, let id = manifest.packageIdentifier,
           environment.runner.run(command: "/usr/sbin/pkgutil", arguments: ["--pkg-info", id], timeout: 20).exitCode != 0 {
            problems.append("pkgutil does not know '\(id)' again")
        }
        if problems.isEmpty {
            manifest.status = "restored"
            if receiptBack { manifest.forgot = false }
            _ = store.write(manifest)
            return finish(.appliedOk, messages + ["verified: \(restoring.count) path(s) back in place"
                                                  + (receiptBack ? ", receipt known again" : "")],
                          plan: plan, executed: executed)
        }
        manifest.status = "restore-fail(\(problems.count))"
        _ = store.write(manifest)
        return finish(.appliedFailed(problems.first!), messages + problems, plan: plan, executed: executed)
    }

    // MARK: - purge (the one real deletion)

    public func purge(name: String, apply: Bool) -> CleanupResult {
        let target = "quarantine:" + name
        func finish(_ status: RemediationStatus, _ messages: [String], plan: [PlannedCommand] = [],
                    executed: [String] = []) -> CleanupResult {
            let result = CleanupResult(operation: "quarantine-purge", target: target, status: status,
                                       messages: messages, plan: plan, executed: executed, analysis: nil,
                                       quarantine: name, undoHint: nil)
            audit.append(operation: "quarantine-purge", target: name, status: result.auditStatus)
            return result
        }
        guard QuarantineStore.isValidName(name), let manifest = store.load(name) else {
            return finish(.refused("no such quarantine"), ["refused: no quarantine '\(name)' — see `launchkeeper quarantine list`"])
        }
        let fm = environment.disk.fileManager
        let directory = store.directory(name)
        // The target must be a direct child of the quarantine root, after
        // resolving links on both sides — `rm -rf` never leaves this box.
        let canonicalRoot = PathUtils.canonicalize(environment.quarantineRoot, fileManager: fm)
        let canonicalDir = PathUtils.canonicalize(directory, fileManager: fm)
        guard (canonicalDir as NSString).deletingLastPathComponent == canonicalRoot,
              (try? fm.attributesOfItem(atPath: directory))?[.type] as? FileAttributeType == .typeDirectory else {
            return finish(.refused("quarantine path escapes its root"), ["refused: \(directory) is not a quarantine entry"])
        }
        let plan = [PlannedCommand(command: "/usr/bin/sudo", arguments: ["/bin/rm", "-rf", "--", directory],
                                   description: "delete the quarantine entry for good — NOT restorable")]
        var messages = ["\(manifest.moves.count) path(s) of \(manifest.packageIdentifier ?? manifest.kind) "
                        + "(\(manifest.status)) would be deleted for good"]
        if manifest.status == "planned" || manifest.status.hasPrefix("applied-fail") {
            messages.append("warning: this entry did not complete (\(manifest.status)) — check `quarantine restore` first")
        }
        guard apply else {
            return finish(.planned, messages + ["dry-run: nothing deleted (add --apply)"], plan: plan)
        }
        let (executed, failure) = run(plan, timeout: environment.purgeTimeout)
        if let failure { return finish(.appliedFailed(failure), messages + [failure], plan: plan, executed: executed) }
        guard (try? fm.attributesOfItem(atPath: directory)) == nil else {
            return finish(.appliedFailed("quarantine entry still exists"), messages, plan: plan, executed: executed)
        }
        return finish(.appliedOk, messages + ["verified: \(directory) is gone"], plan: plan, executed: executed)
    }

    // MARK: - execution

    /// Runs a plan in order, stops at the first failure. sudo steps go
    /// through the interactive seam (the password prompt needs the tty).
    func run(_ plan: [PlannedCommand], timeout: TimeInterval) -> (executed: [String], failure: String?) {
        var executed: [String] = []
        for command in plan {
            let exit: Int32 = command.command == "/usr/bin/sudo"
                ? environment.runner.runInteractive(command: command.command, arguments: command.arguments,
                                                    timeout: timeout)
                : environment.runner.run(command: command.command, arguments: command.arguments,
                                         timeout: timeout).exitCode
            executed.append(command.display)
            if exit != 0 { return (executed, "stopped at: \(command.display) (exit \(exit))") }
        }
        return (executed, nil)
    }
}

/// Every package that lists a path, Apple's included — `pkgutil --file-info`,
/// asked once per path.
final class ClaimCache: @unchecked Sendable {
    let runner: CommandRunner
    private var cache: [String: Set<String>] = [:]

    init(runner: CommandRunner) { self.runner = runner }

    func claimants(_ path: String) -> Set<String> {
        if let hit = cache[path] { return hit }
        let result = runner.run(command: "/usr/sbin/pkgutil", arguments: ["--file-info", path], timeout: 20)
        var ids = Set<String>()
        for line in result.stdout.components(separatedBy: "\n") where line.hasPrefix("pkgid: ") {
            ids.insert(String(line.dropFirst(7)).trimmingCharacters(in: .whitespaces))
        }
        cache[path] = ids
        return ids
    }
}
