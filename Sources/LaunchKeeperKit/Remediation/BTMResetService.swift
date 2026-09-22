import Foundation

/// V0.4b: guarded `sfltool resetbtm` — the reset of the Background Task
/// Management database.
///
/// Design constraints come from the 2026-09-17 incident AND from what
/// `sfltool` actually offers:
///
/// 1. **`sfltool` has no import/load.** A `dumpbtm` text file cannot be
///    written back. The pre-reset snapshot is therefore an AUDIT artifact
///    (what was destroyed, for the record) — NOT a backup. The command says
///    so in words before `--apply`, and it is not dressed up as restorable.
/// 2. **No snapshot, no reset.** The same rule that makes `remove` take a
///    pre-delete snapshot: if the pre-dump cannot be written, nothing is
///    reset. An unrecorded reset of a system database is exactly the failure
///    mode of the incident.
/// 3. **Unreadable DB, no reset.** If the pre-dump itself fails, the state
///    is unknown — reset a database you cannot read? Never.
/// 4. **Verify-after-mutate.** After the reset the service dumps AGAIN:
///    exit codes prove nothing, and a "successful" reset is only one whose
///    after-dump succeeds and shows the database is actually empty-ish.
/// 5. **Dry-run is the default.** Like every other command in this tool.
///
/// The command goes through the same argv-only runner seam (no shell, no
/// private APIs) and is audited like every other operation.

public struct BTMResetEnvironment {
    public var runner: CommandRunner
    public var fileManager: FileManager
    public var home: String
    /// Root for the audit snapshots (full dumpbtm text, one file per reset).
    public var snapshotsRoot: String
    /// Same budget as the scan's BTM stage: a healthy dump takes seconds.
    public var btmTimeout: TimeInterval = 150

    public init(runner: CommandRunner = SystemCommandRunner(),
                fileManager: FileManager = .default,
                home: String = NSHomeDirectory(),
                snapshotsRoot: String? = nil,
                btmTimeout: TimeInterval = 150) {
        self.runner = runner
        self.fileManager = fileManager
        self.home = home
        self.snapshotsRoot = snapshotsRoot ?? LaunchKeeperPaths.btmSnapshots(home: home)
        self.btmTimeout = btmTimeout
    }
}

public enum BTMResetOutcome: Equatable {
    /// Default mode: current state shown, nothing executed, snapshot would
    /// be written before the reset.
    case dryRun(beforeRecords: Int, wouldSnapshot: String, notes: [String])
    case applied(beforeRecords: Int, afterRecords: Int, snapshot: String, notes: [String])
    /// The reset command ran (or its precondition ran) but the end state
    /// could not be verified.
    case appliedFailed(detail: String, beforeRecords: Int, snapshot: String?)
    case refused(reason: String)
}

/// One-sentence irreversibility statement — printed with EVERY outcome,
/// because the danger is not in the command but in the assumption that it
/// is undoable.
public let btmResetIrreversibilityNote =
    "NOT RESTORABLE: sfltool has no import — the snapshot is an audit "
    + "artifact, not a backup. Registrations re-establish only as the apps "
    + "that own them run again."

public struct BTMResetService {
    public var env: BTMResetEnvironment
    public init(env: BTMResetEnvironment = BTMResetEnvironment()) { self.env = env }

    private func dumpbtm() -> CommandResult {
        env.runner.run(command: "/usr/bin/sfltool", arguments: ["dumpbtm"],
                       timeout: env.btmTimeout)
    }

    private func recordCount(_ result: CommandResult) -> Int? {
        guard result.exitCode == 0 else { return nil }
        return BTMDumpParser.parse(result.stdout).records.count
    }

    /// Full dumpbtm text persisted under snapshotsRoot + `sfltool archive`
    /// (copies the SharedFileList storage — a DIFFERENT store, but the only
    /// Apple-provided copy mechanism; its destination is reported).
    ///
    /// `preDump` is the read `run` already performed as its refusal gate:
    /// the snapshot persists exactly the state we verified we can read.
    /// One dump, used twice — a wedged dumpbtm costs its full timeout
    /// budget and this tool must never pay it twice in a single reset.
    func snapshot(now: Date, preDump: CommandResult) -> (name: String,
                                                        path: String,
                                                        records: Int,
                                                        ok: Bool,
                                                        notes: [String]) {
        let fm = env.fileManager
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd-HHmmss"
        formatter.timeZone = TimeZone(identifier: "UTC")
        let name = formatter.string(from: now) + "Z"
        let dir = env.snapshotsRoot
        var notes: [String] = []

        let before = preDump
        guard before.exitCode == 0, let records = recordCount(before) else {
            return (name, "", 0, false,
                    ["pre-dump failed (exit \(before.exitCode)) — no snapshot written, "
                        + "no reset will run"])
        }
        do {
            try fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
        } catch {
            return (name, "", 0, false,
                    ["cannot create snapshot dir \(dir): \(error.localizedDescription)"])
        }
        let path = dir + "/" + name + ".btmdump.txt"
        do {
            try Data(before.stdout.utf8).write(to: URL(fileURLWithPath: path))
        } catch {
            return (name, path, records, false,
                    ["snapshot write failed: \(error.localizedDescription)"])
        }
        let archive = env.runner.run(command: "/usr/bin/sfltool", arguments: ["archive"],
                                     timeout: 20)
        if archive.exitCode == 0, let dest = archive.stdout
            .split(separator: "copied to").last?.trimmingCharacters(in: .whitespaces) {
            notes.append("sfltool archive: SharedFileList storage copied to \(dest)")
        } else {
            notes.append("sfltool archive unavailable (exit \(archive.exitCode)) — "
                + "BTM snapshot written anyway")
        }
        return (name, path, records, true, notes)
    }

    public func run(apply: Bool) -> BTMResetOutcome {
        // 1. Read the state we are about to destroy. Unreadable -> refused.
        let before = dumpbtm()
        guard before.exitCode == 0, let beforeRecords = recordCount(before) else {
            return .refused(reason: "could not read the BTM database (sfltool dumpbtm "
                + "exit \(before.exitCode)) — refusing to reset a state we cannot even see")
        }

        let proposedName = { () -> String in
            let f = DateFormatter()
            f.dateFormat = "yyyy-MM-dd-HHmmss"
            f.timeZone = TimeZone(identifier: "UTC")
            return f.string(from: Date()) + "Z"
        }()

        // 2. Dry-run default: show the state, name the snapshot, warn.
        guard apply else {
            return .dryRun(beforeRecords: beforeRecords, wouldSnapshot: proposedName,
                           notes: [btmResetIrreversibilityNote,
                                   "dry-run: nothing executed, no snapshot written"])
        }

        // 3. No snapshot, no reset — persist the state we just read
        //    (one dumpbtm: gate and artifact share it).
        let snap = snapshot(now: Date(), preDump: before)
        guard snap.ok else {
            return .refused(reason: "audit snapshot could not be written "
                + "(\(snap.notes.joined(separator: "; "))) — no reset without a "
                + "record of what was destroyed")
        }

        // 4. The reset itself (argv only, no shell).
        let reset = env.runner.run(command: "/usr/bin/sfltool", arguments: ["resetbtm"],
                                   timeout: 30)
        if reset.exitCode != 0 {
            return .appliedFailed(detail: "resetbtm exit \(reset.exitCode): "
                + (reset.stderr.isEmpty ? "(no stderr)" : reset.stderr),
                                  beforeRecords: beforeRecords, snapshot: snap.path)
        }

        // 5. Verify-after-mutate: dump AGAIN. The database must be readable
        //    afterwards; the expected end state is empty (fresh registrations
        //    accumulate over time, a handful is fine — a full rebuild is not
        //    instant, so the count is reported, not policed).
        let after = dumpbtm()
        if after.exitCode != 0 {
            return .appliedFailed(detail: "post-dump exit \(after.exitCode) — "
                + "end state unverified",
                                  beforeRecords: beforeRecords, snapshot: snap.path)
        }
        let afterRecords = recordCount(after) ?? 0
        return .applied(beforeRecords: beforeRecords, afterRecords: afterRecords,
                        snapshot: snap.path,
                        notes: [btmResetIrreversibilityNote,
                                "audit snapshot: \(snap.path) (\(snap.records) records)",
                                snap.notes.joined(separator: "; ")]
                            .filter { !$0.isEmpty })
    }
}
