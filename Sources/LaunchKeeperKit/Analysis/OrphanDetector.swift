import Foundation

/// Conservative orphan detection: an item is orphaned only when a referenced
/// on-disk target is provably missing. Absence of evidence is NOT evidence —
/// unknown cases stay unflagged (spec: never auto-guilty, no malware claims).
public struct OrphanDetector {
    public var fileManager: FileManager
    public init(fileManager: FileManager = .default) { self.fileManager = fileManager }

    public func apply(to items: inout [BackgroundItem]) {
        for index in items.indices {
            var item = items[index]
            var reasons: [String] = []
            var confidence: Confidence = .low

            func raise(_ level: Confidence) {
                switch (level, confidence) {
                case (.high, _): confidence = .high
                case (.medium, .low): confidence = .medium
                default: break
                }
            }

            // 1. Primary executable target missing (includes broken symlinks).
            // Relative fragments are unresolvable by design -> NOT evidence (conservative).
            if let exec = item.executable, exec.hasPrefix("/") {
                if !PathUtils.exists(exec, fileManager: fileManager) {
                    reasons.append("executable missing: \(exec)")
                    raise(.high)
                }
            }

            // 2. Interpreter or launcher whose payload is gone: the script
            // (`bash /x/run.sh`) or the binary (`arch -arm64 /opt/x/tool`).
            // Only the argument the interpreter actually runs counts — an
            // output file among the other arguments does not (V0.9.4;
            // before, every absolute argument was treated as the script).
            if let program = EffectiveProgram.resolve(executable: item.executable, arguments: item.arguments),
               let target = program.targetPath, program.kind == .script || program.kind == .binary,
               !PathUtils.exists(target, fileManager: fileManager) {
                reasons.append((program.kind == .script ? "script missing: " : "program missing: ") + target
                    + " (run by \((program.launchers.last.map { ($0 as NSString).lastPathComponent }) ?? "?"))")
                raise(.medium)
            }

            // 3. Login-item helper whose parent application bundle is gone.
            if item.parentApplication != nil, item.appPresent == false {
                reasons.append("parent application bundle missing")
                raise(item.running ? .high : .medium)
            }

            // 4. (V0.4) Spotlight is the INDEPENDENT second source: the bundle
            // path probe says "gone" and a fresh index lookup confirms that
            // nothing is registered under the bundle id, anywhere. That
            // upgrades the single path probe to a hard orphan signal.
            // "unknown"/"relocated" deliberately add nothing — unknown stays
            // unknown, and relocated means the app exists elsewhere.
            if item.parentApplication != nil, item.appPresent == false,
               item.metadata["app-gone-confirmed"] == "missing",
               let bundleID = item.bundleIdentifier {
                reasons.append("parent application \(item.parentApplication!) is gone — "
                    + "bundle ID \(bundleID) not found via Spotlight")
                raise(.high)
            }

            // 5. BTM entry pointing at a .plist that is no longer on disk.
            if item.btmPresent, !item.plistPresent, !item.launchdPresent,
               let path = item.path, path.hasSuffix(".plist"), path.hasPrefix("/") {
                if !PathUtils.exists(path, fileManager: fileManager) {
                    reasons.append("BTM entry without backing plist: \(path)")
                    raise(.medium)
                }
            }

            // 7. (V0.5.5) A privileged helper no LaunchDaemon points at: nothing
            // can start it — the leftover of an uninstalled app.
            if item.type == .privilegedHelper, !item.launchdPresent, !item.plistPresent {
                reasons.append("privileged helper without a LaunchDaemon — nothing can start it "
                    + "(leftover of an uninstalled app)")
                raise(.medium)
            }

            // 8. (V0.5.5) A system extension whose host app is nowhere: it
            // outlives its app (no app in /Applications ships it, Spotlight
            // knows none).
            if item.type == .systemExtension, item.metadata["sysext-host-app"] == "not found" {
                reasons.append("host app not found — no app ships \(item.bundleIdentifier ?? item.displayName) "
                    + "and Spotlight knows none; the extension outlives its app")
                raise(.medium)
            }

            // 9. (V0.5.6) StartupItems: SystemStarter left with OS X 10.10.
            // Whatever sits in /Library/StartupItems never runs — a leftover
            // of an installer that predates launchd-only boot.
            if item.type == .startupItem {
                reasons.append("legacy StartupItem — SystemStarter is gone since OS X 10.10, nothing runs it")
                raise(.medium)
            }

            // 10. (V0.5.7) A shell profile that sources a file that is gone
            // — the leftover of an uninstalled tool's `source` line.
            if item.type == .shellProfile || item.type == .pathEntry,
               let missing = item.metadata["shell-sources-missing"] ?? item.metadata["path-entries-missing"] {
                reasons.append((item.type == .pathEntry ? "PATH entry points at a missing directory: " : "sources a missing file: ") + missing)
                raise(.low)
            }

            // 6. (V0.4.4) BTM leftover: the record is all that is left — no
            // plist on disk, no launchd job. Not a broken component but the
            // trail of one already removed. `remove` has nothing to delete and
            // BTM prunes the record itself (seen live within minutes after the
            // plist went). ONE reason, low confidence: a note, not a work item.
            if item.btmPresent, !item.plistPresent, !item.launchdPresent,
               let path = item.path, path.hasPrefix("/"), path.hasSuffix(".plist"),
               !PathUtils.exists(path, fileManager: fileManager) {
                reasons = ["BTM leftover: plist already gone (\(path)) — nothing to remove; "
                    + "BTM prunes the record itself, otherwise `launchkeeper resetbtm`"]
                confidence = .low
                item.metadata["btm-leftover"] = "true"
            }

            if !reasons.isEmpty {
                item.orphaned = true
                item.orphanConfidence = confidence
                item.orphanReasons = reasons
            }
            items[index] = item
        }
    }
}
