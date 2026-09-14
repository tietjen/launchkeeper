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

            // 2. Shell-interpreter service whose script argument is gone.
            if let exec = item.executable, isInterpreterLike(exec) {
                for arg in item.arguments where arg.hasPrefix("/") {
                    if !PathUtils.exists(arg, fileManager: fileManager) {
                        reasons.append("script argument missing: \(arg)")
                        raise(.medium)
                    }
                }
            }

            // 3. Login-item helper whose parent application bundle is gone.
            if item.parentApplication != nil, item.appPresent == false {
                reasons.append("parent application bundle missing")
                raise(item.running ? .high : .medium)
            }

            // 4. BTM entry pointing at a .plist that is no longer on disk.
            if item.btmPresent, !item.plistPresent, !item.launchdPresent,
               let path = item.path, path.hasSuffix(".plist"), path.hasPrefix("/") {
                if !PathUtils.exists(path, fileManager: fileManager) {
                    reasons.append("BTM entry without backing plist: \(path)")
                    raise(.medium)
                }
            }

            if !reasons.isEmpty {
                item.orphaned = true
                item.orphanConfidence = confidence
                item.orphanReasons = reasons
            }
            items[index] = item
        }
    }

    private func isInterpreterLike(_ exec: String) -> Bool {
        if PathUtils.shellInterpreters.contains(exec) { return true }
        let known: Set<String> = ["bash", "sh", "zsh", "dash", "csh", "tcsh", "ksh",
                                  "osascript", "python", "python3", "perl", "ruby", "node"]
        guard exec.hasPrefix("/bin/") || exec.hasPrefix("/usr/bin/")
            || exec.hasPrefix("/usr/local/bin/") || exec.hasPrefix("/opt/homebrew/bin/") else { return false }
        return known.contains((exec as NSString).lastPathComponent)
    }
}
