import Foundation

/// Risk hints are "REVIEW RECOMMENDED" markers only — never a malware claim
/// and never an auto-delete trigger (spec §"Risk is a hint, not a verdict").
public struct RiskAnalyzer {
    public var fileManager: FileManager
    public init(fileManager: FileManager = .default) { self.fileManager = fileManager }

    public func apply(to items: inout [BackgroundItem]) {
        for index in items.indices {
            var item = items[index]
            var flags: [String] = []

            let targets = [item.executable].compactMap { $0 } + item.arguments.filter { $0.hasPrefix("/") }

            // Executables living in world-writable temp or hidden dot-directories.
            for target in targets where PathUtils.isTempOrHiddenPath(target) {
                flags.append("temp-or-hidden-path")
            }

            // A shell/interpreter persisting as a launchd service deserves a look:
            // "shell script + auto-start" is a classic accidental-persistence shape.
            if item.executable.map(interpreterLike) == true, item.plistPresent || item.launchdPresent {
                flags.append("shell-interpreter-service")
            }

            // Unsigned or ad-hoc payloads. Apple system components are excluded:
            // they are read-only by design and not user-manageable anyway.
            if let sig = item.codeSignatureStatus, sig == "unsigned" || sig == "adhoc",
               let exec = item.executable, !PathUtils.isSystemOwnedPath(exec) {
                flags.append("unsigned-executable")
            }

            // System-domain service whose backing file is writable by a non-root owner.
            if item.domain == .system || item.domain == .mixed,
               let exec = item.executable,
               let info = PathUtils.ownerInfo(exec, fileManager: fileManager),
               info.writableByUser {
                flags.append("user-writable-daemon-binary")
            }

            // Anything launched straight out of Downloads.
            for target in targets where target.contains("/Downloads/") {
                flags.append("downloads-executable")
            }

            item.riskFlags = Array(Set(flags)).sorted()
            items[index] = item
        }
    }

    private func interpreterLike(_ exec: String) -> Bool {
        if PathUtils.shellInterpreters.contains(exec) { return true }
        let known: Set<String> = ["bash", "sh", "zsh", "dash", "csh", "tcsh", "ksh",
                                  "osascript", "python", "python3", "perl", "ruby", "node"]
        guard exec.hasPrefix("/bin/") || exec.hasPrefix("/usr/bin/")
            || exec.hasPrefix("/usr/local/bin/") || exec.hasPrefix("/opt/homebrew/bin/") else { return false }
        return known.contains((exec as NSString).lastPathComponent)
    }
}
