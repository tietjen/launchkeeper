import Foundation

/// Runs `codesign -dvvv` per unique executable path (cached). No shell, argv only.
public final class SignatureScanner {
    private var cache: [String: CodeSignatureRecord] = [:]

    public init() {}

    public func status(for path: String, runner: CommandRunner) -> CodeSignatureRecord {
        if let cached = cache[path] { return cached }
        guard path.hasPrefix("/") else {
            let record = CodeSignatureRecord(path: path, status: "unavailable")
            cache[path] = record
            return record
        }

        // Apple system binaries: classified without spawning codesign per path.
        // /usr/local is NOT Apple territory (Homebrew, custom scripts) — sign it.
        let appleCore = !path.hasPrefix("/usr/local/")
            && (path.hasPrefix("/usr/") || path.hasPrefix("/bin/")
                || path.hasPrefix("/sbin/") || path.hasPrefix("/System/"))
        if appleCore {
            let record = CodeSignatureRecord(path: path, status: "apple-system")
            cache[path] = record
            return record
        }

        let result = runner.run(command: "/usr/bin/codesign", arguments: ["-dvvv", path])
        // codesign prints its report to stderr; combined source of truth below.
        let output = result.stdout + "\n" + result.stderr

        var status: String
        var identifier: String?
        var teamIdentifier: String?
        var authority0: String?

        for rawLine in output.split(separator: "\n") {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("Identifier=") {
                identifier = String(line.dropFirst("Identifier=".count))
            } else if line.hasPrefix("TeamIdentifier=") {
                // "TeamIdentifier=not set" is codesign's way of saying none.
                let t = String(line.dropFirst("TeamIdentifier=".count))
                teamIdentifier = t == "not set" ? nil : t.split(separator: " ").first.map(String.init)
            } else if line.hasPrefix("Authority="), authority0 == nil {
                authority0 = String(line.dropFirst("Authority=".count))
            }
        }

        if result.exitCode == 0 {
            if output.contains("Signature=adhoc") || authority0 == nil {
                status = "adhoc"
            } else {
                status = "signed"
            }
        } else {
            status = identifier == nil ? "unsigned" : "unavailable"
        }

        let record = CodeSignatureRecord(
            path: path, status: status, identifier: identifier,
            teamIdentifier: teamIdentifier, authority0: authority0
        )
        cache[path] = record
        return record
    }

    public func cachedRecords() -> [CodeSignatureRecord] { Array(cache.values) }
}