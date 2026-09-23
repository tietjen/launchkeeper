import Foundation
#if canImport(CryptoKit)
import CryptoKit
#endif

// V0.6.2 — `inspect --verify`: the signature in depth for ONE item. Too
// slow and too noisy for every row (spctl is a third of a second per
// path), exactly right when one entry deserves a look: is the seal
// intact, who signed it, is it notarized, what is its hash.

public struct SignatureVerification: Codable, Equatable {
    public var path: String
    /// `codesign --verify --strict`: seal and designated requirement hold.
    public var sealValid: Bool
    public var sealDetail: String
    public var identifier: String?
    public var teamIdentifier: String?
    public var format: String?
    public var cdHash: String?
    public var timestamp: String?
    public var hardenedRuntime: Bool
    public var adhoc: Bool
    /// The whole chain, leaf first.
    public var authorities: [String]
    /// `spctl --assess`: accepted / rejected / unavailable.
    public var assessment: String
    public var assessmentSource: String?
    public var assessmentDetail: String?
    public var sha256: String?
    /// The file the hash and the assessment refer to (a bundle's main executable).
    public var hashedFile: String?

    public init(path: String, sealValid: Bool = false, sealDetail: String = "", identifier: String? = nil,
                teamIdentifier: String? = nil, format: String? = nil, cdHash: String? = nil, timestamp: String? = nil,
                hardenedRuntime: Bool = false, adhoc: Bool = false, authorities: [String] = [],
                assessment: String = "unavailable", assessmentSource: String? = nil, assessmentDetail: String? = nil,
                sha256: String? = nil, hashedFile: String? = nil) {
        self.path = path; self.sealValid = sealValid; self.sealDetail = sealDetail; self.identifier = identifier
        self.teamIdentifier = teamIdentifier; self.format = format; self.cdHash = cdHash; self.timestamp = timestamp
        self.hardenedRuntime = hardenedRuntime; self.adhoc = adhoc; self.authorities = authorities
        self.assessment = assessment; self.assessmentSource = assessmentSource; self.assessmentDetail = assessmentDetail
        self.sha256 = sha256; self.hashedFile = hashedFile
    }

    public func renderText() -> String {
        var lines = ["  verification: \(path)"]
        lines.append("    seal:       " + (sealValid ? "valid (codesign --verify --strict)" : "INVALID — " + sealDetail))
        if let identifier { lines.append("    identifier: \(identifier)") }
        lines.append("    team:       " + (teamIdentifier ?? "none"))
        if let format { lines.append("    format:     \(format)") }
        lines.append("    runtime:    " + (hardenedRuntime ? "hardened" : "not hardened") + (adhoc ? ", ad-hoc signature" : ""))
        if let timestamp { lines.append("    timestamp:  \(timestamp)") }
        if let cdHash { lines.append("    cdhash:     \(cdHash)") }
        if authorities.isEmpty {
            lines.append("    authority:  none")
        } else {
            for (index, authority) in authorities.enumerated() {
                lines.append((index == 0 ? "    authority:  " : "                ") + authority)
            }
        }
        var gate = "    gatekeeper: \(assessment)"
        if let source = assessmentSource { gate += " — \(source)" }
        if let detail = assessmentDetail, assessment != "accepted", detail != assessment { gate += " (\(detail))" }
        lines.append(gate)
        if let sha256 {
            lines.append("    sha256:     \(sha256)")
            if let hashedFile, hashedFile != path { lines.append("                of \(hashedFile)") }
        }
        return lines.joined(separator: "\n")
    }
}

public struct SignatureVerifier {
    let runner: CommandRunner
    let fileManager: FileManager

    public init(runner: CommandRunner, fileManager: FileManager = .default) {
        self.runner = runner; self.fileManager = fileManager
    }

    /// The bundle's main executable, when `path` is a bundle.
    func mainExecutable(ofBundle path: String) -> String? {
        guard let info = try? PlistReader.readDictionary(fromFile: path + "/Contents/Info.plist", fileManager: fileManager),
              let name = info["CFBundleExecutable"] as? String else { return nil }
        let candidate = path + "/Contents/MacOS/" + name
        return fileManager.fileExists(atPath: candidate) ? candidate : nil
    }

    static func sha256(ofFile path: String) -> String? {
        #if canImport(CryptoKit)
        guard let data = fileManager_default_contents(path) else { return nil }
        return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
        #else
        return nil
        #endif
    }

    private static func fileManager_default_contents(_ path: String) -> Data? {
        try? Data(contentsOf: URL(fileURLWithPath: path), options: .mappedIfSafe)
    }

    public func verify(path: String) -> SignatureVerification {
        var result = SignatureVerification(path: path)
        var isDirectory: ObjCBool = false
        let exists = fileManager.fileExists(atPath: path, isDirectory: &isDirectory)
        guard exists else {
            result.sealDetail = "file missing"
            result.assessment = "unavailable"
            return result
        }
        let isBundle = isDirectory.boolValue

        // 1. The seal.
        let verify = runner.run(command: "/usr/bin/codesign", arguments: ["--verify", "--strict", "-v", path])
        let verifyText = (verify.stdout + "\n" + verify.stderr).trimmingCharacters(in: .whitespacesAndNewlines)
        result.sealValid = verify.exitCode == 0
        result.sealDetail = verifyText.components(separatedBy: "\n").last
            .map { $0.replacingOccurrences(of: path + ": ", with: "") } ?? ""

        // 2. The details.
        let display = runner.run(command: "/usr/bin/codesign", arguments: ["-dvvv", path])
        for raw in (display.stdout + "\n" + display.stderr).components(separatedBy: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("Identifier=") { result.identifier = String(line.dropFirst("Identifier=".count)) }
            else if line.hasPrefix("TeamIdentifier=") {
                let team = String(line.dropFirst("TeamIdentifier=".count))
                result.teamIdentifier = team == "not set" ? nil : team
            } else if line.hasPrefix("Format=") { result.format = String(line.dropFirst("Format=".count)) }
            else if line.hasPrefix("CDHash=") { result.cdHash = String(line.dropFirst("CDHash=".count)) }
            else if line.hasPrefix("Timestamp=") { result.timestamp = String(line.dropFirst("Timestamp=".count)) }
            else if line.hasPrefix("Authority=") { result.authorities.append(String(line.dropFirst("Authority=".count))) }
            else if line.hasPrefix("CodeDirectory ") { result.hardenedRuntime = line.contains("(runtime)") }
            else if line.hasPrefix("Signature=adhoc") { result.adhoc = true }
        }

        // 3. Gatekeeper. Bundles are assessed for execution; a bare binary
        // is "not an app" to that policy, the install policy answers it.
        let assess = runner.run(command: "/usr/sbin/spctl",
                                arguments: ["--assess", "-vv", "--type", isBundle ? "execute" : "install", path])
        let assessText = (assess.stdout + "\n" + assess.stderr).trimmingCharacters(in: .whitespacesAndNewlines)
        result.assessment = assess.exitCode == 0 ? "accepted" : "rejected"
        for raw in assessText.components(separatedBy: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("source=") { result.assessmentSource = String(line.dropFirst("source=".count)) }
            else if line.hasPrefix(path + ": ") {
                result.assessmentDetail = String(line.dropFirst(path.count + 2))
            }
        }
        if assess.exitCode != 0, result.assessmentDetail == nil, !assessText.isEmpty { result.assessmentDetail = assessText }

        // 4. The hash — of the executable, never of a directory.
        let target = isBundle ? mainExecutable(ofBundle: path) : path
        if let target, let hash = Self.sha256(ofFile: target) {
            result.sha256 = hash
            result.hashedFile = target
        }
        return result
    }
}
