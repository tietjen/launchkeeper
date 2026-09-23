import Foundation

/// Where did this come from? V0.5 answers the cheap questions from evidence
/// already in hand: Apple (label / path), Homebrew (label prefix, Cellar
/// path), Mac App Store (`_MASReceipt` in the parent bundle). Package
/// receipts (`pkgutil`) arrive with V0.6. Unknown stays unknown.
public struct ProvenanceResolver {
    public var fileManager: FileManager
    /// V0.6: package receipts, indexed by path. nil = pkgutil not consulted.
    public var receipts: ReceiptIndex?
    public init(fileManager: FileManager = .default, receipts: ReceiptIndex? = nil) {
        self.fileManager = fileManager; self.receipts = receipts
    }

    /// yyyy-mm-dd — a fresh formatter per call keeps the struct Sendable.
    static func dayString(_ date: Date) -> String {
        let f = ISO8601DateFormatter()
        f.formatOptions = [.withFullDate]
        return f.string(from: date)
    }

    /// The app bundle an item belongs to, when one is known.
    func appBundle(of item: BackgroundItem) -> String? {
        for candidate in [item.metadata["app-bundle"], item.metadata["btm-bundle-path"],
                          item.metadata["sysext-host-app"], item.metadata["helper-client-app"], item.path] {
            guard let candidate, candidate.hasPrefix("/") else { continue }
            if let range = candidate.range(of: ".app/") { return String(candidate[..<range.lowerBound]) + ".app" }
            if candidate.hasSuffix(".app") { return candidate }
        }
        return nil
    }

    public func apply(to items: inout [BackgroundItem]) {
        for index in items.indices where items[index].provenance == nil {
            items[index].provenance = resolve(items[index])
        }
    }

    public func resolve(_ item: BackgroundItem) -> Provenance {
        if item.label?.hasPrefix("com.apple.") == true
            || item.displayName.hasPrefix("com.apple.")
            || item.executable.map(PathUtils.isSystemOwnedPath) == true
            || item.path?.hasPrefix("/System/") == true {
            return Provenance(kind: .apple, detail: "Apple system component")
        }
        if item.label?.hasPrefix("homebrew.") == true {
            return Provenance(kind: .homebrew, detail: "launchd label homebrew.*")
        }
        let bundle = appBundle(of: item)
        for probe in [item.executable, item.path, bundle].compactMap({ $0 }) {
            if probe.hasPrefix("/opt/homebrew/") || probe.contains("/usr/local/Cellar/")
                || probe.contains("/usr/local/Caskroom/") {
                return Provenance(kind: .homebrew, detail: probe)
            }
        }
        if let bundle, fileManager.fileExists(atPath: bundle + "/Contents/_MASReceipt/receipt") {
            return Provenance(kind: .appStore, detail: bundle + "/Contents/_MASReceipt/receipt")
        }
        // V0.6: a package receipt that lists the plist, the executable, the
        // bundle or the app — pkgutil's word on who installed it.
        if let receipts {
            let probes = [item.path, item.executable, item.metadata["btm-bundle-path"], bundle,
                          item.metadata["helper-path"]].compactMap { $0 }.filter { $0.hasPrefix("/") }
            for probe in probes {
                if let receipt = receipts.receipt(forPath: probe) {
                    let installed = receipt.installTime.map(Self.dayString)
                    var detail = "package " + receipt.id
                    if let version = receipt.version { detail += " " + version }
                    if let installed { detail += ", installed " + installed }
                    return Provenance(kind: .receipt, detail: detail, packageIdentifier: receipt.id,
                                      version: receipt.version, installedAt: installed)
                }
            }
            // An app on disk that no receipt knows and no store sold:
            // dragged out of a disk image or a zip, or put there by an app
            // itself. Only with the index in hand — else "unknown".
            if let bundle, fileManager.fileExists(atPath: bundle), !bundle.hasPrefix("/System/") {
                return Provenance(kind: .manual,
                                  detail: "app bundle without a package receipt or App Store receipt: " + bundle)
            }
        }
        return Provenance(kind: .unknown, detail: nil)
    }
}
