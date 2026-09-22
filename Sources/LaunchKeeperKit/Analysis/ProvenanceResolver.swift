import Foundation

/// Where did this come from? V0.5 answers the cheap questions from evidence
/// already in hand: Apple (label / path), Homebrew (label prefix, Cellar
/// path), Mac App Store (`_MASReceipt` in the parent bundle). Package
/// receipts (`pkgutil`) arrive with V0.6. Unknown stays unknown.
public struct ProvenanceResolver {
    public var fileManager: FileManager
    public init(fileManager: FileManager = .default) { self.fileManager = fileManager }

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
        for probe in [item.executable, item.path].compactMap({ $0 }) {
            if probe.hasPrefix("/opt/homebrew/") || probe.contains("/usr/local/Cellar/") {
                return Provenance(kind: .homebrew, detail: probe)
            }
        }
        if let bundle = item.metadata["app-bundle"],
           fileManager.fileExists(atPath: bundle + "/Contents/_MASReceipt/receipt") {
            return Provenance(kind: .appStore, detail: bundle + "/Contents/_MASReceipt/receipt")
        }
        return Provenance(kind: .unknown, detail: nil)
    }
}
