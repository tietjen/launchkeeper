import ArgumentParser
import BTMKit
import Foundation

// btmctl V0.1 — READ-ONLY by design. No subcommand here writes, deletes,
// unloads, disables or resets anything. Removal workflows are a separate,
// future decision (spec: inventory and destruction never share a code path).

private func runScan(userOnly: Bool, systemOnly: Bool) -> ScanReport {
    var options = ScanOptions()
    if userOnly { options.includeSystem = false }
    if systemOnly { options.includeUser = false }
    return ScanCoordinator().perform(options: options)
}

private func emitWarnings(_ report: ScanReport) {
    guard !report.warnings.isEmpty else { return }
    let text = "warnings:\n" + report.warnings.map { "  - " + $0 }.joined(separator: "\n") + "\n"
    FileHandle.standardError.write(Data(text.utf8))
}

struct ListCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "list",
        abstract: "Show the background-service inventory (read-only).")

    @Flag(name: .customLong("json"), help: "JSON output instead of a table")
    var json = false
    @Flag(name: .customLong("orphans"), help: "show only orphaned entries (reason column)")
    var orphans = false
    @Flag(name: .customLong("running"), help: "show only entries with a live process")
    var running = false
    @Flag(name: .customLong("disabled"), help: "show only disabled entries")
    var disabled = false
    @Flag(name: .customLong("user"), help: "user domain only")
    var user = false
    @Flag(name: .customLong("system"), help: "system domain only")
    var system = false
    @Flag(name: .customLong("all"), help: "include Apple-internal entries")
    var all = false

    mutating func run() throws {
        let userOnly = user && !system
        let systemOnly = system && !user
        var filter = ListFilter()
        filter.orphansOnly = orphans
        filter.runningOnly = running
        filter.disabledOnly = disabled
        filter.userOnly = userOnly
        filter.systemOnly = systemOnly
        filter.includeAll = all

        let report = runScan(userOnly: userOnly, systemOnly: systemOnly)
        let rows = filter.apply(to: report.items)
        if json {
            print(try JSONRenderer.encode(rows))
        } else {
            print(TableRenderer.render(rows, mode: orphans ? .orphans : .table))
            emitWarnings(report)
        }
    }
}

struct InspectCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "inspect",
        abstract: "Full details for one entry by display id (e.g. 07) or unique name fragment.")

    @Argument(help: "display id, launchd label, name or key fragment")
    var id: String
    @Flag(name: .customLong("json"), help: "JSON output")
    var json = false

    mutating func run() throws {
        let env = ScanEnvironment()
        let report = ScanCoordinator(environment: env).perform()
        let needle = id.trimmingCharacters(in: .whitespaces).lowercased()

        var candidates: [BackgroundItem] = []
        if let n = Int(needle), needle.allSatisfy({ $0.isNumber }) {
            candidates = report.items.filter { $0.id == String(format: "%02d", n) }
        }
        if candidates.isEmpty {
            candidates = report.items.filter {
                $0.displayName.lowercased().contains(needle)
                    || $0.label?.lowercased().contains(needle) == true
                    || $0.key.lowercased().contains(needle)
            }
        }

        switch candidates.count {
        case 0:
            throw ValidationError("no entry matches '\(id)' — start with `btmctl list`")
        case 1:
            if json {
                print(try JSONRenderer.encode(candidates[0]))
            } else {
                print(InspectRenderer.render(candidates[0], uid: env.uid))
            }
        default:
            let preview = candidates.prefix(6)
                .map { "[\($0.id)] \($0.displayName)" }
                .joined(separator: "\n  ")
            throw ValidationError("ambiguous '\(id)' — \(candidates.count) matches:\n  \(preview)")
        }
    }
}

struct DoctorCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "doctor",
        abstract: "Environment health check and inventory summary (read-only).")

    @Flag(name: .customLong("json"), help: "machine-readable output (checks, warnings, orphans)")
    var json = false

    private struct DoctorJSON: Codable {
        var checks: [String]
        var warnings: [String]
        var orphanCount: Int
        var orphans: [BackgroundItem]
    }

    mutating func run() throws {
        let report = runScan(userOnly: false, systemOnly: false)
        if json {
            let orphans = report.items.filter { $0.orphaned }
            print(try JSONRenderer.encode(DoctorJSON(
                checks: report.checks, warnings: report.warnings,
                orphanCount: orphans.count, orphans: orphans)))
            return
        }
        print("btmctl doctor — read-only checks")
        for check in report.checks {
            print("  . \(check)")
        }
        if report.warnings.isEmpty {
            print("  no warnings")
        } else {
            print("  warnings (\(report.warnings.count)):")
            for warning in report.warnings {
                print("    ! \(warning)")
            }
        }
        let orphans = report.items.filter { $0.orphaned }.count
        if orphans > 0 {
            print("\n\(orphans) orphaned entries — inspect with: btmctl list --orphans")
        }
    }
}

@main
struct Btmctl: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "btmctl",
        abstract: """
        Read-only inventory of macOS background services (V0.1).

        V0.1 deliberately contains no removal or modification capability:
        inventory and destructive operations stay separate, by construction.
        """,
        version: "0.1.0",
        subcommands: [ListCommand.self, InspectCommand.self, DoctorCommand.self],
        defaultSubcommand: ListCommand.self
    )
}
