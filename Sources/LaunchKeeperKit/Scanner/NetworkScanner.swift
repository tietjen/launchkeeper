import Foundation

// V0.5.7 — K "Network": listening sockets ↔ process ↔ inventory entry, and
// the Application Firewall's per-app rules. Read-only.

public struct ListeningSocket: Equatable, Sendable {
    public var pid: Int
    public var command: String
    public var user: String
    public var proto: String             // tcp / udp
    public var address: String           // "*:59368", "127.0.0.1:23373", "[::1]:8080"
    public init(pid: Int, command: String, user: String, proto: String, address: String) {
        self.pid = pid; self.command = command; self.user = user; self.proto = proto; self.address = address
    }
    public var port: Int? {
        guard let colon = address.lastIndex(of: ":") else { return nil }
        return Int(address[address.index(after: colon)...])
    }
    public var loopbackOnly: Bool { address.hasPrefix("127.") || address.hasPrefix("[::1]") || address.hasPrefix("localhost") }
}

public struct ListeningProcess: Equatable, Sendable {
    public var pid: Int
    public var command: String
    public var user: String
    public var executable: String?
    public var sockets: [ListeningSocket]
    public init(pid: Int, command: String, user: String, executable: String? = nil, sockets: [ListeningSocket] = []) {
        self.pid = pid; self.command = command; self.user = user; self.executable = executable; self.sockets = sockets
    }
}

public struct FirewallRule: Equatable, Sendable {
    public var path: String
    public var action: String            // allow / block
    public init(path: String, action: String) { self.path = path; self.action = action }
}

public enum LsofFieldParser {
    /// `lsof -F pcLPn`: one field per line, first char is the field id —
    /// p pid, c command, L login, P protocol, n name. A process header (p)
    /// applies to every n line until the next p.
    public static func parse(_ text: String) -> [ListeningSocket] {
        var sockets: [ListeningSocket] = []
        var pid = 0, command = "", user = "", proto = ""
        for line in text.components(separatedBy: "\n") {
            guard let id = line.first else { continue }
            let value = String(line.dropFirst())
            switch id {
            case "p": pid = Int(value) ?? 0; command = ""; user = ""
            case "c": command = value
            case "L": user = value
            case "P": proto = value.lowercased()
            case "n":
                // Unbound UDP sockets ("*:*") listen to nothing; a connected
                // socket ("local->remote", QUIC and friends) is a client.
                guard value != "*:*", !value.isEmpty, !value.contains("->") else { continue }
                let address = value.replacingOccurrences(of: " (LISTEN)", with: "")
                sockets.append(ListeningSocket(pid: pid, command: command, user: user, proto: proto, address: address))
            default: continue
            }
        }
        return sockets
    }

    public static func group(_ sockets: [ListeningSocket]) -> [ListeningProcess] {
        var order: [Int] = []
        var byPid: [Int: ListeningProcess] = [:]
        for socket in sockets {
            if byPid[socket.pid] == nil {
                order.append(socket.pid)
                byPid[socket.pid] = ListeningProcess(pid: socket.pid, command: socket.command, user: socket.user)
            }
            // The same port on IPv4 and IPv6 is one listener.
            if byPid[socket.pid]!.sockets.contains(where: { $0.proto == socket.proto && $0.address == socket.address }) { continue }
            byPid[socket.pid]!.sockets.append(socket)
        }
        return order.compactMap { byPid[$0] }
    }
}

public enum FirewallListParser {
    /// `socketfilterfw --listapps`: "N : <path>" followed by a line with
    /// "(Allow incoming connections)" or "(Block incoming connections)".
    public static func parse(_ text: String) -> [FirewallRule] {
        var rules: [FirewallRule] = []
        var pending: String?
        for raw in text.components(separatedBy: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if let colon = line.range(of: " : "), Int(line[..<colon.lowerBound]) != nil {
                pending = String(line[colon.upperBound...]).trimmingCharacters(in: .whitespaces)
            } else if let path = pending, line.hasPrefix("(") {
                rules.append(FirewallRule(path: path, action: line.lowercased().contains("block") ? "block" : "allow"))
                pending = nil
            }
        }
        return rules
    }
}

public struct NetworkScanner {
    public struct Result {
        public var processes: [ListeningProcess] = []
        public var firewall: [FirewallRule] = []
        public var firewallState: String?
        public var warnings: [String] = []
        public var checks: [String] = []
        public var failed: [String] = []
        public init() {}
    }

    let runner: CommandRunner
    public init(runner: CommandRunner) { self.runner = runner }

    public func scan() -> Result {
        var result = Result()
        var sockets: [ListeningSocket] = []
        var lsofFailed = false
        for (label, args) in [("tcp", ["-nP", "-iTCP", "-sTCP:LISTEN", "-F", "pcLPn"]),
                              ("udp", ["-nP", "-iUDP", "-F", "pcLPn"])] {
            let run = runner.run(command: "/usr/sbin/lsof", arguments: args)
            // lsof exits 1 when nothing matched — that is an empty answer, not a failure.
            if run.exitCode == 0 || (run.exitCode == 1 && run.stdout.isEmpty) {
                sockets.append(contentsOf: LsofFieldParser.parse(run.stdout))
            } else {
                lsofFailed = true
                result.warnings.append("\(label) sockets not scanned: lsof exit \(run.exitCode): "
                    + run.stderr.trimmingCharacters(in: .whitespacesAndNewlines))
            }
        }
        if lsofFailed {
            result.checks.append("lsof: FAILED")
            result.failed.append("lsof")
        } else {
            var processes = LsofFieldParser.group(sockets)
            if !processes.isEmpty {
                let pids = processes.map { String($0.pid) }.joined(separator: ",")
                let ps = runner.run(command: "/bin/ps", arguments: ["-o", "pid=,comm=", "-p", pids])
                if ps.exitCode == 0 {
                    var paths: [Int: String] = [:]
                    for line in ps.stdout.components(separatedBy: "\n") {
                        let trimmed = line.trimmingCharacters(in: .whitespaces)
                        guard let space = trimmed.firstIndex(of: " "), let pid = Int(trimmed[..<space]) else { continue }
                        paths[pid] = String(trimmed[trimmed.index(after: space)...]).trimmingCharacters(in: .whitespaces)
                    }
                    for index in processes.indices { processes[index].executable = paths[processes[index].pid] }
                } else {
                    result.warnings.append("process paths unresolved: ps exit \(ps.exitCode)")
                }
            }
            result.processes = processes
            let ports = processes.reduce(0) { $0 + $1.sockets.count }
            result.checks.append("lsof: ok (\(processes.count) listening processes, \(ports) sockets)")
        }

        let fw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        let state = runner.run(command: fw, arguments: ["--getglobalstate"])
        if state.exitCode == 0 {
            let text = state.stdout.trimmingCharacters(in: .whitespacesAndNewlines)
            result.firewallState = text.lowercased().contains("enabled") ? "enabled" : "disabled"
            let list = runner.run(command: fw, arguments: ["--listapps"])
            if list.exitCode == 0 {
                result.firewall = FirewallListParser.parse(list.stdout)
                result.checks.append("application firewall: \(result.firewallState!) (\(result.firewall.count) app rules)")
            } else {
                result.warnings.append("firewall rules not scanned: socketfilterfw --listapps exit \(list.exitCode)")
                result.checks.append("application firewall: \(result.firewallState!), rules FAILED")
                result.failed.append("socketfilterfw")
            }
        } else {
            result.warnings.append("application firewall not scanned: socketfilterfw exit \(state.exitCode): "
                + state.stderr.trimmingCharacters(in: .whitespacesAndNewlines))
            result.checks.append("application firewall: FAILED (exit \(state.exitCode))")
            result.failed.append("socketfilterfw")
        }
        return result
    }
}
