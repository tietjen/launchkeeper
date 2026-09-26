//
//  EffectiveProgram.swift
//  LaunchKeeperKit — what an entry really runs when its executable is only
//  an interpreter or a launcher ("bash", "python3", "arch", "env" …).
//
//  System Settings names such entries after the interpreter ("bash"), and
//  the inventory's `executable` is the interpreter too. The payload — the
//  script, the module, the real binary — is in the arguments. This resolver
//  reads argv the way the interpreter would and names it. Pure function,
//  no file access.
//

import Foundation

/// The program behind an interpreter or launcher command line.
public struct EffectiveProgram: Codable, Equatable, Sendable {

    /// What kind of payload the command line runs.
    public enum Kind: String, Codable, Sendable {
        /// A script file run by an interpreter (`bash /x/run.sh`, `python3 tool.py`).
        case script
        /// A module run by name (`python3 -m http.server`).
        case module
        /// Code given inline on the command line (`bash -c "…"`, `osascript -e "…"`, `ruby -e "…"`).
        case inline
        /// A binary started through a launcher (`arch -arm64 /opt/tool/bin/tool`).
        case binary
        /// An app opened by `open` (`open -a Name`, `open -b com.vendor.app`, `open /Applications/X.app`).
        case app
        /// The interpreter runs without a recognizable payload (interactive, stdin).
        case none
    }

    /// Interpreters and launchers from the outside in, by executable path
    /// (e.g. `["/usr/bin/arch", "/bin/bash"]`).
    public var launchers: [String]
    /// The payload: a path, a module or app name, or the inline code.
    public var target: String?
    /// What the payload is.
    public var kind: Kind

    /// Creates a resolved program.
    public init(launchers: [String], target: String?, kind: Kind) {
        self.launchers = launchers
        self.target = target
        self.kind = kind
    }

    /// The payload as a file path when it is one (script, binary, app bundle path).
    public var targetPath: String? {
        guard let target, kind == .script || kind == .binary || kind == .app, target.hasPrefix("/") else { return nil }
        return target
    }

    /// One line for humans, e.g. "script /x/run.sh via bash", "module http.server via python3".
    public var summary: String {
        let via = launchers.map { ($0 as NSString).lastPathComponent }.joined(separator: " → ")
        switch kind {
        case .script: return "script \(target ?? "?") via \(via)"
        case .module: return "module \(target ?? "?") via \(via)"
        case .inline: return "inline code via \(via): \(Self.shorten(target ?? ""))"
        case .binary: return "\(target ?? "?") via \(via)"
        case .app: return "app \(target ?? "?") via \(via)"
        case .none: return "\(via) without a script"
        }
    }

    /// Cuts inline code to one readable line.
    static func shorten(_ code: String) -> String {
        let oneLine = code.replacingOccurrences(of: "\n", with: " ").trimmingCharacters(in: .whitespaces)
        return oneLine.count > 80 ? String(oneLine.prefix(77)) + "…" : oneLine
    }

    // MARK: - Resolution

    /// Shell interpreters: `-c` takes inline code, `-o`/`+o` take an option name.
    static let shells: Set<String> = ["sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "fish"]
    /// Launchers that run the next argument as a program (after their own options).
    static let wrappers: Set<String> = ["env", "arch", "nohup", "nice", "caffeinate", "exec", "time"]

    /// Resolves what a command line really runs.
    /// - Parameters:
    ///   - executable: argv[0] as launchd starts it (the `Program` key, else `ProgramArguments[0]`).
    ///   - arguments: argv[1...].
    /// - Returns: The resolved program, or `nil` when the executable is neither
    ///   an interpreter nor a launcher (then the executable is the program).
    public static func resolve(executable: String?, arguments: [String]) -> EffectiveProgram? {
        guard let executable, isLauncher(executable) else { return nil }
        return resolve(executable: executable, arguments: arguments, chain: [], depth: 0)
    }

    /// Whether an executable is an interpreter or a launcher this resolver understands.
    public static func isLauncher(_ executable: String) -> Bool {
        let name = (executable as NSString).lastPathComponent
        return shells.contains(name) || wrappers.contains(name) || isPython(name)
            || ["perl", "ruby", "php", "node", "osascript", "open", "tclsh", "lua"].contains(name)
    }

    /// `python`, `python3`, `python3.12` …
    static func isPython(_ name: String) -> Bool {
        name == "python" || name.hasPrefix("python3") || name.hasPrefix("python2")
    }

    private static func resolve(executable: String, arguments: [String], chain: [String],
                                depth: Int) -> EffectiveProgram {
        let launchers = chain + [executable]
        let name = (executable as NSString).lastPathComponent
        var args = arguments[...]

        // Launchers hand over to the next program after their own options.
        if wrappers.contains(name) {
            skipWrapperOptions(name, &args)
            guard let next = args.first else { return EffectiveProgram(launchers: launchers, target: nil, kind: .none) }
            let rest = Array(args.dropFirst())
            if depth < 4, isLauncher(next) {
                return resolve(executable: next, arguments: rest, chain: launchers, depth: depth + 1)
            }
            return EffectiveProgram(launchers: launchers, target: next, kind: .binary)
        }

        // `open` starts an app or a document.
        if name == "open" {
            while let arg = args.first {
                args = args.dropFirst()
                if arg == "-a", let app = args.first { return EffectiveProgram(launchers: launchers, target: app, kind: .app) }
                if arg == "-b", let id = args.first { return EffectiveProgram(launchers: launchers, target: id, kind: .app) }
                if !arg.hasPrefix("-") { return EffectiveProgram(launchers: launchers, target: arg, kind: .app) }
            }
            return EffectiveProgram(launchers: launchers, target: nil, kind: .none)
        }

        // Interpreters: inline code, a module, or the first non-option argument is the script.
        let inlineFlags: Set<String>
        let valueFlags: Set<String>
        var moduleFlag: String?
        switch name {
        case _ where shells.contains(name):
            inlineFlags = ["-c"]; valueFlags = ["-o", "+o", "-O", "+O"]
        case _ where isPython(name):
            inlineFlags = ["-c"]; valueFlags = ["-W", "-X", "--check-hash-based-pycs"]; moduleFlag = "-m"
        case "perl":
            inlineFlags = ["-e", "-E"]; valueFlags = ["-I", "-M", "-m"]
        case "ruby":
            inlineFlags = ["-e"]; valueFlags = ["-I", "-r", "-C", "-E"]
        case "node":
            inlineFlags = ["-e", "--eval", "-p", "--print"]; valueFlags = ["-r", "--require", "--import"]
        case "osascript":
            inlineFlags = ["-e"]; valueFlags = ["-l", "-s"]
        case "php":
            inlineFlags = ["-r"]; valueFlags = ["-d", "-c"]
        default:
            inlineFlags = ["-e", "-c"]; valueFlags = []
        }
        var inline: [String] = []
        while let arg = args.first {
            args = args.dropFirst()
            if inlineFlags.contains(arg) {
                // osascript takes several -e lines; the others one.
                if let code = args.first { inline.append(code); args = args.dropFirst() }
                continue
            }
            if let moduleFlag, arg == moduleFlag, let module = args.first {
                return EffectiveProgram(launchers: launchers, target: module, kind: .module)
            }
            if valueFlags.contains(arg) { args = args.dropFirst(); continue }
            if arg == "--" {
                if let script = args.first { return EffectiveProgram(launchers: launchers, target: script, kind: .script) }
                break
            }
            if arg.hasPrefix("-") || (arg.hasPrefix("+") && shells.contains(name)) { continue }
            // With inline code, the next plain arguments are its $0/$1 — not a script.
            if !inline.isEmpty { break }
            return EffectiveProgram(launchers: launchers, target: arg, kind: .script)
        }
        if !inline.isEmpty {
            return EffectiveProgram(launchers: launchers, target: inline.joined(separator: "\n"), kind: .inline)
        }
        return EffectiveProgram(launchers: launchers, target: nil, kind: .none)
    }

    /// Drops a launcher's own options so the next argument is the program.
    private static func skipWrapperOptions(_ name: String, _ args: inout ArraySlice<String>) {
        while let arg = args.first {
            switch name {
            case "env":
                // env [-i] [-u name] [-P path] [-S string] [name=value …] program
                if arg == "-u" || arg == "-P" || arg == "-S" { args = args.dropFirst(2); continue }
                if arg.hasPrefix("-") || arg.contains("=") { args = args.dropFirst(); continue }
            case "arch":
                // arch [-arch name | -arm64 | -x86_64 …] [-e VAR=value] [-d VAR] [-c] program
                if arg == "-arch" || arg == "-e" || arg == "-d" { args = args.dropFirst(2); continue }
                if arg.hasPrefix("-") { args = args.dropFirst(); continue }
            case "nice":
                if arg == "-n" { args = args.dropFirst(2); continue }
                if arg.hasPrefix("-") { args = args.dropFirst(); continue }
            case "caffeinate":
                if arg == "-t" || arg == "-w" { args = args.dropFirst(2); continue }
                if arg.hasPrefix("-") { args = args.dropFirst(); continue }
            default:
                if arg.hasPrefix("-") { args = args.dropFirst(); continue }
            }
            return
        }
    }

    // MARK: - Inventory

    /// Records what each entry really runs, as metadata: `runs` (one-line
    /// summary), `runs-target` and `runs-kind`. Entries whose executable is
    /// the program itself get nothing.
    /// - Parameter items: The inventory, annotated in place.
    public static func annotate(_ items: inout [BackgroundItem]) {
        for index in items.indices {
            guard let program = resolve(executable: items[index].executable,
                                        arguments: items[index].arguments) else { continue }
            items[index].metadata["runs"] = program.summary
            items[index].metadata["runs-kind"] = program.kind.rawValue
            if let target = program.target { items[index].metadata["runs-target"] = target }
        }
    }
}
