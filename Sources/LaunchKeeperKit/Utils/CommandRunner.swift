import Foundation

public struct CommandResult: Equatable {
    public let exitCode: Int32
    public let stdout: String
    public let stderr: String

    public init(exitCode: Int32, stdout: String, stderr: String) {
        self.exitCode = exitCode
        self.stdout = stdout
        self.stderr = stderr
    }
}

/// All external tools go through this seam so unit tests never shell out.
/// Security: argv arrays only — the tool never uses `shell = true`.
public protocol CommandRunner {
    func run(command: String, arguments: [String], timeout: TimeInterval) -> CommandResult
    /// Runs a command with INHERITED stdin/stdout/stderr (exit code only).
    /// Required for `sudo`: the password prompt goes to the tty, and a piped
    /// stderr swallows it — the prompt would hang or fail invisibly. Everything
    /// whose output must be parsed stays on `run`.
    func runInteractive(command: String, arguments: [String], timeout: TimeInterval) -> Int32
}

extension CommandRunner {
    public func run(command: String, arguments: [String]) -> CommandResult {
        run(command: command, arguments: arguments, timeout: 20)
    }
    /// Default: delegates to `run` so scripted test doubles key interactive
    /// calls by the same "command arg1 arg2 ..." scheme.
    public func runInteractive(command: String, arguments: [String], timeout: TimeInterval) -> Int32 {
        run(command: command, arguments: arguments, timeout: timeout).exitCode
    }
}

public final class SystemCommandRunner: CommandRunner {
    public init() {}

    public func run(command: String, arguments: [String], timeout: TimeInterval) -> CommandResult {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: command)
        process.arguments = arguments

        let outPipe = Pipe()
        let errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe

        do {
            try process.run()
        } catch {
            return CommandResult(exitCode: -1, stdout: "", stderr: "spawn failed: \(error.localizedDescription)")
        }

        // Read concurrently, then wait — avoids pipe-buffer deadlock on large output.
        // Each box is written by exactly one reader and read only after
        // `group.wait()` — the group sequences the access (hence @unchecked).
        final class DataBox: @unchecked Sendable { var data = Data() }
        let outBox = DataBox()
        let errBox = DataBox()
        let group = DispatchGroup()
        group.enter()
        DispatchQueue.global().async {
            outBox.data = outPipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }
        group.enter()
        DispatchQueue.global().async {
            errBox.data = errPipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }
        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning && Date() < deadline {
            usleep(20_000)
        }
        if process.isRunning {
            process.terminate()
            group.wait()
            return CommandResult(exitCode: -2, stdout: "", stderr: "timeout after \(timeout)s")
        }
        group.wait()
        process.waitUntilExit()

        return CommandResult(
            exitCode: process.terminationStatus,
            stdout: String(decoding: outBox.data, as: UTF8.self),
            stderr: String(decoding: errBox.data, as: UTF8.self)
        )
    }

    /// INHERITED stdio AND our process group: the child talks to the user's
    /// terminal directly, so `sudo` can show its password prompt.
    ///
    /// Why not `Process` here: Foundation spawns children into a NEW process
    /// group. On a terminal that makes the child a *background* job — its
    /// `tcsetattr` (echo off) and `read` on /dev/tty stop it with
    /// SIGTTOU/SIGTTIN, the line discipline keeps echoing, and the typed
    /// password shows up in clear text with nobody consuming it (seen live,
    /// fixed in V0.4.2). `posix_spawn` without POSIX_SPAWN_SETPGROUP keeps the
    /// child in the foreground group we already own; fds 0/1/2 are inherited.
    public func runInteractive(command: String, arguments: [String], timeout: TimeInterval) -> Int32 {
        var argv: [UnsafeMutablePointer<CChar>?] = ([command] + arguments).map { strdup($0) }
        argv.append(nil)
        var envp: [UnsafeMutablePointer<CChar>?] = ProcessInfo.processInfo.environment
            .map { strdup("\($0.key)=\($0.value)") }
        envp.append(nil)
        defer {
            argv.forEach { free($0) }
            envp.forEach { free($0) }
        }

        var pid: pid_t = 0
        let spawnError = posix_spawn(&pid, command, nil, nil, argv, envp)
        guard spawnError == 0 else {
            FileHandle.standardError.write(
                Data("spawn failed: \(String(cString: strerror(spawnError)))\n".utf8))
            return -1
        }

        let deadline = Date().addingTimeInterval(timeout)
        var status: Int32 = 0
        while true {
            let reaped = waitpid(pid, &status, WNOHANG)
            if reaped == pid { break }
            if reaped < 0 && errno != EINTR { return -1 }
            if Date() >= deadline {
                _ = kill(pid, SIGTERM)
                _ = waitpid(pid, &status, 0)
                return -2
            }
            usleep(20_000)
        }
        // WIFEXITED / WEXITSTATUS / WTERMSIG by hand — the macros are not imported.
        let signal = status & 0x7f
        return signal == 0 ? (status >> 8) & 0xff : 128 + signal
    }
}

/// Test double: canned outputs keyed by "command arg1 arg2 ...".
public struct ScriptedCommandRunner: CommandRunner {
    public var responses: [String: CommandResult]
    public var defaultResult: CommandResult

    public init(responses: [String: CommandResult] = [:],
                defaultResult: CommandResult = CommandResult(exitCode: 127, stdout: "", stderr: "not scripted")) {
        self.responses = responses
        self.defaultResult = defaultResult
    }

    public func run(command: String, arguments: [String], timeout: TimeInterval) -> CommandResult {
        let key = ([command] + arguments).joined(separator: " ")
        return responses[key] ?? defaultResult
    }
}