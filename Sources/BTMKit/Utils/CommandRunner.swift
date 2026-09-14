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
}

extension CommandRunner {
    public func run(command: String, arguments: [String]) -> CommandResult {
        run(command: command, arguments: arguments, timeout: 20)
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
        var outData = Data()
        var errData = Data()
        let group = DispatchGroup()
        group.enter()
        DispatchQueue.global().async {
            outData = outPipe.fileHandleForReading.readDataToEndOfFile()
            group.leave()
        }
        group.enter()
        DispatchQueue.global().async {
            errData = errPipe.fileHandleForReading.readDataToEndOfFile()
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
            stdout: String(decoding: outData, as: UTF8.self),
            stderr: String(decoding: errData, as: UTF8.self)
        )
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