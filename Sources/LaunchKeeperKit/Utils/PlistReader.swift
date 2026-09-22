import Foundation

/// Plist reading via PropertyListSerialization — never string parsing.
public enum PlistReader {
    public enum ReadError: Error, Equatable {
        case unreadable
        case notAPropertyList
    }

    public static func readDictionary(fromFile path: String, fileManager: FileManager = .default) throws -> [String: Any] {
        guard let data = fileManager.contents(atPath: path), !data.isEmpty else {
            throw ReadError.unreadable
        }
        var format = PropertyListSerialization.PropertyListFormat.xml
        guard let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: &format),
              let dict = plist as? [String: Any] else {
            throw ReadError.notAPropertyList
        }
        return dict
    }

    /// Extracts the launchd-relevant subset; unknown keys are returned for preservation.
    public static func extractJob(dict: [String: Any]) -> (program: String?, arguments: [String], runAtLoad: Bool, keepAlive: Bool, unknownKeys: [String]) {
        var program: String?
        var arguments: [String] = []

        if let args = dict["ProgramArguments"] as? [String], let first = args.first {
            program = first
            arguments = Array(args.dropFirst())
        }
        if program == nil, let prog = dict["Program"] as? String {
            program = prog
        }
        // ProgramArgumentsFile style (rare) is ignored as a program source; recorded as unknown key.
        let known: Set<String> = [
            "Label", "Program", "ProgramArguments", "RunAtLoad", "KeepAlive",
            "UserName", "GroupName", "RootDirectory", "WorkingDirectory",
        ]
        let unknown = dict.keys.filter { !known.contains($0) }.sorted()
        return (program, arguments,
                (dict["RunAtLoad"] as? Bool) ?? false,
                dict["KeepAlive"] != nil,
                unknown)
    }
}