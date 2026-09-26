import Foundation

// V0.8 — "remove the source, not the symptom". An installer package's bill
// of materials (`/var/db/receipts/<id>.bom`) records every path it wrote,
// with mode, size and a 32-bit CRC for files and the target for symlinks.
// That is the proof launchkeeper needs before it touches anything: a file
// that still matches its BOM entry is the package's, unchanged; a file that
// does not (edited, updated, replaced) is somebody's work and stays.

/// One line of `lsbom <bom>` (default format, tab separated):
///
///     ./Library/Printers/RWTS/PDFwriter/PDFfolder.png	100644	0/0	214230	1666348966
///     ./Applications/X.app/Contents/Frameworks/Y.framework/Y	120755	0/0	26	3488579006	Versions/Current/Y
///     ./Library/Printers	40775	0/0
public struct BOMEntry: Equatable, Sendable {
    public enum Kind: String, Codable, Sendable { case file, directory, symlink, other }

    /// Path relative to the install root, without the leading "./" ("" = the root).
    public var relativePath: String
    public var mode: UInt32
    public var kind: Kind
    public var size: UInt64?
    public var crc: UInt32?
    public var linkTarget: String?

    public init(relativePath: String, mode: UInt32, kind: Kind, size: UInt64? = nil, crc: UInt32? = nil,
                linkTarget: String? = nil) {
        self.relativePath = relativePath; self.mode = mode; self.kind = kind
        self.size = size; self.crc = crc; self.linkTarget = linkTarget
    }

    /// AppleDouble side files ("._x", size 0) are listed but never exist on APFS.
    public var isAppleDouble: Bool { (relativePath as NSString).lastPathComponent.hasPrefix("._") }
}

public enum BOMParser {
    public static func parse(_ text: String) -> (entries: [BOMEntry], warnings: [String]) {
        var entries: [BOMEntry] = []
        var warnings: [String] = []
        for line in text.components(separatedBy: "\n") where !line.isEmpty {
            let fields = line.components(separatedBy: "\t")
            guard fields.count >= 3, let mode = UInt32(fields[1], radix: 8) else {
                warnings.append("lsbom: unparsed line: \(line.prefix(120))")
                continue
            }
            var path = fields[0]
            if path == "." { path = "" } else if path.hasPrefix("./") { path.removeFirst(2) }
            let kind: BOMEntry.Kind
            switch mode & 0o170000 {
            case 0o100000: kind = .file
            case 0o040000: kind = .directory
            case 0o120000: kind = .symlink
            default: kind = .other
            }
            var entry = BOMEntry(relativePath: path, mode: mode, kind: kind)
            if kind == .file || kind == .symlink {
                guard fields.count >= 5, let size = UInt64(fields[3]), let crc = UInt32(fields[4]) else {
                    warnings.append("lsbom: \(kind.rawValue) without size/checksum: \(path)")
                    continue
                }
                entry.size = size
                entry.crc = crc
                if kind == .symlink { entry.linkTarget = fields.count >= 6 ? fields[5] : nil }
            }
            entries.append(entry)
        }
        return (entries, warnings)
    }
}

/// POSIX `cksum` CRC (polynomial 0x04C11DB7, MSB first, length appended,
/// complemented) — the checksum BOM files record. Streams the file in
/// chunks; nil when it cannot be read.
public enum POSIXChecksum {
    private static let table: [UInt32] = (0..<256).map { index -> UInt32 in
        var crc = UInt32(index) << 24
        for _ in 0..<8 { crc = (crc & 0x8000_0000) != 0 ? (crc << 1) ^ 0x04C1_1DB7 : crc << 1 }
        return crc
    }

    public static func checksum(_ data: Data) -> UInt32 {
        var state = State()
        state.update(data)
        return state.finish()
    }

    public static func checksum(fileAtPath path: String) -> UInt32? {
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? handle.close() }
        var state = State()
        do {
            // `read(upToCount:)` answers nil (or empty) at end of file; only
            // a thrown error means the file cannot be read.
            while let chunk = try handle.read(upToCount: 1 << 20), !chunk.isEmpty {
                state.update(chunk)
            }
        } catch {
            return nil
        }
        return state.finish()
    }

    struct State {
        var crc: UInt32 = 0
        var length: UInt64 = 0

        mutating func update(_ data: Data) {
            for byte in data {
                crc = (crc << 8) ^ POSIXChecksum.table[Int(((crc >> 24) ^ UInt32(byte)) & 0xff)]
            }
            length += UInt64(data.count)
        }

        func finish() -> UInt32 {
            var crc = self.crc
            var length = self.length
            while length > 0 {
                crc = (crc << 8) ^ POSIXChecksum.table[Int(((crc >> 24) ^ UInt32(length & 0xff)) & 0xff)]
                length >>= 8
            }
            return ~crc
        }
    }
}
