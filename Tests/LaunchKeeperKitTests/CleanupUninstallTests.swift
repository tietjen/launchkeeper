import XCTest
@testable import LaunchKeeperKit

// V0.8.0: receipt-based uninstall into a quarantine. Hermetic: a temp tree
// plays "/", a fake installer answers pkgutil/lsbom and performs the sudo
// mkdir/mv/cp/rm for real inside that tree — so analysis, quarantine moves,
// verification and restore all run against actual file operations.

final class CleanupChecksumTests: XCTestCase {
    func testPOSIXChecksumMatchesCksumVectors() {
        // Vectors from /usr/bin/cksum on macOS 27.
        XCTAssertEqual(POSIXChecksum.checksum(Data()), 4_294_967_295)
        XCTAssertEqual(POSIXChecksum.checksum(Data("hello\n".utf8)), 3_015_617_425)
        XCTAssertEqual(POSIXChecksum.checksum(Data("123456789".utf8)), 930_766_865)
        XCTAssertEqual(POSIXChecksum.checksum(Data(repeating: UInt8(ascii: "a"), count: 100_000)), 614_267_494)
    }

    func testBOMLinesParse() {
        let text = """
        .\t40755\t0/0
        ./Library/Printers\t40775\t0/0
        ./Library/Printers/RWTS/PDFwriter/PDFfolder.png\t100644\t0/0\t214230\t1666348966
        ./Library/Printers/RWTS/PDFwriter/._PDFfolder.png\t100644\t0/0\t0\t0
        ./Applications/X.app/Contents/Frameworks/Y.framework/Y\t120755\t0/0\t26\t3488579006\tVersions/Current/Y
        garbage
        """
        let (entries, warnings) = BOMParser.parse(text)
        XCTAssertEqual(entries.count, 5)
        XCTAssertEqual(entries[0].relativePath, "")
        XCTAssertEqual(entries[1].kind, .directory)
        XCTAssertEqual(entries[2].kind, .file)
        XCTAssertEqual(entries[2].size, 214_230)
        XCTAssertEqual(entries[2].crc, 1_666_348_966)
        XCTAssertTrue(entries[3].isAppleDouble)
        XCTAssertEqual(entries[4].kind, .symlink)
        XCTAssertEqual(entries[4].linkTarget, "Versions/Current/Y")
        XCTAssertEqual(warnings.count, 1)
    }
}

/// pkgutil + lsbom twin; sudo mkdir/mv/cp/rm really run inside the temp root.
final class FakeInstaller: CommandRunner {
    struct Package {
        var id: String
        var bom: String
        var files: [String]
        var location = "/"
    }
    let root: String
    var packages: [String: Package] = [:]
    var failMoves = false
    /// Paths Apple's own receipts list (not in the non-Apple index).
    var appleClaims: Set<String> = []
    var sudoRefused = false
    private(set) var log: [String] = []
    let fm = FileManager.default

    init(root: String) { self.root = root }

    func install(_ package: Package) {
        packages[package.id] = package
        let receipts = root + "/var/db/receipts"
        try? fm.createDirectory(atPath: receipts, withIntermediateDirectories: true)
        fm.createFile(atPath: receipts + "/\(package.id).bom", contents: Data(package.bom.utf8))
        fm.createFile(atPath: receipts + "/\(package.id).plist", contents: Data("<plist/>".utf8))
    }

    private func known(_ id: String) -> Bool {
        packages[id] != nil && fm.fileExists(atPath: root + "/var/db/receipts/\(id).plist")
    }

    func run(command: String, arguments: [String], timeout: TimeInterval) -> CommandResult {
        log.append(([command] + arguments).joined(separator: " "))
        var command = command
        var args = arguments
        let ok = CommandResult(exitCode: 0, stdout: "", stderr: "")
        let fail = CommandResult(exitCode: 1, stdout: "", stderr: "failed")
        if command == "/usr/bin/sudo", args == ["-v"] { return sudoRefused ? fail : ok }
        if command == "/usr/bin/sudo", args.first == "-n" { args.removeFirst() }
        if command == "/usr/bin/sudo", let first = args.first { command = first; args.removeFirst() }
        switch (command, args.first) {
        case ("/usr/sbin/pkgutil", "--pkgs"):
            return CommandResult(exitCode: 0, stdout: packages.keys.filter(known).sorted().joined(separator: "\n") + "\n",
                                 stderr: "")
        case ("/usr/sbin/pkgutil", "--pkg-info-plist"):
            guard known(args[1]) else { return fail }
            return CommandResult(exitCode: 0, stdout: """
                <?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict>
                <key>pkg-version</key><string>1.0</string><key>install-time</key><integer>1780000000</integer>
                <key>volume</key><string>/</string><key>install-location</key><string>\(packages[args[1]]!.location)</string></dict></plist>
                """, stderr: "")
        case ("/usr/sbin/pkgutil", "--files"):
            guard known(args[1]) else { return fail }
            return CommandResult(exitCode: 0, stdout: packages[args[1]]!.files.joined(separator: "\n") + "\n", stderr: "")
        case ("/usr/sbin/pkgutil", "--file-info"):
            let relative = String(args[1].dropFirst())
            var out = "volume: /\npath: \(args[1])\n"
            for package in packages.values.sorted(by: { $0.id < $1.id }) where package.files.contains(relative) {
                out += "\npkgid: \(package.id)\npkg-version: 1.0\n"
            }
            if appleClaims.contains(args[1]) { out += "\npkgid: com.apple.files.data-template\n" }
            return CommandResult(exitCode: 0, stdout: out, stderr: "")
        case ("/usr/bin/cksum", _):
            guard args.first == "--" else { return fail }
            var out = ""
            for path in args.dropFirst() {
                // "root" can read what the test user cannot.
                let mode = (try? fm.attributesOfItem(atPath: path))?[.posixPermissions] as? Int ?? 0o644
                try? fm.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path)
                let data = fm.contents(atPath: path) ?? Data()
                try? fm.setAttributes([.posixPermissions: mode], ofItemAtPath: path)
                out += "\(POSIXChecksum.checksum(data)) \(data.count) \(path)\n"
            }
            return CommandResult(exitCode: 0, stdout: out, stderr: "")
        case ("/usr/sbin/pkgutil", "--pkg-info"):
            return known(args[1]) ? ok : fail
        case ("/usr/sbin/pkgutil", "--forget"):
            guard known(args[1]) else { return fail }
            try? fm.removeItem(atPath: root + "/var/db/receipts/\(args[1]).plist")
            try? fm.removeItem(atPath: root + "/var/db/receipts/\(args[1]).bom")
            return ok
        case ("/usr/bin/lsbom", _):
            guard let path = args.first, fm.fileExists(atPath: path),
                  let package = packages.values.first(where: { path.hasSuffix("/\($0.id).bom") }) else { return fail }
            return CommandResult(exitCode: 0, stdout: package.bom, stderr: "")
        case ("/bin/mkdir", _):
            guard args.count == 3, args[0] == "-p", args[1] == "--" else { return fail }
            return (try? fm.createDirectory(atPath: args[2], withIntermediateDirectories: true)) != nil ? ok : fail
        case ("/bin/mv", _):
            guard !failMoves, args.first == "--", args.count >= 3 else { return fail }
            let destination = args.last!
            for source in args.dropFirst().dropLast() {
                let target = destination.hasSuffix("/")
                    ? destination + (source as NSString).lastPathComponent : destination
                guard (try? fm.moveItem(atPath: source, toPath: target)) != nil else { return fail }
            }
            return ok
        case ("/bin/cp", _):
            guard args.count == 4, args[0] == "-p", args[1] == "--" else { return fail }
            return (try? fm.copyItem(atPath: args[2], toPath: args[3])) != nil ? ok : fail
        case ("/bin/rm", _):
            guard args.count == 3, args[0] == "-rf", args[1] == "--" else { return fail }
            try? fm.removeItem(atPath: args[2])
            return ok
        default:
            return CommandResult(exitCode: 127, stdout: "", stderr: "not modeled")
        }
    }

    var mutations: [String] { log.filter { $0.hasPrefix("/usr/bin/sudo") } }
}

final class CleanupUninstallTests: XCTestCase {
    private var root = ""
    private var home = ""

    override func setUpWithError() throws {
        let base = FileManager.default.temporaryDirectory
            .appendingPathComponent("lk-uninstall-\(UUID().uuidString)", isDirectory: true).path
        root = base + "/root"
        home = base + "/home"
        try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(atPath: home, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(atPath: (root as NSString).deletingLastPathComponent)
    }

    // MARK: fixture helpers

    private func write(_ path: String, _ content: String) {
        let full = root + path
        try? FileManager.default.createDirectory(atPath: (full as NSString).deletingLastPathComponent,
                                                 withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: full, contents: Data(content.utf8))
    }

    private func mkdir(_ path: String) {
        try? FileManager.default.createDirectory(atPath: root + path, withIntermediateDirectories: true)
    }

    /// BOM lines for the tree as it is NOW (so it reads as "intact").
    private func bom(dirs: [String], files: [String], links: [(String, String)] = [],
                     phantomFiles: [String] = []) -> (text: String, files: [String]) {
        var lines = [".\t40755\t0/0"]
        for dir in dirs { lines.append(".\(dir)\t40755\t0/0") }
        for file in files {
            let data = FileManager.default.contents(atPath: root + file) ?? Data()
            lines.append(".\(file)\t100644\t0/0\t\(data.count)\t\(POSIXChecksum.checksum(data))")
        }
        for file in phantomFiles { lines.append(".\(file)\t100644\t0/0\t3\t123") }
        for (link, target) in links {
            lines.append(".\(link)\t120755\t0/0\t\(target.utf8.count)\t\(POSIXChecksum.checksum(Data(target.utf8)))\t\(target)")
        }
        let listed = (dirs + files + phantomFiles + links.map(\.0)).map { String($0.dropFirst()) }
        return (lines.joined(separator: "\n") + "\n", listed)
    }

    private func engine(_ runner: FakeInstaller) -> CleanupEngine {
        CleanupEngine(environment: CleanupEnvironment(runner: runner, disk: DiskView(rootPrefix: root), home: home,
                                                      quarantineRoot: home + "/quarantine"),
                      audit: AuditLog(directory: home + "/logs"))
    }

    private func exists(_ path: String) -> Bool {
        (try? FileManager.default.attributesOfItem(atPath: root + path)) != nil
    }

    /// Tool.app intact, a support dir with one edited file, a daemon plist,
    /// a /usr/local/bin link, one /System path the BOM claims.
    private func toolPackage(_ fake: FakeInstaller) {
        write("/Applications/Tool.app/Contents/Info.plist", "<plist/>")
        write("/Applications/Tool.app/Contents/MacOS/tool", "binary")
        write("/Library/Application Support/Tool/data.bin", "data")
        write("/Library/Application Support/Tool/config.json", "{}")
        write("/Library/LaunchDaemons/com.vendor.tool.plist", "<plist/>")
        write("/System/Library/Extensions/evil.txt", "x")
        mkdir("/usr/local/bin")
        try? FileManager.default.createSymbolicLink(atPath: root + "/usr/local/bin/tool",
                                                    withDestinationPath: "/Applications/Tool.app/Contents/MacOS/tool")
        let b = bom(dirs: ["/Applications", "/Applications/Tool.app", "/Applications/Tool.app/Contents",
                           "/Applications/Tool.app/Contents/MacOS", "/Library", "/Library/Application Support",
                           "/Library/Application Support/Tool", "/Library/LaunchDaemons", "/usr", "/usr/local",
                           "/usr/local/bin"],
                    files: ["/Applications/Tool.app/Contents/Info.plist", "/Applications/Tool.app/Contents/MacOS/tool",
                            "/Library/Application Support/Tool/data.bin", "/Library/Application Support/Tool/config.json",
                            "/Library/LaunchDaemons/com.vendor.tool.plist", "/System/Library/Extensions/evil.txt"],
                    links: [("/usr/local/bin/tool", "/Applications/Tool.app/Contents/MacOS/tool")])
        fake.install(.init(id: "com.vendor.tool", bom: b.text, files: b.files))
        // The user edits the config after installing.
        write("/Library/Application Support/Tool/config.json", "{\"mine\": true}")
    }

    // MARK: tests

    func testAnalysisMovesOnlyProvenUnchangedExclusiveContent() throws {
        let fake = FakeInstaller(root: root)
        toolPackage(fake)
        let result = engine(fake).uninstall(packageIdentifier: "com.vendor.tool", apply: false)
        XCTAssertEqual(result.status, .planned, "\(result.messages)")
        let analysis = try XCTUnwrap(result.analysis)
        XCTAssertEqual(analysis.moveRoots, [
            "/Applications/Tool.app",                          // whole bundle, one move
            "/Library/Application Support/Tool/data.bin",     // the dir keeps the edited config
            "/Library/LaunchDaemons/com.vendor.tool.plist",
            "/usr/local/bin/tool",
        ])
        func status(_ path: String) -> String? { analysis.paths.first { $0.path == path }?.status.label }
        XCTAssertEqual(status("/Library/Application Support/Tool/config.json"), "modified")
        XCTAssertEqual(status("/Library/Application Support/Tool"), "foreign-content")
        XCTAssertEqual(status("/Applications"), "shared")
        XCTAssertEqual(status("/Library/LaunchDaemons"), "shared")
        XCTAssertEqual(status("/System/Library/Extensions/evil.txt"), "protected")
        XCTAssertFalse(analysis.canForget, "an edited file stays — so does the receipt")
        XCTAssertFalse(result.plan.contains { $0.arguments.contains("--forget") })
        XCTAssertTrue(fake.mutations.isEmpty, "dry-run")
        XCTAssertFalse(FileManager.default.fileExists(atPath: home + "/quarantine"))
    }

    func testApplyMovesIntoQuarantineAndRestorePutsEverythingBack() throws {
        let fake = FakeInstaller(root: root)
        toolPackage(fake)
        let result = engine(fake).uninstall(packageIdentifier: "com.vendor.tool", apply: true)
        XCTAssertEqual(result.status, .appliedOk, "\(result.messages)")
        let name = try XCTUnwrap(result.quarantine)
        XCTAssertFalse(exists("/Applications/Tool.app"))
        XCTAssertFalse(exists("/usr/local/bin/tool"))
        XCTAssertTrue(exists("/Library/Application Support/Tool/config.json"), "the edited file stays")
        XCTAssertTrue(exists("/System/Library/Extensions/evil.txt"), "protected territory stays")
        XCTAssertTrue(FileManager.default.fileExists(
            atPath: home + "/quarantine/\(name)/files/Applications/Tool.app/Contents/MacOS/tool"))
        let manifest = try XCTUnwrap(QuarantineStore(root: home + "/quarantine").load(name))
        XCTAssertEqual(manifest.status, "applied-ok")
        XCTAssertEqual(manifest.moves.count, 4)
        XCTAssertFalse(manifest.forgot)
        XCTAssertEqual(result.undoHint, "launchkeeper quarantine restore \(name)")
        XCTAssertTrue(fake.mutations.allSatisfy { $0.contains(" -- ") }, "every path behind --: \(fake.mutations)")

        let back = engine(fake).restore(name: name, apply: true)
        XCTAssertEqual(back.status, .appliedOk, "\(back.messages)")
        XCTAssertTrue(exists("/Applications/Tool.app/Contents/MacOS/tool"))
        XCTAssertEqual(try FileManager.default.destinationOfSymbolicLink(atPath: root + "/usr/local/bin/tool"),
                       "/Applications/Tool.app/Contents/MacOS/tool", "links come back as links")
        XCTAssertEqual(QuarantineStore(root: home + "/quarantine").load(name)?.status, "restored")
    }

    func testLeftoverReceiptIsForgottenWithACopyAndRestoredOnDemand() throws {
        let fake = FakeInstaller(root: root)
        mkdir("/Library/Gone/Resources")
        let b = bom(dirs: ["/Library", "/Library/Gone", "/Library/Gone/Resources"], files: [],
                    phantomFiles: ["/Library/Gone/Resources/a.txt", "/Applications/Gone.app/Contents/Info.plist"])
        fake.install(.init(id: "com.vendor.gone", bom: b.text, files: b.files))

        let result = engine(fake).uninstall(packageIdentifier: "com.vendor.gone", apply: true)
        XCTAssertEqual(result.status, .appliedOk, "\(result.messages)")
        // /Library/Gone is two levels deep — never moved, only named.
        XCTAssertEqual(result.analysis?.moveRoots, ["/Library/Gone/Resources"])
        XCTAssertTrue(result.messages.contains { $0.contains("/Library/Gone stays (empty afterwards)") },
                      "\(result.messages)")
        XCTAssertEqual(result.analysis?.count("missing"), 2)
        XCTAssertTrue(result.plan.last?.arguments.contains("--forget") == true)
        XCTAssertFalse(exists("/var/db/receipts/com.vendor.gone.plist"))
        let name = try XCTUnwrap(result.quarantine)
        let manifest = try XCTUnwrap(QuarantineStore(root: home + "/quarantine").load(name))
        XCTAssertTrue(manifest.forgot)
        XCTAssertEqual(manifest.receiptCopies.count, 2)

        let back = engine(fake).restore(name: name, apply: true)
        XCTAssertEqual(back.status, .appliedOk, "\(back.messages)")
        XCTAssertTrue(exists("/var/db/receipts/com.vendor.gone.plist"), "the receipt is known again")
        XCTAssertTrue(exists("/Library/Gone/Resources"))
        XCTAssertTrue(exists("/Library/Gone"))
    }

    func testPathsListedByAnotherReceiptNeverMove() throws {
        let fake = FakeInstaller(root: root)
        write("/Library/Vendor/Common/lib.dylib", "lib")
        write("/Library/Vendor/One/one.txt", "1")
        let one = bom(dirs: ["/Library", "/Library/Vendor", "/Library/Vendor/Common", "/Library/Vendor/One"],
                      files: ["/Library/Vendor/Common/lib.dylib", "/Library/Vendor/One/one.txt"])
        let two = bom(dirs: ["/Library", "/Library/Vendor", "/Library/Vendor/Common"],
                      files: ["/Library/Vendor/Common/lib.dylib"])
        fake.install(.init(id: "com.vendor.one", bom: one.text, files: one.files))
        fake.install(.init(id: "com.vendor.two", bom: two.text, files: two.files))
        let result = engine(fake).uninstall(packageIdentifier: "com.vendor.one", apply: false)
        let analysis = try XCTUnwrap(result.analysis)
        XCTAssertEqual(analysis.moveRoots, ["/Library/Vendor/One"])
        XCTAssertEqual(analysis.paths.first { $0.path == "/Library/Vendor/Common/lib.dylib" }?.status, .shared)
        XCTAssertEqual(analysis.paths.first { $0.path == "/Library/Vendor" }?.status.label, "shared")
    }

    func testSymlinkedParentIsNeverFollowed() throws {
        let fake = FakeInstaller(root: root)
        write("/Elsewhere/Real/file.txt", "x")
        mkdir("/Library")
        try FileManager.default.createSymbolicLink(atPath: root + "/Library/Linked", withDestinationPath: root + "/Elsewhere/Real")
        let data = Data("x".utf8)
        let text = ".\t40755\t0/0\n./Library/Linked/file.txt\t100644\t0/0\t1\t\(POSIXChecksum.checksum(data))\n"
        fake.install(.init(id: "com.vendor.link", bom: text, files: ["Library/Linked/file.txt"]))
        let result = engine(fake).uninstall(packageIdentifier: "com.vendor.link", apply: false)
        guard case .refused = result.status else { return XCTFail("\(result.status) \(result.messages)") }
        XCTAssertEqual(result.analysis?.paths.first?.status.label, "protected")
    }

    func testGateRefusesAppleFragmentsAndUnknownPackages() {
        let fake = FakeInstaller(root: root)
        for bad in ["com.apple.pkg.Core", "Tool", "-rf", "../x", "a b"] {
            let result = engine(fake).uninstall(packageIdentifier: bad, apply: true)
            guard case .refused = result.status else { return XCTFail("\(bad): \(result.status)") }
        }
        XCTAssertTrue(fake.mutations.isEmpty)
        XCTAssertTrue(CleanupEngine(environment: CleanupEnvironment(runner: fake, disk: DiskView(rootPrefix: root),
                                                                    home: home, quarantineRoot: home + "/q"),
                                    audit: AuditLog(directory: home + "/logs"))
            .audit.readAll().contains("uninstall pkg:com.apple.pkg.Core refused("))
    }

    func testFailedMoveIsReportedAndLeavesARestorableManifest() throws {
        let fake = FakeInstaller(root: root)
        toolPackage(fake)
        fake.failMoves = true
        let result = engine(fake).uninstall(packageIdentifier: "com.vendor.tool", apply: true)
        guard case .appliedFailed = result.status else { return XCTFail("\(result.status)") }
        let name = try XCTUnwrap(result.quarantine)
        XCTAssertTrue(QuarantineStore(root: home + "/quarantine").load(name)?.status.hasPrefix("applied-fail") == true)
        XCTAssertTrue(exists("/Applications/Tool.app"), "nothing was moved")
    }

    func testPurgeDeletesOnlyInsideTheQuarantine() throws {
        let fake = FakeInstaller(root: root)
        toolPackage(fake)
        let result = engine(fake).uninstall(packageIdentifier: "com.vendor.tool", apply: true)
        let name = try XCTUnwrap(result.quarantine)
        let dry = engine(fake).purge(name: name, apply: false)
        XCTAssertEqual(dry.status, .planned)
        XCTAssertTrue(dry.plan[0].description.contains("NOT restorable"))
        XCTAssertTrue(FileManager.default.fileExists(atPath: home + "/quarantine/\(name)"))

        for bad in ["..", "../home", "/etc", ""] {
            guard case .refused = engine(fake).purge(name: bad, apply: true).status else { return XCTFail(bad) }
        }
        let done = engine(fake).purge(name: name, apply: true)
        XCTAssertEqual(done.status, .appliedOk, "\(done.messages)")
        XCTAssertFalse(FileManager.default.fileExists(atPath: home + "/quarantine/\(name)"))
        XCTAssertTrue(exists("/Library/Application Support/Tool/config.json"), "purge never touches the live tree")
    }

    func testRestoreNeverOverwritesSomethingNewAtTheOriginalPlace() throws {
        let fake = FakeInstaller(root: root)
        toolPackage(fake)
        let name = try XCTUnwrap(engine(fake).uninstall(packageIdentifier: "com.vendor.tool", apply: true).quarantine)
        write("/Library/LaunchDaemons/com.vendor.tool.plist", "<plist>new</plist>")
        let back = engine(fake).restore(name: name, apply: true)
        XCTAssertEqual(back.status, .appliedOk, "\(back.messages)")
        XCTAssertTrue(back.messages.contains { $0.contains("never overwritten") })
        XCTAssertEqual(String(data: FileManager.default.contents(atPath: root + "/Library/LaunchDaemons/com.vendor.tool.plist")!,
                              encoding: .utf8), "<plist>new</plist>")
    }

    // MARK: live findings 2026-09-26

    func testADirectoryAppleAlsoListsNeverMovesWhole() throws {
        // /Library/Printers/PPDs held only the vendor's PPD — but Apple's
        // data template lists the folder. The non-Apple index cannot know.
        let fake = FakeInstaller(root: root)
        write("/Library/Printers/PPDs/Contents/Resources/Vendor.gz", "ppd")
        write("/Library/Printers/Vendor/icon.png", "png")
        let b = bom(dirs: ["/Library", "/Library/Printers", "/Library/Printers/PPDs", "/Library/Printers/PPDs/Contents",
                           "/Library/Printers/PPDs/Contents/Resources", "/Library/Printers/Vendor"],
                    files: ["/Library/Printers/PPDs/Contents/Resources/Vendor.gz", "/Library/Printers/Vendor/icon.png"])
        fake.install(.init(id: "com.vendor.printer", bom: b.text, files: b.files))
        fake.appleClaims = ["/Library/Printers/PPDs", "/Library/Printers/PPDs/Contents",
                            "/Library/Printers/PPDs/Contents/Resources"]
        let analysis = try XCTUnwrap(engine(fake).uninstall(packageIdentifier: "com.vendor.printer", apply: false).analysis)
        XCTAssertEqual(analysis.moveRoots, ["/Library/Printers/PPDs/Contents/Resources/Vendor.gz", "/Library/Printers/Vendor"])
        XCTAssertEqual(analysis.paths.first { $0.path == "/Library/Printers/PPDs" }?.status, .shared)
    }

    func testRootOnlyFilesStayUnprovenUntilVerifiedAsRoot() throws {
        let fake = FakeInstaller(root: root)
        write("/Library/Printers/Vendor/tool", "secret")
        write("/Library/Printers/Vendor/icon.png", "png")
        let b = bom(dirs: ["/Library", "/Library/Printers", "/Library/Printers/Vendor"],
                    files: ["/Library/Printers/Vendor/tool", "/Library/Printers/Vendor/icon.png"])
        fake.install(.init(id: "com.vendor.printer", bom: b.text, files: b.files))
        try FileManager.default.setAttributes([.posixPermissions: 0o000], ofItemAtPath: root + "/Library/Printers/Vendor/tool")
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o644],
                                                        ofItemAtPath: root + "/Library/Printers/Vendor/tool") }

        let dry = engine(fake).uninstall(packageIdentifier: "com.vendor.printer", apply: false)
        let plain = try XCTUnwrap(dry.analysis)
        XCTAssertEqual(plain.paths.first { $0.path == "/Library/Printers/Vendor/tool" }?.status, .unreadable)
        XCTAssertEqual(plain.moveRoots, ["/Library/Printers/Vendor/icon.png"], "unproven keeps the folder")
        XCTAssertFalse(plain.canForget)
        XCTAssertFalse(fake.log.contains("/usr/bin/sudo -v"), "a plain dry-run never asks for a password")

        let proven = try XCTUnwrap(engine(fake).uninstall(packageIdentifier: "com.vendor.printer", apply: false,
                                                          verifyAsRoot: true).analysis)
        XCTAssertEqual(proven.moveRoots, ["/Library/Printers/Vendor"])
        XCTAssertTrue(proven.canForget)
        XCTAssertTrue(fake.mutations.allSatisfy { $0.hasPrefix("/usr/bin/sudo -v") || $0.contains("cksum") },
                      "verifying reads only: \(fake.mutations)")

        fake.sudoRefused = true
        guard case .refused = engine(fake).uninstall(packageIdentifier: "com.vendor.printer", apply: true).status else {
            return XCTFail("no root proof, no apply")
        }
    }

    func testABundleThatChangedSinceInstallStaysWhole() throws {
        let fake = FakeInstaller(root: root)
        write("/Applications/Self.app/Contents/Info.plist", "<plist/>")
        write("/Applications/Self.app/Contents/MacOS/self", "v1")
        write("/Applications/Self.app/Contents/Frameworks/Qt.framework/Qt", "qt")
        write("/Library/LaunchAgents/com.vendor.self.plist", "<plist/>")
        let b = bom(dirs: ["/Applications", "/Applications/Self.app", "/Applications/Self.app/Contents",
                           "/Applications/Self.app/Contents/MacOS", "/Applications/Self.app/Contents/Frameworks",
                           "/Applications/Self.app/Contents/Frameworks/Qt.framework", "/Library", "/Library/LaunchAgents"],
                    files: ["/Applications/Self.app/Contents/Info.plist", "/Applications/Self.app/Contents/MacOS/self",
                            "/Applications/Self.app/Contents/Frameworks/Qt.framework/Qt",
                            "/Library/LaunchAgents/com.vendor.self.plist"])
        fake.install(.init(id: "com.vendor.self", bom: b.text, files: b.files))
        write("/Applications/Self.app/Contents/MacOS/self", "v2 — self-updated")   // Sparkle was here

        let result = engine(fake).uninstall(packageIdentifier: "com.vendor.self", apply: false)
        let analysis = try XCTUnwrap(result.analysis)
        XCTAssertEqual(analysis.moveRoots, ["/Library/LaunchAgents/com.vendor.self.plist"],
                       "nothing is taken out of the changed bundle")
        XCTAssertEqual(analysis.paths.first { $0.path == "/Applications/Self.app/Contents/Frameworks/Qt.framework/Qt" }?
            .status.label, "kept-with-bundle")
        XCTAssertEqual(result.messages.filter { $0.contains("bundles move whole or not at all") }.count, 1,
                       "one note for the outermost bundle: \(result.messages)")
        XCTAssertFalse(analysis.canForget)
    }

    func testThePackagesOwnInstallLocationMovesToo() throws {
        // com.oracle.jdk-27 installs INTO jdk-27.jdk: the BOM root "." is
        // that bundle — without it, an empty .jdk shell was left behind.
        let fake = FakeInstaller(root: root)
        write("/Library/Java/JavaVirtualMachines/tool.jdk/Contents/Info.plist", "<plist/>")
        let lines = ".\t40755\t0/0\n./Contents\t40755\t0/0\n./Contents/Info.plist\t100644\t0/0\t8\t"
            + "\(POSIXChecksum.checksum(Data("<plist/>".utf8)))\n"
        fake.install(.init(id: "com.vendor.jdk", bom: lines, files: ["Contents", "Contents/Info.plist"],
                           location: "/Library/Java/JavaVirtualMachines/tool.jdk"))
        let analysis = try XCTUnwrap(engine(fake).uninstall(packageIdentifier: "com.vendor.jdk", apply: false).analysis)
        XCTAssertEqual(analysis.moveRoots, ["/Library/Java/JavaVirtualMachines/tool.jdk"])
        XCTAssertTrue(analysis.canForget)
    }
}
