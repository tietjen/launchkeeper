import Foundation
#if canImport(CoreServices)
import CoreServices
#endif

// V0.9 — FSEvents plumbing for `watch`: file-level events on the autostart
// locations, filtered by WatchPaths, handed to a callback on a serial queue.
// Read-only: the stream observes, it never touches a file.

public final class FileSystemTriggers: @unchecked Sendable {
    private let paths: WatchPaths
    private let queue: DispatchQueue
    private let onRelevant: (String) -> Void
    #if canImport(CoreServices)
    private var stream: FSEventStreamRef?
    #endif

    public init(paths: WatchPaths, queue: DispatchQueue, onRelevant: @escaping (String) -> Void) {
        self.paths = paths
        self.queue = queue
        self.onRelevant = onRelevant
    }

    /// false when FSEvents could not be started (the interval still runs).
    @discardableResult
    public func start(latency: TimeInterval = 2) -> Bool {
        #if canImport(CoreServices)
        let roots = paths.streamRoots.filter { FileManager.default.fileExists(atPath: $0) } as CFArray
        var context = FSEventStreamContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(),
                                           retain: nil, release: nil, copyDescription: nil)
        let callback: FSEventStreamCallback = { _, info, count, eventPaths, _, _ in
            guard let info else { return }
            let me = Unmanaged<FileSystemTriggers>.fromOpaque(info).takeUnretainedValue()
            guard let list = Unmanaged<CFArray>.fromOpaque(eventPaths).takeUnretainedValue() as? [String] else { return }
            for path in list.prefix(count) where me.paths.isRelevant(path) {
                me.onRelevant(path)
            }
        }
        let flags = UInt32(kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagUseCFTypes
                           | kFSEventStreamCreateFlagNoDefer)
        guard let created = FSEventStreamCreate(nil, callback, &context, roots,
                                                FSEventStreamEventId(kFSEventStreamEventIdSinceNow),
                                                latency, FSEventStreamCreateFlags(flags)) else { return false }
        FSEventStreamSetDispatchQueue(created, queue)
        guard FSEventStreamStart(created) else {
            FSEventStreamInvalidate(created)
            FSEventStreamRelease(created)
            return false
        }
        stream = created
        return true
        #else
        return false
        #endif
    }

    public func stop() {
        #if canImport(CoreServices)
        guard let stream else { return }
        FSEventStreamStop(stream)
        FSEventStreamInvalidate(stream)
        FSEventStreamRelease(stream)
        self.stream = nil
        #endif
    }

    deinit { stop() }
}
