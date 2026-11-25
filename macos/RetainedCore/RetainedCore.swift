import CirrusRetained
import Darwin
import Foundation

enum RetainedError: Error {
    case invalidABI, cancelled, unavailable, stale, capacity, internalFailure, pageExpired, anchorExpired, signInFinishing, retainedSpaceNotReady
    case mutationPending, mutationConflict, mutationUncertain, mutationUnsupported
    case confirmedDeleted
}

func checked(_ status: Int32) throws {
    switch status {
    case Int32(CIRRUS_OK): return
    case Int32(CIRRUS_INVALID_ABI): throw RetainedError.invalidABI
    case Int32(CIRRUS_CANCELLED): throw RetainedError.cancelled
    case Int32(CIRRUS_STALE): throw RetainedError.stale
    case Int32(CIRRUS_CAPACITY): throw RetainedError.capacity
    case Int32(CIRRUS_INTERNAL): throw RetainedError.internalFailure
    case Int32(CIRRUS_PAGE_EXPIRED): throw RetainedError.pageExpired
    case Int32(CIRRUS_ANCHOR_EXPIRED): throw RetainedError.anchorExpired
    case Int32(CIRRUS_SIGNIN_FINISHING): throw RetainedError.signInFinishing
    case Int32(CIRRUS_RETAINED_SPACE_NOT_READY): throw RetainedError.retainedSpaceNotReady
    case Int32(CIRRUS_MUTATION_PENDING): throw RetainedError.mutationPending
    case Int32(CIRRUS_MUTATION_CONFLICT): throw RetainedError.mutationConflict
    case Int32(CIRRUS_MUTATION_UNCERTAIN): throw RetainedError.mutationUncertain
    case Int32(CIRRUS_MUTATION_UNSUPPORTED): throw RetainedError.mutationUnsupported
    case Int32(CIRRUS_CONFIRMED_DELETED): throw RetainedError.confirmedDeleted
    default: throw RetainedError.unavailable
    }
}

func withRetainedText<T>(_ string: String, _ body: (CirrusRetainedText) throws -> T) rethrows -> T {
    try Array(string.utf8).withUnsafeBufferPointer {
        try body(CirrusRetainedText(data: $0.baseAddress, len: $0.count))
    }
}

// Deliberately synchronous, non-Sendable, no actor/Dispatch scheduler: a serial
// queue does not promise OS-thread affinity. Callers dedicate one OS thread.
class RetainedHandle {
    let raw: UnsafeMutableRawPointer
    private let owner = pthread_self()
    init(taking raw: UnsafeMutableRawPointer) { self.raw = raw }
    func onOwnerThread() {
        precondition(pthread_equal(owner, pthread_self()) != 0, "retained handle moved OS threads")
    }
    func readJSON<T: Decodable>(
        minimumWritten: Int = 0,
        _ call: (UnsafeMutablePointer<UInt8>?, Int, UnsafeMutablePointer<Int>) -> Int32
    ) throws -> T {
        onOwnerThread()
        var bytes = [UInt8](repeating: 0, count: Int(CIRRUS_RETAINED_PAGE_BYTES))
        var written = 0
        try bytes.withUnsafeMutableBufferPointer { buffer in
            try checked(call(buffer.baseAddress, buffer.count, &written))
        }
        guard written >= minimumWritten, written <= bytes.count else {
            throw RetainedError.internalFailure
        }
        return try JSONDecoder().decode(T.self, from: Data(bytes.prefix(written)))
    }
    deinit {
        onOwnerThread()
        precondition(cirrus_retained_close(raw) == Int32(CIRRUS_OK), "invalid retained handle close")
    }
}

final class RetainedRequest: RetainedHandle {
    convenience init() throws {
        var raw: UnsafeMutableRawPointer?
        try checked(cirrus_retained_request(&raw))
        guard let raw else { throw RetainedError.internalFailure }
        self.init(taking: raw)
    }
    // C supports concurrent cancellation while the owner keeps this object live.
    // The Swift wrapper is not Sendable; do not transfer its lifetime to a Task.
    func cancel() throws { try checked(cirrus_retained_cancel(raw)) }
}

struct DispatcherObservation: Decodable, Sendable {
    struct Status: Decodable, Sendable {
        let phase: String
        let queued: UInt64
        let conflicts: UInt64
        let uncertain: UInt64
        let cause: String?
    }
    let status: Status?
    let domains: [String]
}
final class RetainedDispatcher: RetainedHandle {
    convenience init(owner: RetainedHandle) throws {
        owner.onOwnerThread()
        var raw: UnsafeMutableRawPointer?
        try checked(cirrus_dispatcher_open(owner.raw, &raw))
        guard let raw else { throw RetainedError.internalFailure }
        self.init(taking: raw)
    }
    func turn() throws -> DispatcherObservation {
        try readJSON(minimumWritten: 1) { buffer, capacity, written in
            cirrus_dispatcher_turn(raw, buffer, capacity, written)
        }
    }
}

final class RetainedCore: RetainedHandle {
    convenience init(appGroup: String, keychainAccessGroup: String) throws {
        var raw: UnsafeMutableRawPointer?
        try withRetainedText(appGroup) { group in
            try withRetainedText(keychainAccessGroup) {
                try checked(cirrus_retained_open(group, $0, &raw))
            }
        }
        guard let raw else { throw RetainedError.internalFailure }
        self.init(taking: raw)
    }
}

private func physicalDirectory(_ url: URL) throws -> Int32 {
    guard url.isFileURL, url.path.hasPrefix("/") else { throw RetainedError.invalidABI }
    var fd = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    guard fd >= 0 else { throw RetainedError.unavailable }
    do {
        for component in url.pathComponents where component != "/" {
            guard component != ".", component != "..", !component.contains("\0") else {
                throw RetainedError.invalidABI
            }
            let child = openat(fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard child >= 0 else { throw RetainedError.unavailable }
            close(fd)
            fd = child
        }
        return fd
    } catch { close(fd); throw error }
}

struct RetainedOutput: Sendable {
    let url: URL
    fileprivate let device: dev_t
    fileprivate let inode: ino_t

    // Only a completed download owned by this request may be unwound. A changed
    // name/inode is left untouched; the trusted-directory race limits are the
    // same as candidate cleanup below, not a hostile same-UID guarantee.
    func removeIfOwned() {
        guard let parent = try? physicalDirectory(url.deletingLastPathComponent()) else { return }
        defer { close(parent) }
        var named = stat()
        if fstatat(parent, url.lastPathComponent, &named, AT_SYMLINK_NOFOLLOW) == 0,
           named.st_dev == device, named.st_ino == inode,
           named.st_uid == geteuid(), named.st_mode == mode_t(S_IFREG | 0o600),
           named.st_nlink == 1 {
            _ = unlinkat(parent, url.lastPathComponent, 0)
            _ = fsync(parent)
        }
    }
}

final class RetainedVersion: RetainedHandle {
    // Destination is a caller-owned trusted directory. Only the new private
    // candidate is cleaned on failure, never an existing/published destination.
    // A post-rename directory fsync failure reports unavailable but leaves the
    // published file intact. Cancellation is cooperative, not atomic with rename.
    func materialize(in directory: URL, name: String, request: RetainedRequest) throws {
        _ = try materializeOwned(in: directory, name: name, request: request)
    }
    func materializeOwned(in directory: URL, name: String, request: RetainedRequest) throws -> RetainedOutput {
        onOwnerThread()
        guard !name.isEmpty, name != ".", name != "..", !name.contains("/"),
              !name.contains("\0") else { throw RetainedError.invalidABI }
        let parent = try physicalDirectory(directory)
        defer { close(parent) }
        let temporary = ".cirrus-retained-\(UUID().uuidString)"
        let fd = openat(parent, temporary, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw RetainedError.unavailable }
        defer { close(fd) }
        var original = stat()
        guard fstat(fd, &original) == 0 else { throw RetainedError.unavailable }
        var published = false
        func ownedCandidate() -> Bool {
            var held = stat()
            var named = stat()
            return fstat(fd, &held) == 0 &&
                fstatat(parent, temporary, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
                held.st_dev == original.st_dev && held.st_ino == original.st_ino &&
                named.st_dev == held.st_dev && named.st_ino == held.st_ino &&
                held.st_uid == geteuid() && held.st_mode == mode_t(S_IFREG | 0o600) &&
                held.st_nlink == 1 && named.st_nlink == 1
        }
        defer {
            if !published && ownedCandidate() { _ = unlinkat(parent, temporary, 0); _ = fsync(parent) }
        }
        try checked(cirrus_retained_materialize(raw, fd, request.raw))
        try checked(cirrus_retained_verify(raw, request.raw))
        guard ownedCandidate() else { throw RetainedError.unavailable }
        guard renameatx_np(parent, temporary, parent, name, UInt32(RENAME_EXCL)) == 0 else {
            if errno == ENOSPC || errno == EDQUOT { throw RetainedError.capacity }
            throw RetainedError.unavailable
        }
        published = true
        guard fsync(parent) == 0 else { throw RetainedError.unavailable }
        return RetainedOutput(url: directory.appendingPathComponent(name),
                              device: original.st_dev, inode: original.st_ino)
    }
}

// Linked fixed implementation of Rust's container resolver. Not public path
// admission: identifiers were entitlement-checked in Rust before this call.
@_cdecl("cirrus_native_container_url")
func nativeContainerURL(_ group: UnsafePointer<CChar>?, _ output: UnsafeMutablePointer<UInt8>?,
                        _ capacity: Int) -> Int {
    guard let group, let output, capacity > 0,
          let identifier = String(validatingCString: group),
          let url = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: identifier)
    else { return 0 }
    let bytes = Array(url.path.utf8)
    guard !bytes.isEmpty, bytes.count <= capacity else { return 0 }
    output.update(from: bytes, count: bytes.count)
    return bytes.count
}
