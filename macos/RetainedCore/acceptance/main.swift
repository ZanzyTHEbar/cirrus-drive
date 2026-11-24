import CirrusRetained
import Darwin
import Foundation

func require(_ condition: Bool, _ message: String) {
    precondition(condition, message)
}

// No entitled identities are invented: these explicitly unregistered inputs must
// fail on this unsigned acceptance process before container discovery succeeds.
do {
    _ = try RetainedCore(appGroup: "invalid.cirrus.acceptance", keychainAccessGroup: "invalid.cirrus.keychain")
    fatalError("unsigned production admission unexpectedly succeeded")
} catch RetainedError.unavailable {
    print("production App Group admission: refused without entitlement (expected)")
}

#if CIRRUS_ACCEPTANCE
guard CommandLine.arguments.count == 2 else { fatalError("explicit new private APFS fixture required") }
let fixture = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
let container = fixture.appendingPathComponent("container", isDirectory: true)
let output = fixture.appendingPathComponent("output", isDirectory: true)
try FileManager.default.createDirectory(at: container, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
try FileManager.default.createDirectory(at: output, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])

func scenario() throws {
    var raw: UnsafeMutableRawPointer?
    let status = withRetainedText(container.path) { cirrus_retained_fixture($0, &raw) }
    require(status == 0, "real fixture initialization failed status \(status)")
    guard let raw else { fatalError("missing fixture handle") }
    var core: RetainedCore? = RetainedCore(taking: raw)
    let binding = try core!.bind(instance: "https://retained-bridge.example/", space: "space")
    core = nil // Child binding must retain the exact admitted root/account.
    let request = try RetainedRequest()
    let listing = try binding.enumerate([], request: request)
    let page = try listing.page(after: 0, request: request)
    require(page.entries.count == 1, "real retained namespace did not enumerate one file")
    let entry = page.entries[0]
    require(entry.name == "retained.bin" && entry.size == 3 * 131072 + 17, "retained metadata mismatch")
    require(try listing.page(after: page.next, request: request).entries.isEmpty, "pagination failed")
    let version = try binding.open([entry.name], entry: entry, request: request)
    var observation = [UInt8](repeating: 0, count: Int(CIRRUS_RETAINED_PAGE_BYTES))
    var observedCount = 0
    try observation.withUnsafeMutableBufferPointer {
        try checked(cirrus_retained_operation(version.raw, request.raw, $0.baseAddress, $0.count, &observedCount))
    }
    let observed = try JSONSerialization.jsonObject(with: Data(observation.prefix(observedCount))) as? [String: Any]
    let exactResult = observed?["result"] as? [String: Any]
    require(exactResult?["state"] as? String == "pending", "durable staging falsely reported remote confirmation")
    let cancelled = try RetainedRequest()
    try cancelled.cancel()
    do {
        try version.materialize(in: output, name: "cancelled.bin", request: cancelled)
        fatalError("cancelled request published")
    } catch RetainedError.cancelled {}
    require(try FileManager.default.contentsOfDirectory(atPath: output.path).isEmpty, "owned cancelled candidate leaked")
    try version.materialize(in: output, name: "exact.bin", request: request)
    // Stream output verification too; no whole-file Swift Data.
    let fd = Darwin.open(output.appendingPathComponent("exact.bin").path, O_RDONLY | O_NOFOLLOW)
    require(fd >= 0, "materialized file missing")
    defer { close(fd) }
    var buffer = [UInt8](repeating: 0, count: 32768)
    var offset = 0
    while true {
        let n = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
        require(n >= 0, "read-back failed")
        if n == 0 { break }
        for i in 0..<n { require(buffer[i] == UInt8((offset + i) % 251), "exact retained byte mismatch at \(offset+i)") }
        offset += n
    }
    require(offset == 3 * 131072 + 17, "multichunk length mismatch")
    do {
        try version.materialize(in: output, name: "exact.bin", request: request)
        fatalError("existing destination was replaced")
    } catch RetainedError.unavailable {}
    require(try FileManager.default.contentsOfDirectory(atPath: output.path) == ["exact.bin"], "failure cleanup touched destination/leaked candidate")
    print("Swift -> production C ABI -> real account/SQLite/APFS: exact \(offset) bytes; cancellation cleanup and no-replace PASS")
}
try scenario()
#endif
