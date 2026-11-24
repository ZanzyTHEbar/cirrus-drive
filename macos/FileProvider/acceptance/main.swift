import Darwin
import Foundation

// One two-process acceptance flow against the same APFS container. Uses the
// product dedicated worker, typed adapter and actual account C ABI, not a copied
// driver or NSFileProvider mock.
func require(_ condition: Bool, _ message: String) { precondition(condition, message) }
final class Awaited: @unchecked Sendable {
    let condition = NSCondition()
    private var value: Result<ProviderReply, Error>?
    private var completions = 0
    func complete(_ result: Result<ProviderReply, Error>) {
        condition.lock()
        completions += 1
        require(completions == 1, "multiple terminal callbacks")
        value = result
        condition.signal()
        condition.unlock()
    }
    func wait() throws -> ProviderReply {
        condition.lock()
        let deadline = Date().addingTimeInterval(45)
        while value == nil {
            require(condition.wait(until: deadline), "dedicated worker did not complete")
        }
        let result = value!
        condition.unlock()
        return try result.get()
    }
}
guard CommandLine.arguments.count == 3 else { fatalError("phase and explicit private fixture required") }
let phase = CommandLine.arguments[1]
let base = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
// Separate owned variant of this ONE acceptance flow. This symbol exists only
// in the fixture archive, not the production ABI.
@_silgen_name("cirrus_catalog_move_observations")
func moveObservations(_ path: CirrusRetainedText, _ moved: UInt8) -> Int32
if phase.hasPrefix("move-") {
    try withRetainedText(base.appendingPathComponent("container").path) {
        try checked(moveObservations($0, phase == "move-first" ? 0 : 1))
    }
}
let configuration = ProviderConfiguration(appGroup: "not-used-fixture", keychainGroup: "not-used-fixture")
let stopped = DispatchSemaphore(value: 0)
let worker = SwiftProviderWorker(configuration: configuration, fixture: base.appendingPathComponent("container"),
                                 stopped: { stopped.signal() })
func run(_ operation: ProviderOperation) throws -> ProviderReply {
    let awaited = Awaited()
    worker.submit(operation, completion: awaited.complete)
    return try awaited.wait()
}
let receipt = base.appendingPathComponent("catalog-restart.json")
if phase == "move-first" {
    guard case .page(let first) = try run(.page(container: "root", token: nil, sort: "name")),
          let token = first.next,
          case .page(let last) = try run(.page(container: "root", token: token, sort: "name")),
          let b = last.items.first(where: { $0.name == "B" }) else { fatalError("initial move page missing") }
    require(first.items.count == 32 && last.items.count == 9 && b.etag == "\"b1\"", "initial move inputs changed")
    let encoder = JSONEncoder()
    encoder.outputFormatting = .sortedKeys
    let data = try JSONSerialization.data(withJSONObject: [
        "id":first.items[0].id, "b":b.id, "next":token,
        "version":first.items[0].contentVersion.base64EncodedString(),
        "old":try encoder.encode(last.items).base64EncodedString(),
        "anchor":last.anchor
    ])
    try data.write(to: receipt, options: .withoutOverwriting)
    worker.invalidate()
    print("move first: published root X and B(b1), immutable old page recorded PASS")
} else if phase == "move-second" {
    let saved = try JSONSerialization.jsonObject(with: Data(contentsOf: receipt)) as! [String:String]
    // Destination MUST be captured first: this is the F1 wedged ordering.
    guard case .page(let destination) = try run(.page(container: saved["b"]!, token: nil, sort: "name")),
          let x = destination.items.first else { fatalError("destination capture failed") }
    require(destination.items.count == 1 && x.id == saved["id"] && x.parent == saved["b"]
            && x.name == "000.bin" && x.contentVersion.base64EncodedString() == saved["version"],
            "move changed identity/version or failed to update parent")
    guard case .item(let b) = try run(.item(saved["b"]!)) else { fatalError("directory lookup failed") }
    require(b.etag == "\"b2\"" && b.modified == 2, "container metadata not refreshed")
    guard case .page(let root) = try run(.page(container: "root", token: nil, sort: "name")),
          let next = root.next,
          case .page(let rest) = try run(.page(container: "root", token: next, sort: "name")) else { fatalError("source capture still wedged") }
    require(root.items.count + rest.items.count == 40 && !(root.items + rest.items).contains(where: { $0.id == x.id }),
            "source move reconciliation failed")
    guard case .page(let old) = try run(.page(container: "root", token: saved["next"]!, sort: "name")) else { fatalError("old page unavailable") }
    let encoder = JSONEncoder()
    encoder.outputFormatting = .sortedKeys
    require(try encoder.encode(old.items).base64EncodedString() == saved["old"], "old durable page mutated across restart/move")
    guard case .changes(let changes) = try run(.changes(saved["anchor"]!)) else { fatalError("move journal missing") }
    require(changes.items.contains(where: { $0.id == b.id && $0.etag == "\"b2\"" })
            && changes.items.contains(where: { $0.id == x.id && $0.parent == b.id })
            && !changes.authoritative, "move/container changes not journaled")
    guard case .file(let url, _) = try run(.fixtureFetch(id: x.id, version: x.contentVersion, directory: base.appendingPathComponent("output"))) else { fatalError("move fetch failed") }
    let bytes = try Data(contentsOf: url)
    require(bytes.count == 393233 && bytes.enumerated().allSatisfy { $0.element == UInt8($0.offset % 251) },
            "moved exact-version bytes changed")
    worker.invalidate()
    print("move second: destination b2 BEFORE root, stable X FPID/parent/name/exact393233 bytes, old page immutable, journal PASS")
} else if phase == "first" {
    guard case .page(let page) = try run(.page(container: "root", token: nil, sort: "name")) else { fatalError("wrong reply") }
    require(page.items.count == 32 && page.next != nil, "first bounded page missing")
    require(page.items[0].name == "000.bin", "ordering mismatch")
    let data = try JSONSerialization.data(withJSONObject: [
        "id":page.items[0].id,"next":page.next!,"anchor":page.anchor,
        "version":page.items[0].contentVersion.base64EncodedString()
    ])
    try data.write(to: receipt, options: .withoutOverwriting)
    // Hold only a callback (outside all mailbox locks), so the next request is
    // deterministically queued when cancellation and invalidation arrive.
    let entered = DispatchSemaphore(value: 0)
    let release = DispatchSemaphore(value: 0)
    let active = Awaited()
    worker.submit(.item("root")) { result in
        entered.signal()
        require(release.wait(timeout: .now()+30) == .success, "callback release timeout")
        active.complete(result)
    }
    require(entered.wait(timeout: .now()+30) == .success, "callback never entered")
    let cancelled = Awaited()
    let progress = worker.submit(.fixtureFetch(id: page.items[0].id, version: page.items[0].contentVersion,
        directory: base.appendingPathComponent("output")), completion: cancelled.complete)
    progress.cancel() // intent stored before request creation
    worker.invalidate()
    release.signal()
    _ = try active.wait()
    do { _ = try cancelled.wait(); fatalError("queued cancelled download succeeded") } catch RetainedError.cancelled {}
    require(try FileManager.default.contentsOfDirectory(atPath: base.appendingPathComponent("output").path) == ["exact.bin"],
            "queued cancellation leaked output")
    // Closed admission gives a terminal cancellation; owner-thread FIFO drains
    // all earlier work before the fresh process is launched by the supervisor.
    let done = Awaited()
    worker.submit(.item("root"), completion: done.complete)
    do { _ = try done.wait(); fatalError("invalidated worker admitted work") } catch RetainedError.cancelled {}
    print("first process: durable 32/40 page, stable FPID/anchor recorded; queued cancel/invalidate exactly-once, clean output PASS")
} else {
    let data = try Data(contentsOf: receipt)
    let saved = try JSONSerialization.jsonObject(with: data) as! [String:String]
    guard case .page(let page) = try run(.page(container: "root", token: saved["next"]!, sort: "name")) else { fatalError("wrong page reply") }
    require(page.items.count == 8 && page.next == nil, "restart durable page did not resume remaining eight")
    guard case .item(let item) = try run(.item(saved["id"]!)) else { fatalError("wrong lookup reply") }
    require(item.name == "000.bin" && item.contentVersion.base64EncodedString() == saved["version"], "stable identity/version changed after restart")
    guard case .changes(let changes) = try run(.changes(saved["anchor"]!)) else { fatalError("wrong changes reply") }
    require(changes.items.isEmpty && !changes.more && !changes.authoritative, "retained state claimed fresh cloud sync")
    guard case .file(let url, _) = try run(.fixtureFetch(id: item.id, version: item.contentVersion, directory: base.appendingPathComponent("output"))) else { fatalError("wrong fetch reply") }
    let fd = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW)
    require(fd >= 0, "materialized output missing")
    var buffer = [UInt8](repeating: 0, count: 32768)
    var offset = 0
    while true {
        let n = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
        require(n >= 0, "read failed")
        if n == 0 { break }
        for i in 0..<n { require(buffer[i] == UInt8((offset+i)%251), "exact retained byte mismatch") }
        offset += n
    }
    close(fd)
    require(offset == 393233, "exact multichunk length mismatch")
    worker.invalidate()
    print("second process: SAME durable page/anchor/FPID; exact \(offset) retained bytes through dedicated worker PASS (not OS extension execution)")
}
require(stopped.wait(timeout: .now()+45) == .success, "owner-thread retained teardown did not finish")
print("owner-thread catalog/parents/requests teardown complete; no live worker")
