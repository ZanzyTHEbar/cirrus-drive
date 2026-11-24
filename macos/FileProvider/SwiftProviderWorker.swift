import CirrusRetained
import Foundation
import FileProvider

#if CIRRUS_ACCEPTANCE
@_silgen_name("cirrus_catalog_fixture_prepare")
private func cirrus_catalog_fixture_prepare(_ core: UnsafeMutableRawPointer, _ buffer: UnsafeMutablePointer<UInt8>?,
                                            _ capacity: Int, _ written: UnsafeMutablePointer<Int>) -> Int32
#endif

struct ProviderConfiguration: Sendable {
    let appGroup: String
    let keychainGroup: String
}

enum ProviderOperation: Sendable {
    case item(String)
    case page(container: String, token: String?, sort: String)
    case changes(String?)
    case fetch(id: String, version: Data?)
    case mutate(ProviderMutationInput)
    #if CIRRUS_ACCEPTANCE
    case fixtureFetch(id: String, version: Data?, directory: URL)
    #endif
}
enum ProviderReply: Sendable {
    case item(CatalogItem)
    case page(CatalogPage)
    case changes(CatalogChanges)
    case file(URL, CatalogItem)
    case mutation(MutationReply)
}

// The only cross-thread mutable boundary. Each field is protected by condition;
// the raw request pointer is borrowed solely for cirrus_retained_cancel while
// holding that lock. No RetainedHandle is Sendable or leaves run()'s OS thread.
final class SwiftProviderWorker: @unchecked Sendable {
    private typealias Completion = (Result<ProviderReply, Error>) -> Void
    // Phase is accessed only under the enclosing worker's condition.
    private final class Job: @unchecked Sendable {
        private enum Phase {
            case pending(Completion)
            case cancelled(Completion)
            case attached(UnsafeMutableRawPointer, Completion)
            case cancelledAttached(UnsafeMutableRawPointer, Completion)
            case finished
        }
        let operation: ProviderOperation
        let progress = Progress(totalUnitCount: 1)
        private var phase: Phase
        init(_ operation: ProviderOperation, _ completion: @escaping Completion) {
            self.operation = operation
            phase = .pending(completion)
        }
        var isCancelled: Bool {
            switch phase {
            case .cancelled, .cancelledAttached: return true
            case .pending, .attached, .finished: return false
            }
        }
        func cancel() {
            switch phase {
            case .pending(let callback):
                phase = .cancelled(callback)
            case .attached(let pointer, let callback), .cancelledAttached(let pointer, let callback):
                phase = .cancelledAttached(pointer, callback)
                _ = cirrus_retained_cancel(pointer)
            case .cancelled, .finished:
                break
            }
        }
        func attach(_ pointer: UnsafeMutableRawPointer) {
            switch phase {
            case .pending(let callback):
                phase = .attached(pointer, callback)
            case .cancelled(let callback):
                phase = .cancelledAttached(pointer, callback)
                _ = cirrus_retained_cancel(pointer)
            default:
                preconditionFailure("request already attached or finished")
            }
        }
        func detach() {
            switch phase {
            case .attached(_, let callback): phase = .pending(callback)
            case .cancelledAttached(_, let callback): phase = .cancelled(callback)
            default: preconditionFailure("request not attached")
            }
        }
        func finish() -> (callback: Completion, cancelled: Bool) {
            let terminal: (Completion, Bool)
            switch phase {
            case .pending(let callback): terminal = (callback, false)
            case .cancelled(let callback): terminal = (callback, true)
            default: preconditionFailure("request still attached or already finished")
            }
            phase = .finished
            return terminal
        }
    }
    private enum Lifecycle {
        case accepting
        case draining
        case stopped

        var isAccepting: Bool {
            if case .accepting = self { return true }
            return false
        }
    }
    private let condition = NSCondition()
    private var queue: [Job] = []
    private var active: Job?
    private var background: UnsafeMutableRawPointer?
    private var lifecycle: Lifecycle = .accepting
    private let configuration: ProviderConfiguration?
    // Immutable OS domain identity, supplied by init(domain:), never inferred
    // from a display name. Its manager is resolved only on the owner thread.
    private let domain: NSFileProviderDomain?
    #if CIRRUS_ACCEPTANCE
    private let fixture: URL?
    private let stopped: (@Sendable () -> Void)?
    #endif

    init(configuration: ProviderConfiguration?, domain: NSFileProviderDomain? = nil) {
        self.configuration = configuration
        self.domain = domain
        #if CIRRUS_ACCEPTANCE
        self.fixture = nil
        self.stopped = nil
        #endif
        start()
    }
    #if CIRRUS_ACCEPTANCE
    init(configuration: ProviderConfiguration, fixture: URL, stopped: @escaping @Sendable () -> Void) {
        self.configuration = configuration
        self.domain = nil
        self.fixture = fixture
        self.stopped = stopped
        start()
    }
    #endif
    private func start() {
        // Thread's closure strongly retains the mailbox until owner-thread
        // teardown. No stored Thread/closure/self cycle and no synchronous join.
        let thread = Thread {
            autoreleasepool { self.run() }
            self.condition.lock()
            self.lifecycle = .stopped
            self.condition.unlock()
            #if CIRRUS_ACCEPTANCE
            self.stopped?()
            #endif
        }
        thread.name = "Cirrus retained FileProvider"
        thread.start()
    }
    @discardableResult
    func submit(_ operation: ProviderOperation,
                completion: @escaping (Result<ProviderReply, Error>) -> Void) -> Progress {
        let job = Job(operation, completion)
        job.progress.cancellationHandler = { [weak self, weak job] in
            if let job { self?.cancel(job) }
        }
        condition.lock()
        if !lifecycle.isAccepting || queue.count >= 32 {
            let error: RetainedError = lifecycle.isAccepting ? .capacity : .cancelled
            let terminal = job.finish()
            condition.unlock()
            job.progress.cancellationHandler = nil
            terminal.callback(.failure(error))
            return job.progress
        }
        queue.append(job)
        if let background { _ = cirrus_dispatcher_pause(background, 1) }
        condition.signal()
        condition.unlock()
        return job.progress
    }
    private func cancel(_ job: Job) {
        condition.lock()
        // Also records intent before admission; terminal jobs are a no-op.
        job.cancel()
        condition.signal()
        condition.unlock()
    }
    func invalidate() {
        condition.lock()
        if !lifecycle.isAccepting { condition.unlock(); return }
        lifecycle = .draining
        if let background { _ = cirrus_dispatcher_pause(background, 1) }
        for job in queue { job.cancel() }
        active?.cancel()
        condition.broadcast()
        condition.unlock()
    }
    private func run() {
        var catalog: RetainedCatalog?
        var dispatcher: RetainedDispatcher?
        var nextTurn = Date(timeIntervalSinceNow: 2)
        // All retained parents and requests are created, used and destroyed here.
        defer {
            condition.lock(); background = nil; condition.unlock()
            dispatcher = nil
            catalog = nil
        }
        while true {
            condition.lock()
            while queue.isEmpty && lifecycle.isAccepting {
                if !condition.wait(until: nextTurn) { break }
            }
            if queue.isEmpty && !lifecycle.isAccepting { condition.unlock(); return }
            if queue.isEmpty {
                condition.unlock()
                autoreleasepool {
                    do {
                        if catalog == nil { catalog = try openCatalog() }
                        if dispatcher == nil, let catalog { dispatcher = try RetainedDispatcher(owner: catalog) }
                        condition.lock()
                        let admitted = lifecycle.isAccepting && queue.isEmpty
                        if admitted, let dispatcher {
                            background = dispatcher.raw
                            _ = cirrus_dispatcher_pause(dispatcher.raw, 0)
                        }
                        condition.unlock()
                        defer { condition.lock(); background = nil; condition.unlock() }
                        if admitted, let observation = try dispatcher?.turn(),
                           let domain, observation.domains.contains(domain.identifier.rawValue),
                           let manager = NSFileProviderManager(for: domain) {
                            manager.signalEnumerator(for: .workingSet) { _ in }
                            manager.signalEnumerator(for: .rootContainer) { _ in }
                        }
                    } catch {
                        condition.lock(); background = nil; condition.unlock()
                        dispatcher = nil
                        if case RetainedError.internalFailure = error { catalog = nil }
                    }
                }
                nextTurn = Date(timeIntervalSinceNow: 2)
                continue
            }
            let job = queue.removeFirst()
            active = job
            let cancelled = job.isCancelled
            condition.unlock()
            // A dedicated Foundation thread has no UI run-loop pool. Drain
            // transient Cocoa objects per request, on this same OS thread.
            autoreleasepool {
                var result: Result<ProviderReply, Error>
                var publication: RetainedOutput?
                do {
                    if cancelled { throw RetainedError.cancelled }
                    let request = try RetainedRequest()
                    condition.lock()
                    job.attach(request.raw)
                    condition.unlock()
                    // Defer removes pointer under the SAME lock before request
                    // deinit/close, including all throwing setup/operation paths.
                    defer {
                        condition.lock()
                        job.detach()
                        condition.unlock()
                        withExtendedLifetime(request) {}
                    }
                    if catalog == nil { catalog = try openCatalog() }
                    guard let catalog else { throw RetainedError.internalFailure }
                    result = .success(try perform(job.operation, catalog: catalog, request: request, progress: job.progress, publication: &publication))
                } catch {
                    // C ABI INTERNAL requires discarding the entire retained session,
                    // never continuing with account state after a caught Rust panic.
                    // The request defer has already removed its live pointer.
                    if case RetainedError.internalFailure = error { dispatcher = nil; catalog = nil }
                    result = .failure(error)
                }
                condition.lock()
                // Sole terminal transition. Once taken, cancellation is a no-op and
                // the callback is never retained by the mailbox again.
                let terminal = job.finish()
                active = nil
                condition.unlock()
                job.progress.cancellationHandler = nil
                if terminal.cancelled {
                    // Terminal ownership is decided under the cancellation mutex.
                    // Cancellation after this transition is a no-op; before it,
                    // even a just-published temporary download is unwound safely.
                    publication?.removeIfOwned()
                    result = .failure(RetainedError.cancelled)
                }
                job.progress.completedUnitCount = job.progress.totalUnitCount
                terminal.callback(result) // outside every lock, including reentrant callbacks
            }
        }
    }
    private func openCatalog() throws -> RetainedCatalog {
        guard let c = configuration else { throw RetainedError.unavailable }
        let core: RetainedCore
        #if CIRRUS_ACCEPTANCE
        if let fixture {
            var raw: UnsafeMutableRawPointer?
            try withRetainedText(fixture.path) { try checked(cirrus_catalog_fixture($0, &raw)) }
            guard let raw else { throw RetainedError.internalFailure }
            core = RetainedCore(taking: raw)
        } else {
            core = try RetainedCore(appGroup: c.appGroup, keychainAccessGroup: c.keychainGroup)
        }
        #else
        core = try RetainedCore(appGroup: c.appGroup, keychainAccessGroup: c.keychainGroup)
        #endif
        let domainID: String
        #if CIRRUS_ACCEPTANCE
        if fixture != nil {
            var bytes = [UInt8](repeating: 0, count: Int(CIRRUS_RETAINED_PAGE_BYTES))
            var written = 0
            try bytes.withUnsafeMutableBufferPointer {
                try checked(cirrus_catalog_fixture_prepare(core.raw, $0.baseAddress, $0.count, &written))
            }
            struct Descriptor: Decodable { let domain: String }
            domainID = try JSONDecoder().decode(Descriptor.self, from: Data(bytes.prefix(written))).domain
        } else {
            guard let domain else { throw RetainedError.unavailable }
            domainID = domain.identifier.rawValue
        }
        #else
        guard let domain else { throw RetainedError.unavailable }
        domainID = domain.identifier.rawValue
        #endif
        return try RetainedCatalog(core: core, domain: domainID)
    }
    private func perform(_ operation: ProviderOperation, catalog: RetainedCatalog,
                         request: RetainedRequest, progress: Progress, publication: inout RetainedOutput?) throws -> ProviderReply {
        switch operation {
        case .mutate(let input):
            let result = try catalog.mutate(input, request: request, progress: progress)
            if let domain, let manager = NSFileProviderManager(for: domain) {
                manager.signalEnumerator(for: .workingSet) { _ in }
                manager.signalEnumerator(for: .rootContainer) { _ in }
            }
            return .mutation(result)
        case .item(let id): return .item(try catalog.lookup(id, request: request))
        case .page(let container, let token, let sort):
            let captured = token == nil
            let token = try token ?? catalog.capture(container: container, sort: sort, request: request)
            let page = try catalog.page(container: container, token: token, request: request)
            if captured && container != "working-set", let domain,
               let manager = NSFileProviderManager(for: domain) {
                // Catalog commit and read have returned; no SQL/mailbox lock.
                // Working-set consumers get newly observed IDs and move/version
                // updates without requiring the user to browse that set.
                manager.signalEnumerator(for: .workingSet) { _ in }
            }
            return .page(page)
        case .changes(let anchor):
            return .changes(try catalog.changes(anchor: anchor, request: request))
        case .fetch(let id, let requested):
            guard let domain, let manager = NSFileProviderManager(for: domain) else { throw RetainedError.unavailable }
            // The manager's throwing API supplies this domain's same-volume
            // temporary directory. Never invent a cache-path fallback.
            return try fetch(id, requested, in: manager.temporaryDirectoryURL(), catalog: catalog, request: request, publication: &publication)
        #if CIRRUS_ACCEPTANCE
        case .fixtureFetch(let id, let requested, let directory):
            return try fetch(id, requested, in: directory, catalog: catalog, request: request, publication: &publication)
        #endif
        }
    }
    private func fetch(_ id: String, _ requested: Data?, in directory: URL,
                       catalog: RetainedCatalog, request: RetainedRequest,
                       publication: inout RetainedOutput?) throws -> ProviderReply {
        let item = try catalog.lookup(id, request: request)
        if let requested, requested != item.contentVersion { throw RetainedError.stale }
        let version = try catalog.open(item, request: request)
        let name = UUID().uuidString
        let output = try version.materializeOwned(in: directory, name: name, request: request)
        publication = output
        return .file(output.url, item)
    }
}
