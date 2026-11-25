import AppKit
import CirrusRetained

enum ApplicationOperation: Sendable {
    case connect(String)
    case spaces(String)
    case spacePage(Int)
    case prepareFinderDomain(instance: String, space: String)
    case restoreFinderDomains
}
enum ApplicationReply: Sendable {
    case connected
    case finderDomain(FinderDomainDescriptor)
    case restoredDomains(RestoredFinderDomains)
    case spaces([ApplicationSpace], Int)
}
enum ApplicationError: Error { case protectedStorageUnavailable }

// The pending URL is consumed by one main-queue launch or discarded on timeout.
// A late launch completion cannot replace the synchronous callback's result.
private final class BrowserDelivery: @unchecked Sendable {
    private enum Phase {
        case pending(URL)
        case opening
        case completed(Int32)
    }
    private let condition = NSCondition()
    private var phase: Phase
    init(_ url: URL) { phase = .pending(url) }
    @MainActor func deliver() {
        condition.lock()
        guard case .pending(let url) = phase else { condition.unlock(); return }
        phase = .opening
        condition.unlock()
        NSWorkspace.shared.open(url, configuration: NSWorkspace.OpenConfiguration()) { [self] app, error in
            complete(app != nil && error == nil ? Int32(CIRRUS_OK) : Int32(CIRRUS_UNAVAILABLE))
        }
    }
    private func complete(_ result: Int32) {
        condition.lock()
        if case .completed = phase {
            condition.unlock()
            return
        }
        phase = .completed(result)
        condition.signal()
        condition.unlock()
    }
    func wait() -> Int32 {
        let deadline = Date(timeIntervalSinceNow: 30)
        condition.lock()
        defer { condition.unlock() }
        while true {
            if case .completed(let result) = phase { return result }
            if !condition.wait(until: deadline) {
                if case .completed(let result) = phase { return result }
                phase = .completed(Int32(CIRRUS_UNAVAILABLE))
            }
        }
    }
    func refuse() {
        complete(Int32(CIRRUS_UNAVAILABLE))
    }
}

private let applicationBrowser: CirrusApplicationBrowser = { context, text in
    guard let context, let bytes = text.data, text.len > 0, text.len <= 16384 else { return Int32(CIRRUS_INVALID_ABI) }
    let worker = Unmanaged<ApplicationWorker>.fromOpaque(context).takeUnretainedValue()
    guard worker.mayOpenBrowser(),
          let string = String(bytes: UnsafeBufferPointer(start: bytes, count: text.len), encoding: .utf8),
          let url = URL(string: string), url.scheme == "https", url.host != nil,
           url.user == nil, url.password == nil else { return Int32(CIRRUS_UNAVAILABLE) }
    let delivery = BrowserDelivery(url)
    DispatchQueue.main.async {
        if worker.mayOpenBrowser() { delivery.deliver() }
        else { delivery.refuse() }
    }
    return delivery.wait()
}

// A single OS thread owns the Core, Space snapshot, mount binding and sign-in attempt.
// The mailbox never transports RetainedHandle. Only cancellation borrows its
// pointer under the same mutex used to remove it before owner-thread teardown.
final class ApplicationWorker: @unchecked Sendable {
    typealias Completion = @MainActor @Sendable (Result<ApplicationReply, Error>) -> Void
    private struct Job {
        let operation: ApplicationOperation
        let completion: Completion
    }
    private enum Lifecycle {
        case accepting
        case draining(@MainActor @Sendable () -> Void)
        case stopped

        var isAccepting: Bool {
            if case .accepting = self { return true }
            return false
        }
    }
    private enum ConnectPhase {
        case absent
        case waiting
        case cancelledWaiting
        case attached(UnsafeMutableRawPointer)
        case cancelledAttached(UnsafeMutableRawPointer)
        case reporting
    }
    private let condition = NSCondition()
    private var queue: [Job] = []
    private var lifecycle: Lifecycle = .accepting
    private var connect: ConnectPhase = .absent
    // Borrowed only while the owner executes a background turn. The condition
    // excludes clearing/closing it until cross-thread pause has returned.
    private var background: UnsafeMutableRawPointer?
    private let configuration: ApplicationConfiguration
    private let syncObservation: (@MainActor @Sendable (DispatcherObservation?) -> Void)?

    init(_ configuration: ApplicationConfiguration,
         syncObservation: (@MainActor @Sendable (DispatcherObservation?) -> Void)? = nil) {
        self.configuration = configuration
        self.syncObservation = syncObservation
        let thread = Thread {
            autoreleasepool { self.run() }
            // Outer pool has drained after all thread-affine handles dropped.
            self.condition.lock()
            let completion: (@MainActor @Sendable () -> Void)?
            if case .draining(let callback) = self.lifecycle { completion = callback }
            else { completion = nil }
            self.lifecycle = .stopped
            self.condition.unlock()
            if let completion { DispatchQueue.main.async { completion() } }
        }
        thread.name = "Cirrus application account"
        thread.start()
    }
    func submit(_ operation: ApplicationOperation, completion: @escaping Completion) {
        condition.lock()
        if !lifecycle.isAccepting || queue.count >= 8 {
            condition.unlock()
            DispatchQueue.main.async { completion(.failure(RetainedError.unavailable)) }
            return
        }
        if case .connect = operation {
            guard case .absent = connect else {
                condition.unlock()
                DispatchQueue.main.async { completion(.failure(RetainedError.unavailable)) }
                return
            }
            connect = .waiting
        }
        queue.append(Job(operation: operation, completion: completion))
        if let background { _ = cirrus_dispatcher_pause(background, 1) }
        condition.signal()
        condition.unlock()
    }
    func cancelConnect() -> Int32 {
        condition.lock()
        defer { condition.unlock() }
        return cancelConnectLocked()
    }
    private func cancelConnectLocked() -> Int32 {
        switch connect {
        case .absent:
            return Int32(CIRRUS_UNAVAILABLE)
        case .attached(let attempt), .cancelledAttached(let attempt):
            let status = cirrus_application_cancel(attempt)
            if status == Int32(CIRRUS_OK) { connect = .cancelledAttached(attempt) }
            return status
        case .waiting, .cancelledWaiting:
            connect = .cancelledWaiting
        case .reporting:
            break
        }
        // Before owner creates the active attempt, queued connect is cancelled
        // at creation. No account-global cancel/reset can affect another flow.
        return Int32(CIRRUS_OK)
    }
    fileprivate func mayOpenBrowser() -> Bool {
        condition.lock()
        defer { condition.unlock() }
        guard lifecycle.isAccepting, case .attached = connect else { return false }
        return true
    }
    func shutdown(_ completion: @escaping @MainActor @Sendable () -> Void) {
        condition.lock()
        if case .stopped = lifecycle {
            condition.unlock()
            DispatchQueue.main.async { completion() }
            return
        }
        lifecycle = .draining(completion)
        _ = cancelConnectLocked()
        if let background { _ = cirrus_dispatcher_pause(background, 1) }
        condition.broadcast()
        condition.unlock()
    }
    private func run() {
        var core: RetainedCore?
        var spaces: ApplicationSpaces?
        var dispatcher: RetainedDispatcher?
        var nextTurn = Date(timeIntervalSinceNow: 2)
        defer {
            condition.lock(); background = nil; condition.unlock()
            dispatcher = nil
            spaces = nil; core = nil
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
                        if dispatcher == nil, let core { dispatcher = try RetainedDispatcher(owner: core) }
                        condition.lock()
                        let admitted = lifecycle.isAccepting && queue.isEmpty
                        if admitted, let dispatcher {
                            background = dispatcher.raw
                            _ = cirrus_dispatcher_pause(dispatcher.raw, 0)
                        }
                        condition.unlock()
                        defer { condition.lock(); background = nil; condition.unlock() }
                        if admitted, let observation = try dispatcher?.turn(), let callback = syncObservation {
                            DispatchQueue.main.async { callback(observation) }
                        }
                    } catch {
                        condition.lock(); background = nil; condition.unlock()
                        dispatcher = nil
                        if let callback = syncObservation { DispatchQueue.main.async { callback(nil) } }
                        if case RetainedError.internalFailure = error {
                            spaces = nil; core = nil
                        }
                    }
                }
                nextTurn = Date(timeIntervalSinceNow: 2)
                continue
            }
            let job = queue.removeFirst()
            let closing = !lifecycle.isAccepting
            condition.unlock()
            let result: Result<ApplicationReply, Error> = autoreleasepool {
                Result {
                    if closing { throw RetainedError.cancelled }
                    if core == nil {
                        do {
                            core = try RetainedCore(appGroup: configuration.appGroup,
                                                    keychainAccessGroup: configuration.keychainGroup)
                        } catch RetainedError.unavailable {
                            throw ApplicationError.protectedStorageUnavailable
                        }
                    }
                    guard let core else { throw RetainedError.unavailable }
                    switch job.operation {
                    case .restoreFinderDomains:
                        return .restoredDomains(try core.restoreFinderDomains())
                    case .prepareFinderDomain(let instance, let space):
                        // Mount preparation requires fresh authenticated membership.
                        let selected = try core.bindOnline(instance: instance, space: space)
                        return .finderDomain(try selected.prepareFinderDomain())
                    case .connect(let instance):
                        let signIn = try ApplicationAttempt()
                        condition.lock()
                        if case .cancelledWaiting = connect {
                            connect = .cancelledAttached(signIn.raw)
                            _ = cirrus_application_cancel(signIn.raw)
                        } else if !lifecycle.isAccepting {
                            connect = .cancelledAttached(signIn.raw)
                            _ = cirrus_application_cancel(signIn.raw)
                        } else {
                            connect = .attached(signIn.raw)
                        }
                        condition.unlock()
                        defer {
                            condition.lock()
                            connect = .reporting
                            condition.unlock()
                            withExtendedLifetime(signIn) {}
                        }
                        // Invalidate prior snapshots before changing credentials.
                        spaces = nil
                        try core.connect(instance: instance, attempt: signIn, browser: applicationBrowser,
                                         context: Unmanaged.passUnretained(self).toOpaque())
                        return .connected
                    case .spaces(let instance):
                        spaces = nil
                        spaces = try core.spaces(instance: instance)
                        guard let spaces else { throw RetainedError.unavailable }
                        let page = try spaces.page(after: 0)
                        return .spaces(page.spaces, page.next)
                    case .spacePage(let offset):
                        guard let spaces else { throw RetainedError.unavailable }
                        let page = try spaces.page(after: offset)
                        return .spaces(page.spaces, page.next)
                    }
                }
            }
            if case .failure(let error) = result,
               let retained = error as? RetainedError, case .internalFailure = retained {
                // ABI INTERNAL requires discarding the entire session, close only.
                dispatcher = nil; spaces = nil; core = nil
            }
            condition.lock()
            if case .connect = job.operation { connect = .absent }
            condition.unlock()
            // Each accepted job gets exactly one main-thread completion, even
            // when queued at shutdown. Main never joins this blocking engine.
            DispatchQueue.main.async { job.completion(result) }
        }
    }
}
