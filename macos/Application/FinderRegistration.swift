import FileProvider
import Foundation

// Mount lifecycle, not a setup UI. Only copied descriptors cross from the
// account owner; all OS calls occur after SQLite/account/mailbox locks release.
@MainActor
final class FinderRegistration {
    struct Outcome: Sendable {
        let ready: Bool
        let message: String
    }
    private typealias Completion = @MainActor @Sendable (Outcome) -> Void
    private struct MountIntent {
        let instance: String
        let space: ApplicationSpace
    }
    @MainActor
    private final class Attempt {
        let completion: Completion
        var retry: MountIntent?
        var remaining: [(FinderDomainDescriptor, String)] = []
        var failed = 0
        var indexPending = false

        init(retry: MountIntent? = nil, completion: @escaping Completion) {
            self.retry = retry
            self.completion = completion
        }
    }
    private enum Phase {
        case idle(MountIntent?)
        case preparing(Attempt)
        case listing(Attempt, UUID)
        case adding(Attempt, UUID)
        case indexing(Attempt, UUID)
    }
    private enum Lifecycle {
        case open
        case draining(@MainActor @Sendable () -> Void)
        case closed

        var isOpen: Bool {
            if case .open = self { return true }
            return false
        }
    }
    private var phase: Phase = .idle(nil)
    private var lifecycle: Lifecycle = .open

    func mount(instance: String, space: ApplicationSpace, worker: ApplicationWorker,
               completion: @escaping @MainActor @Sendable (Outcome) -> Void) {
        guard lifecycle.isOpen, case .idle = phase else { return }
        let attempt = Attempt(retry: MountIntent(instance: instance, space: space), completion: completion)
        phase = .preparing(attempt)
        // Selected ID and display-only name are captured before queueing.
        worker.submit(.prepareFinderDomain(instance: instance, space: space.id)) { result in
            guard case .preparing(let current) = self.phase, current === attempt else { return }
            guard self.lifecycle.isOpen else {
                self.finish(attempt, ready: false, message: "Mount preparation retained; Finder submission deferred until next launch.")
                return
            }
            switch result {
            case .success(.finderDomain(let descriptor)):
                attempt.retry = nil // durable activation/domain now owns retry
                attempt.remaining = [(descriptor, space.name)]
                self.next(attempt)
            default:
                self.finish(attempt, ready: false, message: "Mount pending. Space sync may already be enabled; data is preserved. Cirrus will retry when the app becomes active.")
            }
        }
    }

    // Called after launch/admission and on meaningful activation, never a timer
    // or callback-driven retry loop. Persisted activations are mount intent.
    func restore(worker: ApplicationWorker,
                 completion: @escaping @MainActor @Sendable (Outcome) -> Void) {
        guard lifecycle.isOpen, case .idle(let retry) = phase else { return }
        if let retry {
            mount(instance: retry.instance, space: retry.space, worker: worker, completion: completion)
            return
        }
        let attempt = Attempt(completion: completion)
        phase = .preparing(attempt)
        worker.submit(.restoreFinderDomains) { result in
            guard case .preparing(let current) = self.phase, current === attempt else { return }
            guard self.lifecycle.isOpen else {
                self.finish(attempt, ready: false, message: "Mount restoration deferred until next launch.")
                return
            }
            switch result {
            case .success(.restoredDomains(let restored)):
                attempt.failed = restored.unavailable
                attempt.remaining = restored.domains.map { ($0, "Cirrus Space") }
                self.next(attempt)
            default:
                self.finish(attempt, ready: false, message: "Mounted Spaces are waiting for account storage or connectivity. Cirrus will retry when active.")
            }
        }
    }

    private func next(_ attempt: Attempt) {
        guard lifecycle.isOpen else {
            finish(attempt, ready: false, message: "Mounted Spaces retained for next launch.")
            return
        }
        guard !attempt.remaining.isEmpty else {
            finish(attempt, ready: attempt.failed == 0, message: attempt.failed > 0
                ? "Some mounted Spaces are pending. Data is preserved; Cirrus will retry when active."
                : attempt.indexPending ? "Available in Finder. Search metadata refresh is pending."
                : "Available in Finder. Observed file metadata is offered to Spotlight; indexing runs asynchronously.")
            return
        }
        let (descriptor, name) = attempt.remaining.removeFirst()
        let listingAttempt = UUID()
        phase = .listing(attempt, listingAttempt)
        NSFileProviderManager.getDomainsWithCompletionHandler { domains, error in
            let found = domains.contains { $0.identifier.rawValue == descriptor.domain }
            let failed = error != nil
            DispatchQueue.main.async {
                guard case .listing(let current, let token) = self.phase,
                      current === attempt, token == listingAttempt else { return }
                if failed {
                    attempt.failed += 1; self.next(attempt)
                } else if found {
                    self.refreshIndex(descriptor, name: name, attempt: attempt)
                } else if !self.lifecycle.isOpen {
                    self.next(attempt)
                } else {
                    let addAttempt = UUID()
                    self.phase = .adding(attempt, addAttempt)
                    let domain = NSFileProviderDomain(
                        identifier: NSFileProviderDomainIdentifier(rawValue: descriptor.domain),
                        displayName: name)
                    NSFileProviderManager.add(domain) { error in
                        let failed = error != nil
                        DispatchQueue.main.async {
                            guard case .adding(let current, let token) = self.phase,
                                  current === attempt, token == addAttempt else { return }
                            // An error may follow OS acceptance. Preserve the
                            // durable ID; next lifecycle event lists before add.
                            if failed { attempt.failed += 1; self.next(attempt) }
                            else { self.refreshIndex(descriptor, name: name, attempt: attempt) }
                        }
                    }
                }
            }
        }
    }

    private func refreshIndex(_ descriptor: FinderDomainDescriptor, name: String, attempt: Attempt) {
        // SDK working-set documentation explicitly connects enumeration with
        // Spotlight. Registration alone is not evidence of an indexed Space.
        let domain = NSFileProviderDomain(
            identifier: NSFileProviderDomainIdentifier(rawValue: descriptor.domain), displayName: name)
        guard lifecycle.isOpen, let manager = NSFileProviderManager(for: domain) else {
            attempt.indexPending = true; next(attempt); return
        }
        let indexAttempt = UUID()
        phase = .indexing(attempt, indexAttempt)
        manager.signalEnumerator(for: .workingSet) { error in
            let failed = error != nil
            DispatchQueue.main.async {
                guard case .indexing(let current, let token) = self.phase,
                      current === attempt, token == indexAttempt else { return }
                attempt.indexPending = attempt.indexPending || failed
                self.next(attempt)
            }
        }
    }

    private func finish(_ attempt: Attempt, ready: Bool, message: String) {
        phase = .idle(attempt.retry)
        attempt.remaining = []
        let stopped: (@MainActor @Sendable () -> Void)?
        if case .draining(let callback) = lifecycle {
            lifecycle = .closed
            stopped = callback
        } else { stopped = nil }
        attempt.completion(Outcome(ready: ready, message: message))
        stopped?()
    }
    func drain(_ completion: @escaping @MainActor @Sendable () -> Void) {
        if case .idle = phase {
            lifecycle = .closed
            completion()
        } else {
            lifecycle = .draining(completion)
        }
    }
}
