import FileProvider
import Foundation

final class ProviderEnumerator: NSObject, NSFileProviderEnumerator {
    private enum Registration {
        case submitting
        case registered(Progress)
    }
    private let worker: SwiftProviderWorker
    private let container: String
    private let lock = NSLock()
    private var closed = false
    private var registrations: [UUID: Registration] = [:]
    private var anchor: String?
    init(worker: SwiftProviderWorker, container: String) {
        self.worker = worker
        self.container = container
    }
    func invalidate() {
        lock.lock()
        closed = true
        let abandoned = registrations
        registrations = [:]
        lock.unlock()
        for registration in abandoned.values {
            if case .registered(let progress) = registration { progress.cancel() }
        }
    }
    deinit { invalidate() }
    private func submit(_ operation: ProviderOperation, completion: @escaping (Result<ProviderReply, Error>) -> Void) {
        let id = UUID()
        lock.lock()
        if closed { lock.unlock(); completion(.failure(RetainedError.cancelled)); return }
        registrations[id] = .submitting
        lock.unlock()
        let progress = worker.submit(operation) { result in
            self.lock.lock()
            let registration = self.registrations.removeValue(forKey: id)
            self.lock.unlock()
            withExtendedLifetime(registration) {}
            completion(result)
        }
        lock.lock()
        let cancel = closed
        if case .submitting? = registrations[id], !closed {
            registrations[id] = .registered(progress)
        }
        lock.unlock()
        if cancel { progress.cancel() }
    }
    func enumerateItems(for observer: NSFileProviderEnumerationObserver, startingAt page: NSFileProviderPage) {
        let dateSorted = page.rawValue == NSFileProviderPage.initialPageSortedByDate as Data
        let initial = dateSorted || page.rawValue == NSFileProviderPage.initialPageSortedByName as Data
        let token = initial ? nil : String(data: page.rawValue, encoding: .utf8)
        guard initial || token != nil else { observer.finishEnumeratingWithError(NSFileProviderError(.pageExpired)); return }
        submit(.page(container: container, token: token, sort: dateSorted ? "date" : "name")) { result in
            switch result {
            case .success(.page(let page)):
                self.lock.lock(); self.anchor = page.anchor; self.lock.unlock()
                observer.didEnumerate(page.items.map(ProviderItem.init))
                observer.finishEnumerating(upTo: page.next.map { NSFileProviderPage(Data($0.utf8)) })
            case .failure(let error): observer.finishEnumeratingWithError(providerError(error))
            default: observer.finishEnumeratingWithError(NSFileProviderError(.serverUnreachable))
            }
        }
    }
    func enumerateChanges(for observer: NSFileProviderChangeObserver, from syncAnchor: NSFileProviderSyncAnchor) {
        guard container == "working-set" else {
            observer.finishEnumeratingWithError(NSFileProviderError(.serverUnreachable)); return
        }
        guard let text = String(data: syncAnchor.rawValue, encoding: .utf8), text.utf8.count < 500 else {
            observer.finishEnumeratingWithError(NSFileProviderError(.syncAnchorExpired)); return
        }
        submit(.changes(text.isEmpty ? nil : text)) { result in
            switch result {
            case .success(.changes(let changes)):
                observer.didUpdate(changes.items.map(ProviderItem.init))
                observer.didDeleteItems(withIdentifiers: changes.deleted.map { NSFileProviderItemIdentifier($0) })
                // This anchor acknowledges the bounded durable LOCAL catalog,
                // not a remote freshness/deletion/synchronization watermark.
                // Complete the actual journal batch so OS caches/Spotlight can
                // advance, including at its high-water. No invented deletions.
                observer.finishEnumeratingChanges(
                    upTo: NSFileProviderSyncAnchor(Data(changes.anchor.utf8)), moreComing: changes.more)
            case .failure(let error): observer.finishEnumeratingWithError(providerError(error))
            default: observer.finishEnumeratingWithError(NSFileProviderError(.serverUnreachable))
            }
        }
    }
    func currentSyncAnchor(completionHandler: @escaping (NSFileProviderSyncAnchor?) -> Void) {
        lock.lock(); let saved = anchor; lock.unlock()
        if let saved { completionHandler(NSFileProviderSyncAnchor(Data(saved.utf8))); return }
        submit(.page(container: "working-set", token: nil, sort: "name")) { result in
            if case .success(.page(let page)) = result {
                completionHandler(NSFileProviderSyncAnchor(Data(page.anchor.utf8)))
            } else { completionHandler(nil) }
        }
    }
}
