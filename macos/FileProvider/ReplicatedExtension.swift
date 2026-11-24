import FileProvider
import Foundation
import UniformTypeIdentifiers

// Source module only: no bundle identity, signing, installation, domain
// registration or entitlements are invented by this target.
@objc(CirrusReplicatedExtension)
final class ReplicatedExtension: NSObject, NSFileProviderReplicatedExtension {
    private let worker: SwiftProviderWorker
    private let domain: NSFileProviderDomain
    required init(domain: NSFileProviderDomain) {
        self.domain = domain
        // Base-only explicit shared configuration in the extension's bundle.
        // All principal/Space routing comes from the durable OS domain ID.
        let values = Bundle(for: ReplicatedExtension.self)
            .object(forInfoDictionaryKey: "CirrusRetainedStorage") as? [String: String]
        let config: ProviderConfiguration?
        if let values, let app = values["appGroup"], let keychain = values["keychainGroup"],
           Set(values.keys) == ["appGroup", "keychainGroup"],
           [app, keychain].allSatisfy({
               !$0.isEmpty && $0.utf8.count <= 4096 &&
               !$0.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
           }) {
            config = ProviderConfiguration(appGroup: app, keychainGroup: keychain)
        } else { config = nil }
        worker = SwiftProviderWorker(configuration: config, domain: domain)
        super.init()
    }
    func invalidate() { worker.invalidate() }
    deinit { worker.invalidate() }
    func item(for identifier: NSFileProviderItemIdentifier, request: NSFileProviderRequest,
              completionHandler: @escaping (NSFileProviderItem?, Error?) -> Void) -> Progress {
        do {
            return worker.submit(.item(try catalogIdentifier(identifier))) { result in
                switch result {
                case .success(.item(let item)): completionHandler(ProviderItem(item), nil)
                case .failure(let error): completionHandler(nil, providerError(error))
                default: completionHandler(nil, NSFileProviderError(.serverUnreachable))
                }
            }
        } catch { completionHandler(nil, providerError(error)); return Progress() }
    }
    func fetchContents(for itemIdentifier: NSFileProviderItemIdentifier, version requestedVersion: NSFileProviderItemVersion?,
                       request: NSFileProviderRequest,
                       completionHandler: @escaping (URL?, NSFileProviderItem?, Error?) -> Void) -> Progress {
        do {
            return worker.submit(.fetch(id: try catalogIdentifier(itemIdentifier),
                                         version: requestedVersion?.contentVersion)) { result in
                switch result {
                case .success(.file(let url, let item)): completionHandler(url, ProviderItem(item), nil)
                case .failure(let error): completionHandler(nil, nil, providerError(error))
                default: completionHandler(nil, nil, NSFileProviderError(.serverUnreachable))
                }
            }
        } catch { completionHandler(nil, nil, providerError(error)); return Progress() }
    }
    func enumerator(for containerItemIdentifier: NSFileProviderItemIdentifier,
                    request: NSFileProviderRequest) throws -> NSFileProviderEnumerator {
        ProviderEnumerator(worker: worker, container: try catalogIdentifier(containerItemIdentifier))
    }
    func createItem(basedOn itemTemplate: NSFileProviderItem, fields: NSFileProviderItemFields, contents: URL?,
                    options: NSFileProviderCreateItemOptions, request: NSFileProviderRequest,
                    completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, Error?) -> Void) -> Progress {
        do {
            guard let contentType = itemTemplate.contentType else { throw CocoaError(.featureUnsupported) }
            if contentType.conforms(to: .symbolicLink) { throw CocoaError(.featureUnsupported) }
            let input = ProviderMutationInput(kind: "create", id: nil,
                parent: try catalogIdentifier(itemTemplate.parentItemIdentifier), name: itemTemplate.filename,
                directory: contentType.conforms(to: .folder), base: nil, metadata: nil,
                contents: contents, options: UInt64(options.rawValue))
            let remaining = fields.subtracting([.contents, .filename, .parentItemIdentifier])
            return worker.submit(.mutate(input)) { result in
                switch result {
                case .success(.mutation(let reply)):
                    guard let item = reply.item else { completionHandler(nil, fields, false, NSFileProviderError(.serverUnreachable)); return }
                    completionHandler(ProviderItem(item), remaining, false, nil)
                case .failure(let error): completionHandler(nil, fields, false, providerError(error))
                default: completionHandler(nil, fields, false, NSFileProviderError(.serverUnreachable))
                }
            }
        } catch { completionHandler(nil, fields, false, providerError(error)); return Progress() }
    }
    func modifyItem(_ item: NSFileProviderItem, baseVersion version: NSFileProviderItemVersion,
                    changedFields: NSFileProviderItemFields, contents newContents: URL?,
                    options: NSFileProviderModifyItemOptions, request: NSFileProviderRequest,
                    completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, Error?) -> Void) -> Progress {
        do {
            let basic: NSFileProviderItemFields = [.contents, .filename, .parentItemIdentifier]
            if changedFields.intersection(basic).isEmpty {
                completionHandler(item, changedFields, false, nil)
                return Progress()
            }
            guard !changedFields.contains(.contents) || newContents != nil else { throw CocoaError(.fileReadUnknown) }
            guard let contentType = item.contentType else { throw CocoaError(.featureUnsupported) }
            if contentType.conforms(to: .symbolicLink) { throw CocoaError(.featureUnsupported) }
            let input = ProviderMutationInput(kind: "modify", id: try catalogIdentifier(item.itemIdentifier),
                parent: try catalogIdentifier(item.parentItemIdentifier), name: item.filename,
                directory: contentType.conforms(to: .folder), base: version.contentVersion,
                metadata: version.metadataVersion, contents: changedFields.contains(.contents) ? newContents : nil,
                options: UInt64(options.rawValue))
            let remaining = changedFields.subtracting(basic)
            return worker.submit(.mutate(input)) { result in
                switch result {
                case .success(.mutation(let reply)):
                    guard let item = reply.item else { completionHandler(nil, changedFields, false, NSFileProviderError(.serverUnreachable)); return }
                    completionHandler(ProviderItem(item), remaining, false, nil)
                case .failure(let error): completionHandler(nil, changedFields, false, providerError(error))
                default: completionHandler(nil, changedFields, false, NSFileProviderError(.serverUnreachable))
                }
            }
        } catch { completionHandler(nil, changedFields, false, providerError(error)); return Progress() }
    }
    func deleteItem(identifier: NSFileProviderItemIdentifier, baseVersion: NSFileProviderItemVersion,
                    options: NSFileProviderDeleteItemOptions, request: NSFileProviderRequest,
                    completionHandler: @escaping (Error?) -> Void) -> Progress {
        do {
            let input = ProviderMutationInput(kind: "delete", id: try catalogIdentifier(identifier),
                parent: "root", name: "delete", directory: false, base: baseVersion.contentVersion,
                metadata: baseVersion.metadataVersion, contents: nil, options: UInt64(options.rawValue))
            return worker.submit(.mutate(input)) { result in
                switch result {
                case .success(.mutation): completionHandler(nil)
                case .failure(let error): completionHandler(providerError(error))
                default: completionHandler(NSFileProviderError(.serverUnreachable))
                }
            }
        } catch { completionHandler(providerError(error)); return Progress() }
    }
}
