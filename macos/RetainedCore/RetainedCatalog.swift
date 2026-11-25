import CirrusRetained
import Foundation

private let mutationProgress: CirrusMutationProgress = { context, done, total in
    guard let context, total <= UInt64(Int64.max), done <= total else { return }
    let progress = Unmanaged<Progress>.fromOpaque(context).takeUnretainedValue()
    progress.totalUnitCount = Int64(max(total, 1))
    progress.completedUnitCount = Int64(done)
}
struct CatalogItem: Codable, Sendable {
    let id: String
    let remote: String
    let parent: String
    let name: String
    let directory: Bool
    let etag: String?
    let size: UInt64?
    let modified: UInt64
    let metadata_revision: String

    var contentVersion: Data {
        // The catalog itself is principal/instance/Space bound. JSON preserves
        // exact tuple boundaries (no concatenation collisions).
        (try? JSONEncoder().encode([remote, etag ?? "", size.map(String.init) ?? ""])) ?? Data()
    }
}
struct CatalogPage: Decodable, Sendable {
    let items: [CatalogItem]
    let next: String?
    let anchor: String
}
struct CatalogChanges: Decodable, Sendable {
    let items: [CatalogItem]
    let deleted: [String]
    let anchor: String
    let more: Bool
    let authoritative: Bool
}
struct ProviderMutationInput: Sendable {
    let kind: String
    let id: String?
    let parent: String
    let name: String
    let directory: Bool
    let base: Data?
    let metadata: Data?
    let contents: URL?
    let options: UInt64
}
struct MutationReply: Decodable, Sendable {
    let item: CatalogItem?
    let deleted: [String]
    let operation_ids: [Int64]
}
final class RetainedCatalog: RetainedHandle {
    func mutate(_ input: ProviderMutationInput, request: RetainedRequest, progress: Progress) throws -> MutationReply {
        onOwnerThread()
        struct Descriptor: Encodable {
            let kind: String, id: String?, parent: String, name: String
            let directory: Bool, base: [String]?, metadata: String?, contents: Bool
            let options: UInt64
        }
        let base = try input.base.map { try JSONDecoder().decode([String].self, from: $0) }
        let metadata = input.metadata.flatMap { String(data: $0, encoding: .utf8) }
        guard input.metadata == nil || metadata != nil,
              input.contents == nil || input.contents?.isFileURL == true else { throw RetainedError.invalidABI }
        let value = Descriptor(kind: input.kind, id: input.id, parent: input.parent, name: input.name,
                               directory: input.directory, base: base, metadata: metadata,
                               contents: input.contents != nil, options: input.options)
        let data = try JSONEncoder().encode(value)
        guard let json = String(data: data, encoding: .utf8), data.count <= 16384 else { throw RetainedError.invalidABI }
        var bytes = [UInt8](repeating: 0, count: Int(CIRRUS_RETAINED_PAGE_BYTES))
        var written = 0
        try withRetainedText(json) { descriptor in
            try withRetainedText(input.contents?.path ?? "") { source in
                try bytes.withUnsafeMutableBufferPointer {
                    try checked(cirrus_catalog_mutate(raw, descriptor, source, request.raw,
                                                      mutationProgress, Unmanaged.passUnretained(progress).toOpaque(),
                                                      $0.baseAddress, $0.count, &written))
                }
            }
        }
        guard written > 0, written <= bytes.count else { throw RetainedError.internalFailure }
        return try JSONDecoder().decode(MutationReply.self, from: Data(bytes.prefix(written)))
    }
    convenience init(core: RetainedCore, domain: String) throws {
        core.onOwnerThread()
        var raw: UnsafeMutableRawPointer?
        try withRetainedText(domain) { try checked(cirrus_catalog_resume(core.raw, $0, &raw)) }
        guard let raw else { throw RetainedError.internalFailure }
        self.init(taking: raw)
    }
    private func read<T: Decodable>(_ operation: UInt32, _ identifier: String, _ argument: String,
                                     request: RetainedRequest) throws -> T {
        onOwnerThread()
        var bytes = [UInt8](repeating: 0, count: Int(CIRRUS_RETAINED_PAGE_BYTES))
        var written = 0
        try withRetainedText(identifier) { identifier in
            try withRetainedText(argument) { argument in
                try bytes.withUnsafeMutableBufferPointer {
                    try checked(cirrus_catalog_read(raw, operation, identifier, argument, request.raw,
                                                    $0.baseAddress, $0.count, &written))
                }
            }
        }
        guard written >= 0, written <= bytes.count else { throw RetainedError.internalFailure }
        return try JSONDecoder().decode(T.self, from: Data(bytes.prefix(written)))
    }
    func capture(container: String, sort: String, request: RetainedRequest) throws -> String {
        try read(0, container, sort, request: request)
    }
    func page(container: String, token: String, request: RetainedRequest) throws -> CatalogPage {
        guard token.utf8.count < 500 else { throw RetainedError.pageExpired }
        return try read(1, container, token, request: request)
    }
    func lookup(_ id: String, request: RetainedRequest) throws -> CatalogItem {
        try read(2, id, "", request: request)
    }
    func changes(anchor: String?, request: RetainedRequest) throws -> CatalogChanges {
        try read(3, "", anchor ?? "", request: request)
    }
    func open(_ item: CatalogItem, request: RetainedRequest) throws -> RetainedVersion {
        onOwnerThread()
        guard let etag = item.etag, let size = item.size, !item.directory else { throw RetainedError.unavailable }
        var result: UnsafeMutableRawPointer?
        try withRetainedText(item.id) { id in
            try withRetainedText(etag) {
                try checked(cirrus_catalog_open_version(raw, id, $0, size, request.raw, &result))
            }
        }
        guard let result else { throw RetainedError.internalFailure }
        return RetainedVersion(taking: result)
    }
}
