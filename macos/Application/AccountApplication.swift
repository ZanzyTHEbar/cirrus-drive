import CirrusRetained
import Foundation

struct ApplicationSpace: Decodable, Sendable {
    let id: String
    let name: String
}

struct FinderDomainDescriptor: Decodable, Sendable {
    let domain: String
}
struct RestoredFinderDomains: Decodable, Sendable {
    let domains: [FinderDomainDescriptor]
    let unavailable: Int
}

struct ApplicationBindingIdentity: Decodable, Sendable {
    let instance: String
    let space: String
    let issuer: String
    let subject: String
}

final class ApplicationAttempt: RetainedHandle {
    convenience init() throws {
        var pointer: UnsafeMutableRawPointer?
        try checked(cirrus_application_attempt(&pointer))
        guard let pointer else { throw RetainedError.internalFailure }
        self.init(taking: pointer)
    }
}

final class ApplicationSpaces: RetainedHandle {
    func page(after: Int) throws -> (spaces: [ApplicationSpace], next: Int) {
        onOwnerThread()
        var buffer = [UInt8](repeating: 0, count: Int(CIRRUS_RETAINED_PAGE_BYTES))
        var written = 0
        var next = after
        try buffer.withUnsafeMutableBufferPointer {
            try checked(cirrus_application_space_page(raw, after, $0.baseAddress, $0.count, &written, &next))
        }
        guard written >= 0, written <= buffer.count else { throw RetainedError.internalFailure }
        return (try JSONDecoder().decode([ApplicationSpace].self, from: Data(buffer.prefix(written))), next)
    }
}

extension RetainedCore {
    func restoreFinderDomains() throws -> RestoredFinderDomains {
        try readJSON { buffer, capacity, written in
            cirrus_application_domains_restore(raw, buffer, capacity, written)
        }
    }
    func connect(instance: String, attempt: ApplicationAttempt,
                 browser: CirrusApplicationBrowser, context: UnsafeMutableRawPointer?) throws {
        onOwnerThread()
        try withRetainedText(instance) {
            try checked(cirrus_application_connect(raw, $0, attempt.raw, browser, context))
        }
    }
    func spaces(instance: String) throws -> ApplicationSpaces {
        onOwnerThread()
        var pointer: UnsafeMutableRawPointer?
        try withRetainedText(instance) { instance in
            try checked(cirrus_application_spaces(raw, instance, &pointer))
        }
        guard let pointer else { throw RetainedError.internalFailure }
        return ApplicationSpaces(taking: pointer)
    }
    func bindOnline(instance: String, space: String) throws -> RetainedBinding {
        onOwnerThread()
        var pointer: UnsafeMutableRawPointer?
        try withRetainedText(instance) { instance in
            try withRetainedText(space) { space in
                try checked(cirrus_application_bind(raw, instance, space, &pointer))
            }
        }
        guard let pointer else { throw RetainedError.internalFailure }
        return RetainedBinding(taking: pointer)
    }
}

extension RetainedBinding {
    func prepareFinderDomain() throws -> FinderDomainDescriptor {
        try readJSON { buffer, capacity, written in
            cirrus_application_domain_prepare(raw, buffer, capacity, written)
        }
    }
    func currentIdentity() throws -> ApplicationBindingIdentity {
        try readJSON { buffer, capacity, written in
            cirrus_application_binding(raw, buffer, capacity, written)
        }
    }
    func observe(path: [String], parentID: String) throws -> RetainedListing {
        onOwnerThread()
        var pointer: UnsafeMutableRawPointer?
        try withRetainedText(try encodedPath(path)) { path in
            try withRetainedText(parentID) {
                try checked(cirrus_application_list(raw, path, $0, &pointer))
            }
        }
        guard let pointer else { throw RetainedError.internalFailure }
        return RetainedListing(taking: pointer)
    }
}
