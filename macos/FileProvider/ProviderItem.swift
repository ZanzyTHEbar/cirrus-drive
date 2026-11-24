import FileProvider
import Foundation
import UniformTypeIdentifiers

func providerError(_ error: Error) -> Error {
    switch error {
    case RetainedError.cancelled: return CocoaError(.userCancelled)
    case RetainedError.pageExpired: return NSFileProviderError(.pageExpired)
    case RetainedError.anchorExpired: return NSFileProviderError(.syncAnchorExpired)
    case RetainedError.stale:
        if #available(macOS 12.3, *) { return NSFileProviderError(.versionNoLongerAvailable) }
        return NSFileProviderError(.serverUnreachable)
    case RetainedError.capacity: return CocoaError(.fileWriteOutOfSpace)
    case RetainedError.mutationConflict, RetainedError.mutationUncertain:
        return NSFileProviderError(.cannotSynchronize)
    case RetainedError.mutationUnsupported: return CocoaError(.featureUnsupported)
    case RetainedError.mutationPending: return NSFileProviderError(.serverUnreachable)
    case RetainedError.confirmedDeleted: return NSFileProviderError(.noSuchItem)
    default: return NSFileProviderError(.serverUnreachable)
    }
}
func catalogIdentifier(_ identifier: NSFileProviderItemIdentifier) throws -> String {
    switch identifier {
    case .rootContainer: return "root"
    case .workingSet: return "working-set"
    case .trashContainer: throw CocoaError(.featureUnsupported)
    default: return identifier.rawValue
    }
}
final class ProviderItem: NSObject, NSFileProviderItem {
    let value: CatalogItem
    init(_ value: CatalogItem) { self.value = value }
    var itemIdentifier: NSFileProviderItemIdentifier {
        value.id == "root" ? .rootContainer : NSFileProviderItemIdentifier(value.id)
    }
    var parentItemIdentifier: NSFileProviderItemIdentifier {
        value.parent == "root" ? .rootContainer : NSFileProviderItemIdentifier(value.parent)
    }
    var filename: String { value.name }
    var contentType: UTType {
        value.directory ? .folder : UTType(filenameExtension: (value.name as NSString).pathExtension) ?? .data
    }
    var contentModificationDate: Date? { Date(timeIntervalSince1970: TimeInterval(value.modified)) }
    var capabilities: NSFileProviderItemCapabilities {
        if value.id == "root" { return [.allowsContentEnumerating, .allowsAddingSubItems] }
        let mutations: NSFileProviderItemCapabilities = [.allowsRenaming, .allowsReparenting, .allowsDeleting]
        return mutations.union(value.directory ? [.allowsContentEnumerating, .allowsAddingSubItems] : [.allowsReading, .allowsWriting])
    }
    var documentSize: NSNumber? { value.size.map { NSNumber(value: $0) } }
    var itemVersion: NSFileProviderItemVersion {
        NSFileProviderItemVersion(contentVersion: value.contentVersion,
                                  metadataVersion: Data(value.metadata_revision.utf8))
    }
}
