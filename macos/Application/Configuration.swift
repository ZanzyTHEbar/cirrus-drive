import Foundation

enum ConfigurationError: Error { case usage, invalid }

// Only explicit non-secret configuration. No defaults, HOME or UserDefaults
// storage path. Unknown keys are rejected, including accidental credentials.
struct ApplicationConfiguration: Sendable {
    let appGroup: String
    let keychainGroup: String
    let instance: String

    static func read(_ path: String) throws -> Self {
        let url = URL(fileURLWithPath: path)
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        guard let data = try handle.read(upToCount: 16385), data.count <= 16384,
              let values = try JSONSerialization.jsonObject(with: data) as? [String: String],
              Set(values.keys) == ["appGroup", "keychainGroup", "instance"],
              let group = values["appGroup"], let keychain = values["keychainGroup"],
              let instance = values["instance"],
              [group, keychain, instance].allSatisfy({
                  !$0.isEmpty && $0.utf8.count <= 4096 &&
                  !$0.unicodeScalars.contains(where: CharacterSet.controlCharacters.contains)
              }),
              let parts = URLComponents(string: instance),
              parts.scheme == "https", let host = parts.host, !host.isEmpty,
              parts.user == nil, parts.password == nil, parts.query == nil, parts.fragment == nil
        else { throw ConfigurationError.invalid }
        return Self(appGroup: group, keychainGroup: keychain, instance: instance)
    }
}
