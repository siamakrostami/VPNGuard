import Foundation

public enum ProtectedItemKind: String, Codable, CaseIterable, Sendable { case command, application }

public struct ProtectedItem: Identifiable, Codable, Equatable, Sendable {
    public var id: UUID
    public var name: String
    public var kind: ProtectedItemKind
    public var targetPath: String
    public var commandName: String?
    public var isEnabled: Bool
    public var addedAt: Date
    public init(id: UUID = UUID(), name: String, kind: ProtectedItemKind, targetPath: String, commandName: String? = nil,
                isEnabled: Bool = true, addedAt: Date = Date()) throws {
        self.id = id; self.name = name; self.kind = kind; self.targetPath = targetPath
        self.commandName = commandName; self.isEnabled = isEnabled; self.addedAt = addedAt
        try validate()
    }
    public static func validCommandName(_ value: String) -> Bool {
        let reserved: Set<String> = ["if","then","else","elif","fi","for","foreach","end","while","until","do","done","case","esac","function","select","repeat","in","time","coproc","exec","command","builtin","source"]
        guard !reserved.contains(value), !value.isEmpty, value.count <= 80, let first = value.first, first.isASCII,
              first.isLetter || first == "_" else { return false }
        return value.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_" || $0 == "-") }
    }
    public func validate() throws {
        guard !name.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty, name.count < 200,
              targetPath.hasPrefix("/"), !targetPath.contains("\0"), targetPath.count < 4096 else {
            throw GuardError.invalid("Choose a name and an absolute executable or app path.")
        }
        if kind == .command {
            guard let commandName, Self.validCommandName(commandName) else { throw GuardError.invalid("Command names can contain letters, numbers, dashes and underscores, and must start with a letter or underscore.") }
        }
        if kind == .application && !targetPath.lowercased().hasSuffix(".app") { throw GuardError.invalid("Choose a macOS .app bundle.") }
    }
}

public struct GuardPreferences: Codable, Sendable {
    public var version = 2
    public var items: [ProtectedItem] = []
    public var protectionEnabled = true
    public var launchAtLogin = false
    public init() {}
    public static func validate(items: [ProtectedItem]) throws {
        guard items.count <= 200 else { throw GuardError.invalid("This version supports up to 200 protected items.") }
        var ids = Set<UUID>(), commands = Set<String>()
        for item in items {
            try item.validate()
            guard ids.insert(item.id).inserted else { throw GuardError.invalid("Duplicate rule identifier.") }
            if item.kind == .command, let name = item.commandName {
                guard commands.insert(name).inserted else { throw GuardError.invalid("There is already a rule for the command \(name).") }
            }
        }
    }
}

public struct RuleStore: Sendable {
    public let url: URL
    public init(url: URL? = nil) {
        self.url = url ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/VPNGuard/rules.json")
    }
    public func load() throws -> GuardPreferences {
        guard FileManager.default.fileExists(atPath: url.path) else { return GuardPreferences() }
        let data = try Data(contentsOf: url)
        guard data.count <= 2_000_000 else { throw GuardError.invalid("The rule file is unexpectedly large.") }
        let settings = try JSONDecoder().decode(GuardPreferences.self, from: data)
        guard settings.version == 2 else { throw GuardError.invalid("The rule file uses an unsupported version.") }
        try GuardPreferences.validate(items: settings.items)
        return settings
    }
    public func save(_ settings: GuardPreferences) throws {
        try GuardPreferences.validate(items: settings.items)
        let folder = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try encoder.encode(settings).write(to: url, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
