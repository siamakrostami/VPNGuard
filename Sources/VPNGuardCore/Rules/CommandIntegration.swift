import Foundation

public struct CommandIntegration: Sendable {
    public static let begin = "# >>> VPNGuard command integration >>>"
    public static let end = "# <<< VPNGuard command integration <<<"
    public let home: URL
    public var support: URL { home.appendingPathComponent("Library/Application Support/VPNGuard") }
    public var hook: URL { support.appendingPathComponent("commands.zsh") }
    public var bin: URL { support.appendingPathComponent("bin", isDirectory: true) }
    public var zshrc: URL { home.appendingPathComponent(".zshrc") }
    public init(home: URL = FileManager.default.homeDirectoryForCurrentUser) { self.home = home }

    public static func wrapper(item: ProtectedItem, runner: String, config: String) -> String {
        "#!/bin/zsh\n# Managed by VPNGuard. VPN verification happens on every invocation.\nexec \(ShellArgument.quote(runner)) --rule \(ShellArgument.quote(item.id.uuidString)) --config \(ShellArgument.quote(config)) -- \"$@\"\n"
    }
    public static func removeZshBlock(_ text: String) throws -> String {
        let starts = text.components(separatedBy: begin).count - 1, ends = text.components(separatedBy: end).count - 1
        guard starts == ends, starts <= 1 else { throw GuardError.invalid("The VPNGuard block in .zshrc was edited or is incomplete. It was not overwritten.") }
        guard starts == 1, let start = text.range(of: "\n" + begin + "\n"),
              let finish = text.range(of: "\n" + end + "\n", range: start.upperBound..<text.endIndex) else {
            if starts > 0 { throw GuardError.invalid("The VPNGuard block in .zshrc has an unexpected format. It was not changed.") }
            return text
        }
        var result = text; result.removeSubrange(start.lowerBound..<finish.upperBound); return result
    }
    public static func renderZsh(original: String, hookPath: String) throws -> String {
        let original = try removeZshBlock(original)
        return original + "\n\(begin)\nif [[ -r \(ShellArgument.quote(hookPath)) ]]; then\n  source \(ShellArgument.quote(hookPath))\nfi\n\(end)\n"
    }
    public var isInstalled: Bool {
        guard let text = try? String(contentsOf: zshrc, encoding: .utf8) else { return false }
        return text.contains(Self.begin) && text.contains(ShellArgument.quote(hook.path))
    }
    public func install(items: [ProtectedItem], runner: String, config: String) throws {
        guard FileManager.default.isExecutableFile(atPath: runner) else { throw GuardError.invalid("The bundled command runner is missing.") }
        let attributes = try? FileManager.default.attributesOfItem(atPath: zshrc.path)
        if attributes?[.type] as? FileAttributeType == .typeSymbolicLink {
            throw GuardError.invalid(".zshrc is a symbolic link. Add the source line shown in Settings to its target manually; VPNGuard will not replace the link.")
        }
        let original = FileManager.default.fileExists(atPath: zshrc.path) ? try String(contentsOf: zshrc, encoding: .utf8) : ""
        let updated = try Self.renderZsh(original: original, hookPath: hook.path)
        try synchronize(items: items, runner: runner, config: config)
        let backups = support.appendingPathComponent("Backups", isDirectory: true)
        try FileManager.default.createDirectory(at: backups, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        if original != updated {
            let backup = backups.appendingPathComponent("zshrc-" + UUID().uuidString)
            try Data(original.utf8).write(to: backup, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: backup.path)
            let current = FileManager.default.fileExists(atPath: zshrc.path) ? try String(contentsOf: zshrc, encoding: .utf8) : ""
            guard current == original else { throw GuardError.invalid(".zshrc changed during setup. Try again after your editor finishes saving.") }
            try Data(updated.utf8).write(to: zshrc, options: .atomic)
            let permissions = attributes?[.posixPermissions] ?? 0o600
            try FileManager.default.setAttributes([.posixPermissions: permissions], ofItemAtPath: zshrc.path)
        }
    }
    public func synchronize(items: [ProtectedItem], runner: String, config: String) throws {
        try GuardPreferences.validate(items: items)
        try FileManager.default.createDirectory(at: bin, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let manifest = support.appendingPathComponent("managed-commands.json")
        let previous = (try? JSONDecoder().decode([String].self, from: Data(contentsOf: manifest))) ?? []
        let active = items.filter { $0.kind == .command && $0.isEnabled }
        let names = active.compactMap(\.commandName)
        for old in previous where ProtectedItem.validCommandName(old) && !names.contains(old) {
            let file = bin.appendingPathComponent(old)
            if let text = try? String(contentsOf: file, encoding: .utf8), text.hasPrefix("#!/bin/zsh\n# Managed by VPNGuard.") {
                try FileManager.default.removeItem(at: file)
            }
        }
        for item in active {
            guard let name = item.commandName else { continue }
            let file = bin.appendingPathComponent(name)
            if let existing = try? String(contentsOf: file, encoding: .utf8), !existing.hasPrefix("#!/bin/zsh\n# Managed by VPNGuard.") {
                throw GuardError.invalid("A file named \(name) already exists in VPNGuard’s command folder. It was not overwritten.")
            }
            try Data(Self.wrapper(item: item, runner: runner, config: config).utf8).write(to: file, options: .atomic)
            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: file.path)
        }
        let allKnown = Set(previous.filter(ProtectedItem.validCommandName) + names).sorted()
        var text = "# Managed by VPNGuard. Reload Terminal after changing command rules.\n"
        for name in allKnown { text += "builtin unalias -- \(name) 2>/dev/null || true\nbuiltin unfunction -- \(name) 2>/dev/null || true\n" }
        text += "export PATH=\(ShellArgument.quote(bin.path)):\"$PATH\"\n"
        for item in active {
            guard let name = item.commandName else { continue }
            text += "function \(name) {\n  command \(ShellArgument.quote(bin.appendingPathComponent(name).path)) \"$@\"\n}\n"
        }
        // Do not leave a failure exit code from unalias/unfunction in a user's shell startup.
        text += "true\n"
        try Data(text.utf8).write(to: hook, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: hook.path)
        try JSONEncoder().encode(names).write(to: manifest, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: manifest.path)
    }
    public func uninstall() throws {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: zshrc.path) else { return }
        guard attributes[.type] as? FileAttributeType != .typeSymbolicLink else { throw GuardError.invalid(".zshrc is a symbolic link. Remove the VPNGuard source block from its target manually.") }
        let original = try String(contentsOf: zshrc, encoding: .utf8)
        let clean = try Self.removeZshBlock(original)
        guard clean != original else { return }
        guard try String(contentsOf: zshrc, encoding: .utf8) == original else { throw GuardError.invalid(".zshrc changed while removing integration. Try again.") }
        try Data(clean.utf8).write(to: zshrc, options: .atomic)
        if let permissions = attributes[.posixPermissions] { try FileManager.default.setAttributes([.posixPermissions: permissions], ofItemAtPath: zshrc.path) }
        // Existing shells retain their functions until restarted. Keep wrappers fail-closed.
    }
}
