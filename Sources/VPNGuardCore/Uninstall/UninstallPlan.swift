import Foundation
import Darwin

public struct UninstallReport: Sendable {
    /// Completed removals, or proposed removals when returned by preview().
    public var removed: [String] = []
    public var left: [String] = []
    /// Instructions only. The uninstaller never executes these commands.
    public var manualCommands: [String] = [
        "sudo rm -rf -- /private/var/db/com.siamak.VPNGuard",
        "sudo rm -f -- /private/var/log/VPNGuard.log"
    ]
    public init() {}
}

/// Local file cleanup only. The caller must successfully unregister login/background
/// services before execute(). No processes, VPNs, Keychain items, or system paths are touched.
public struct UninstallPlan: Sendable {
    public let home: URL
    public init(home: URL) { self.home = home }
    public func preview() throws -> UninstallReport { try prepare().report }
    public func execute() throws -> UninstallReport {
        let plan = try prepare()
        // Validate every file before the first mutation; each action checks again on use.
        for action in plan.actions { try action.validate() }
        for action in plan.actions { try action.apply() }
        return plan.report
    }

    private func prepare() throws -> PreparedUninstall {
        let root = try UninstallDirectory.home(home)
        let library = try root.child("Library")
        let applicationSupport = try library?.child("Application Support")
        let support = try applicationSupport?.child("VPNGuard")
        let preferences = try library?.child("Preferences")
        var plan = PreparedUninstall()
        // Perform the shell preflight before scheduling removal of any support files.
        if let shell = try root.file(".zshrc") {
            guard let original = String(data: shell.data, encoding: .utf8) else {
                throw GuardError.invalid(".zshrc is not UTF-8. No uninstall files were changed.")
            }
            let clean = try CommandIntegration.removeZshBlock(original)
            if clean != original {
                var replacement = Data(clean.utf8)
                if let backups = try support?.child("Backups") {
                    for name in try backups.names() where Self.backupName(name) {
                        guard let backup = try? backups.file(name), let text = String(data: backup.data, encoding: .utf8),
                              !text.contains(CommandIntegration.begin), !text.contains(CommandIntegration.end) else { continue }
                        if try CommandIntegration.renderZsh(original: text, hookPath: CommandIntegration(home: home).hook.path) == original {
                            replacement = backup.data; break
                        }
                    }
                }
                plan.actions.append(.replace(shell, replacement))
                plan.report.removed.append(shell.path + " (VPNGuard shell block)")
            }
        }
        if let support {
            let manifest = (try? support.file("managed-commands.json")).flatMap { try? JSONDecoder().decode([String].self, from: $0.data) } ?? []
            let commandNames = Set(manifest.filter(ProtectedItem.validCommandName))
            let settings = (try? support.file("rules.json")).flatMap { try? JSONDecoder().decode(GuardPreferences.self, from: $0.data) }
            let ruleIDs = Set(settings?.items.map(\.id) ?? [])
            let names = try support.names()
            var allRemoved = true
            for name in names {
                switch name {
                case "Backups", "bin", "Sessions", "Launchers":
                    do {
                        guard let directory = try support.child(name) else { continue }
                        var childrenRemoved = true
                        for child in try directory.names() {
                            let recognized: (Data) -> Bool = { data in
                                switch name {
                                case "Backups": return Self.backupName(child) && String(data: data, encoding: .utf8) != nil
                                case "bin":
                                    guard commandNames.contains(child), let text = String(data: data, encoding: .utf8) else { return false }
                                    return Self.managedWrapper(text, config: support.path + "/rules.json")
                                case "Sessions": return Self.managedSession(child, data: data, ruleIDs: ruleIDs)
                                case "Launchers":
                                    return Self.managedLauncher(child, data: data, config: support.path + "/rules.json", ruleIDs: ruleIDs)
                                default: return false
                                }
                            }
                            if !plan.removeFile(directory, child, recognized: recognized) { childrenRemoved = false }
                        }
                        if childrenRemoved { plan.removeDirectory(directory, parent: support, name: name) }
                        else { allRemoved = false }
                    } catch {
                        plan.leave(support.path + "/" + name, reason: "unsafe directory; preserved")
                        allRemoved = false
                    }
                default:
                    let recognized: (Data) -> Bool = { data in
                        switch name {
                        case "rules.json":
                            guard let settings = try? JSONDecoder().decode(GuardPreferences.self, from: data), settings.version == 2,
                                  (try? GuardPreferences.validate(items: settings.items)) != nil else { return false }
                            return true
                        case "connection.json": return (try? JSONDecoder().decode(ConnectionSettings.self, from: data)) != nil
                        case "managed-commands.json": return (try? JSONDecoder().decode([String].self, from: data)) != nil
                        case "commands.zsh": return String(data: data, encoding: .utf8)?.hasPrefix("# Managed by VPNGuard. Reload Terminal after changing command rules.\n") == true
                        default: return false
                        }
                    }
                    if !plan.removeFile(support, name, recognized: recognized) { allRemoved = false }
                }
            }
            if allRemoved, let applicationSupport { plan.removeDirectory(support, parent: applicationSupport, name: "VPNGuard") }
        }
        if let preferences {
            _ = plan.removeFile(preferences, "com.siamak.VPNGuard.plist") { data in
                (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) is [String: Any]
            }
        }
        return plan
    }
    private static func backupName(_ name: String) -> Bool {
        name.hasPrefix("zshrc-") && UUID(uuidString: String(name.dropFirst(6))) != nil
    }
    private static func managedWrapper(_ text: String, config: String) -> Bool {
        let lines = text.components(separatedBy: "\n")
        guard lines.count == 4, lines[0] == "#!/bin/zsh",
              lines[1] == "# Managed by VPNGuard. VPN verification happens on every invocation.",
              lines[2].hasPrefix("exec '"), lines[2].contains("/VPNGuardRun' --rule '"),
              lines[2].hasSuffix(" --config \(ShellArgument.quote(config)) -- \"$@\""), lines[3].isEmpty else { return false }
        return true
    }
    private static func unquotePath(_ quoted: String) -> String? {
        guard quoted.hasPrefix("'"), quoted.hasSuffix("'"), quoted.count >= 2 else { return nil }
        let path = String(quoted.dropFirst().dropLast()).replacingOccurrences(of: "'\\''", with: "'")
        guard path.hasPrefix("/"), !path.contains("\0"), !path.contains("\n"),
              !path.split(separator: "/").contains(where: { $0 == "." || $0 == ".." }),
              ShellArgument.quote(path) == quoted else { return nil }
        return path
    }
    private static func managedLauncher(_ name: String, data: Data, config: String, ruleIDs: Set<UUID>) -> Bool {
        guard name.hasSuffix(".command"), UUID(uuidString: String(name.dropLast(8))) != nil,
              let text = String(data: data, encoding: .utf8) else { return false }
        let lines = text.components(separatedBy: "\n")
        guard lines.count >= 3, lines[0] == "#!/bin/zsh",
              lines[1].hasPrefix("cd -- "), lines[1].hasSuffix(" || exit 1"),
              let directory = unquotePath(String(lines[1].dropFirst(6).dropLast(10))) else { return false }
        let suffix = " --config \(ShellArgument.quote(config)) --"
        guard lines[2].hasSuffix(suffix) else { return false }
        let invocation = String(lines[2].dropLast(suffix.count))
        guard let separator = invocation.range(of: " --rule '", options: .backwards), invocation.hasSuffix("'"),
              let runner = unquotePath(String(invocation[..<separator.lowerBound])),
              URL(fileURLWithPath: runner).lastPathComponent == "VPNGuardRun",
              let id = UUID(uuidString: String(invocation[separator.upperBound...].dropLast())), ruleIDs.contains(id) else { return false }
        return text == CommandLauncher.script(runner: runner, ruleID: id, config: config, directory: URL(fileURLWithPath: directory))
    }
    private static func managedSession(_ name: String, data: Data, ruleIDs: Set<UUID>) -> Bool {
        if name.hasSuffix(".json"), let id = UUID(uuidString: String(name.dropLast(5))),
           let session = try? JSONDecoder().decode(GuardSessionRecord.self, from: data) { return session.id == id }
        if name.hasSuffix(".reset"), let id = UUID(uuidString: String(name.dropLast(6))) { return data == Data(id.uuidString.utf8) }
        if name.hasPrefix("launch-"), name.hasSuffix(".log"), let id = UUID(uuidString: String(name.dropFirst(7).dropLast(4))) { return ruleIDs.contains(id) }
        return false
    }
}

public enum VPNGuardUninstaller {
    public static func execute(home: URL = FileManager.default.homeDirectoryForCurrentUser) throws -> UninstallReport {
        try UninstallPlan(home: home).execute()
    }
}

private struct PreparedUninstall {
    var report = UninstallReport()
    var actions: [UninstallAction] = []
    mutating func leave(_ path: String, reason: String) { report.left.append(path + " (" + reason + ")") }
    mutating func removeFile(_ directory: UninstallDirectory, _ name: String, recognized: (Data) -> Bool) -> Bool {
        do {
            guard let file = try directory.file(name) else { return true }
            guard recognized(file.data) else { leave(file.path, reason: "unrecognized file; preserved"); return false }
            actions.append(.delete(file)); report.removed.append(file.path); return true
        } catch { leave(directory.path + "/" + name, reason: "unsafe or unreadable file; preserved"); return false }
    }
    mutating func removeDirectory(_ directory: UninstallDirectory, parent: UninstallDirectory, name: String) {
        actions.append(.directory(directory, parent, name)); report.removed.append(directory.path)
    }
}

private enum UninstallAction {
    case replace(UninstallFile, Data), delete(UninstallFile), directory(UninstallDirectory, UninstallDirectory, String)
    func validate() throws {
        switch self {
        case .replace(let file, _), .delete(let file): try file.validate()
        case .directory(let directory, let parent, let name): try directory.validateEntry(parent: parent, name: name)
        }
    }
    func apply() throws {
        try validate()
        switch self {
        case .delete(let file):
            guard unlinkat(file.parent.fd, file.name, 0) == 0 else { throw failure(file.path) }
        case .directory(let directory, let parent, let name):
            // Never recursively delete. A newly added or unknown entry prevents rmdir.
            guard unlinkat(parent.fd, name, AT_REMOVEDIR) == 0 else { throw failure(directory.path) }
        case .replace(let file, let data):
            let name = ".VPNGuard-uninstall-" + UUID().uuidString
            let fd = openat(file.parent.fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
            guard fd >= 0 else { throw failure(file.path) }
            defer { Darwin.close(fd); unlinkat(file.parent.fd, name, 0) }
            try data.withUnsafeBytes { bytes in
                var offset = 0
                while offset < bytes.count {
                    let count = Darwin.write(fd, bytes.baseAddress!.advanced(by: offset), bytes.count - offset)
                    if count < 0 && errno == EINTR { continue }
                    guard count > 0 else { throw failure(file.path) }
                    offset += count
                }
            }
            guard fchmod(fd, file.metadata.st_mode & 0o777) == 0, fsync(fd) == 0 else { throw failure(file.path) }
            try file.validate()
            guard renameat(file.parent.fd, name, file.parent.fd, file.name) == 0 else { throw failure(file.path) }
        }
    }
}

private func failure(_ path: String) -> GuardError {
    .invalid("Uninstall refused an unsafe or changed file: \(path).")
}
private func sameIdentity(_ first: stat, _ second: stat) -> Bool {
    first.st_dev == second.st_dev && first.st_ino == second.st_ino && first.st_uid == second.st_uid && first.st_mode == second.st_mode && (first.st_mode & S_IFMT == S_IFDIR || first.st_nlink == second.st_nlink)
}

/// Every operation after home is opened is anchored to held directory descriptors.
/// O_NOFOLLOW rejects symlinks, device comparison rejects mounted replacements, and
/// owner/mode checks reject directories writable by another account.
private final class UninstallDirectory {
    let fd: Int32
    let path: String
    let metadata: stat
    private init(fd: Int32, path: String, metadata: stat) { self.fd = fd; self.path = path; self.metadata = metadata }
    deinit { Darwin.close(fd) }
    static func home(_ url: URL) throws -> UninstallDirectory {
        guard url.isFileURL, url.path.hasPrefix("/"), url.path != "/", !url.pathComponents.contains("..") else { throw failure(url.path) }
        var current = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard current >= 0 else { throw failure(url.path) }
        for part in url.pathComponents.dropFirst() {
            let next = openat(current, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            Darwin.close(current)
            guard next >= 0 else { throw failure(url.path) }
            current = next
        }
        var info = stat()
        guard fstat(current, &info) == 0, info.st_uid == getuid(), info.st_mode & 0o022 == 0 else {
            Darwin.close(current); throw failure(url.path)
        }
        return UninstallDirectory(fd: current, path: url.path, metadata: info)
    }
    func info(_ name: String) throws -> stat? {
        guard !name.isEmpty, name != ".", name != "..", !name.contains("/"), !name.contains("\0") else { throw failure(path) }
        var info = stat()
        if fstatat(fd, name, &info, AT_SYMLINK_NOFOLLOW) != 0 {
            if errno == ENOENT { return nil }
            throw failure(path + "/" + name)
        }
        return info
    }
    func child(_ name: String) throws -> UninstallDirectory? {
        guard let info = try info(name) else { return nil }
        guard info.st_mode & S_IFMT == S_IFDIR, info.st_uid == getuid(), info.st_dev == metadata.st_dev, info.st_mode & 0o022 == 0 else { throw failure(path + "/" + name) }
        let child = openat(fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard child >= 0 else { throw failure(path + "/" + name) }
        var opened = stat()
        guard fstat(child, &opened) == 0, sameIdentity(info, opened) else { Darwin.close(child); throw failure(path + "/" + name) }
        return UninstallDirectory(fd: child, path: path + "/" + name, metadata: opened)
    }
    func file(_ name: String) throws -> UninstallFile? {
        guard let info = try info(name) else { return nil }
        guard info.st_mode & S_IFMT == S_IFREG, info.st_uid == getuid(), info.st_dev == metadata.st_dev,
              info.st_nlink == 1, info.st_size >= 0, info.st_size <= 2_000_000 else { throw failure(path + "/" + name) }
        let opened = openat(fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard opened >= 0 else { throw failure(path + "/" + name) }
        defer { Darwin.close(opened) }
        var checked = stat()
        guard fstat(opened, &checked) == 0, sameIdentity(info, checked) else { throw failure(path + "/" + name) }
        var data = Data(), bytes = [UInt8](repeating: 0, count: 8192)
        while true {
            let count = Darwin.read(opened, &bytes, bytes.count)
            if count < 0 && errno == EINTR { continue }
            guard count >= 0, data.count + max(0, count) <= 2_000_000 else { throw failure(path + "/" + name) }
            if count == 0 { break }
            data.append(contentsOf: bytes.prefix(count))
        }
        return UninstallFile(parent: self, name: name, metadata: checked, data: data)
    }
    func names() throws -> [String] {
        let copy = dup(fd)
        guard copy >= 0 else { throw failure(path) }
        guard let directory = fdopendir(copy) else { Darwin.close(copy); throw failure(path) }
        defer { closedir(directory) }
        // dup shares the directory offset; rewind makes repeated inspections deterministic.
        rewinddir(directory)
        var result: [String] = []
        while let entry = readdir(directory) {
            let name = withUnsafePointer(to: &entry.pointee.d_name) { pointer in
                pointer.withMemoryRebound(to: CChar.self, capacity: Int(entry.pointee.d_namlen) + 1) { String(cString: $0) }
            }
            if name != "." && name != ".." { result.append(name) }
            guard result.count <= 10_000 else { throw failure(path) }
        }
        return result.sorted()
    }
    func validateEntry(parent: UninstallDirectory, name: String) throws {
        guard let current = try parent.info(name), sameIdentity(metadata, current) else { throw failure(path) }
    }
}
private struct UninstallFile {
    let parent: UninstallDirectory
    let name: String
    let metadata: stat
    let data: Data
    var path: String { parent.path + "/" + name }
    func validate() throws {
        guard let current = try parent.file(name), sameIdentity(metadata, current.metadata), data == current.data else { throw failure(path) }
    }
}
