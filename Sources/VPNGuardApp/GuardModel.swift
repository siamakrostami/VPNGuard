import AppKit
import SwiftUI
import ServiceManagement
import VPNGuardCore

public enum GuardSection: String, CaseIterable, Identifiable {
    case overview = "Overview", rules = "VPN Required", activity = "Activity", settings = "Settings"
    public var id: String { rawValue }
    var symbol: String {
        switch self { case .overview: "square.grid.2x2"; case .rules: "checklist"; case .activity: "waveform.path"; case .settings: "gearshape" }
    }
}

@MainActor @Observable final class GuardModel {
    var preferences = GuardPreferences()
    var section: GuardSection = .overview
    var search = ""
    var selectedRule: UUID?
    var verification: VPNVerification?
    var networkMessage = "Checking for a usable VPN connection."
    var isChecking = false
    var error: String?
    var notice: String?
    var clock = Date()
    var showingAdd = false
    var editing: ProtectedItem?
    var pendingRemoval: ProtectedItem?
    var pendingDesktopLaunch: ProtectedItem?
    var sessions: [GuardSessionRecord] = []
    var integrationInstalled = false
    var launchAtLogin = false
    var projectPath: String
    private let store = RuleStore()
    private let integration = CommandIntegration()
    private var polling: Task<Void, Never>?
    private var clockTask: Task<Void, Never>?
    private var childProcesses: [UUID: Process] = [:]
    private var lastAttempt = Date.distantPast
    private var wantsForceCheck = false
    private let defaults = UserDefaults.standard

    init() {
        projectPath = UserDefaults.standard.string(forKey: "projectPath") ?? NSHomeDirectory()
        do {
            preferences = try store.load()
            if !FileManager.default.fileExists(atPath: store.url.path) {
                for command in ["claude", "codex"] {
                    let path = NSHomeDirectory() + "/.local/bin/" + command
                    if FileManager.default.isExecutableFile(atPath: path) {
                        preferences.items.append(try ProtectedItem(name: command == "claude" ? "Claude CLI" : "Codex CLI", kind: .command, targetPath: path, commandName: command))
                    }
                }
                try store.save(preferences)
            }
        } catch { self.error = error.localizedDescription }
        do { try integration.synchronize(items: preferences.items, runner: runnerPath, config: store.url.path) }
        catch { self.error = error.localizedDescription }
        integrationInstalled = integration.isInstalled
        launchAtLogin = SMAppService.mainApp.status == .enabled
    }
    var runnerPath: String { Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/VPNGuardRun").path }
    var rules: [ProtectedItem] { preferences.items }
    var enabledCount: Int { rules.filter(\.isEnabled).count }
    var filteredRules: [ProtectedItem] {
        rules.filter { search.isEmpty || $0.name.localizedCaseInsensitiveContains(search) || $0.targetPath.localizedCaseInsensitiveContains(search) || ($0.commandName?.localizedCaseInsensitiveContains(search) ?? false) }
    }
    var vpnReady: Bool {
        guard let verification else { return false }
        let age = clock.timeIntervalSince(verification.verifiedAt)
        return age >= 0 && age < 30 && verification.exit.country != "IR"
    }
    var statusTitle: String { vpnReady ? "VPN verified" : (isChecking ? "Verifying VPN" : "Protected launches blocked") }
    var statusSymbol: String { vpnReady ? "checkmark.shield.fill" : (isChecking ? "arrow.triangle.2.circlepath" : "lock.shield.fill") }
    var statusColor: Color { vpnReady ? .mint : .orange }
    var countryName: String {
        guard vpnReady, let code = verification?.exit.country else { return "Not verified" }
        return Locale.current.localizedString(forRegionCode: code) ?? code
    }
    var activeSessions: [GuardSessionRecord] {
        sessions.filter { $0.phase == "running" && clock.timeIntervalSince($0.updatedAt) < 15 && kill($0.processID, 0) == 0 }
    }
    var helperSupported: Bool { FileManager.default.isExecutableFile(atPath: "/usr/bin/sandbox-exec") && FileManager.default.isExecutableFile(atPath: runnerPath) }
    func start() {
        guard polling == nil else { return }
        // Startup was explicitly requested by the user. No privileged helper or account is installed.
        if preferences.launchAtLogin && !launchAtLogin { setLogin(true) }
        clockTask = Task { [weak self] in
            while !Task.isCancelled { self?.clock = Date(); try? await Task.sleep(for: .seconds(1)) }
        }
        polling = Task { [weak self] in
            while !Task.isCancelled {
                guard let self else { return }
                self.loadSessions()
                await self.checkVPN(force: self.wantsForceCheck)
                self.wantsForceCheck = false
                try? await Task.sleep(for: .seconds(2))
            }
        }
    }
    func checkVPN(force: Bool = true) async {
        guard !isChecking else { wantsForceCheck = wantsForceCheck || force; return }
        isChecking = true
        defer { isChecking = false; clock = Date() }
        do {
            let path = try await Task.detached(priority: .utility) { try GenericVPNMonitor().inspect() }.value
            if !force, let old = verification, old.path == path, Date().timeIntervalSince(old.verifiedAt) < 20 { return }
            if !force && Date().timeIntervalSince(lastAttempt) < 10 { return }
            lastAttempt = Date()
            if verification?.path != path { verification = nil }
            let checked = try await Task.detached(priority: .utility) { try GenericVPNMonitor().verify() }.value
            verification = checked
            networkMessage = "The tunnel carries internet traffic, and its latest exit check is outside Iran. Each launch verifies again."
        } catch {
            verification = nil
            networkMessage = error.localizedDescription
        }
    }
    func save(_ item: ProtectedItem) {
        var updated = preferences
        if let index = updated.items.firstIndex(where: { $0.id == item.id }) { updated.items[index] = item } else { updated.items.append(item) }
        commit(updated)
        selectedRule = item.id
    }
    func toggle(_ item: ProtectedItem, enabled: Bool) { var item = item; item.isEnabled = enabled; save(item) }
    func remove(_ item: ProtectedItem) {
        var updated = preferences; updated.items.removeAll { $0.id == item.id }; commit(updated)
        if selectedRule == item.id { selectedRule = nil }
    }
    private func commit(_ updated: GuardPreferences) {
        do {
            try store.save(updated)
            preferences = updated; error = nil
            do { try integration.synchronize(items: updated.items, runner: runnerPath, config: store.url.path) }
            catch {
                self.error = "Rules saved, but command integration was not updated: " + error.localizedDescription
                return
            }
            if integrationInstalled { notice = "Command rules updated. Open a new Terminal window to load the changes." }
        } catch { self.error = error.localizedDescription }
    }
    func commandIsIntegrated(_ item: ProtectedItem) -> Bool {
        guard integrationInstalled, let name = item.commandName else { return false }
        let path = integration.bin.appendingPathComponent(name)
        return (try? String(contentsOf: path, encoding: .utf8)) == CommandIntegration.wrapper(item: item, runner: runnerPath, config: store.url.path)
    }
    func installIntegration() {
        do {
            try integration.install(items: rules, runner: runnerPath, config: store.url.path)
            integrationInstalled = integration.isInstalled
            notice = "Command integration installed. Open a new Terminal window, then type claude or another protected command normally."
        } catch { self.error = error.localizedDescription }
    }
    func removeIntegration() {
        do {
            try integration.uninstall(); integrationInstalled = false
            notice = "Command integration removed. Existing shells keep their functions until you close them."
        } catch { self.error = error.localizedDescription }
    }
    var manualSourceLine: String { "source " + ShellArgument.quote(integration.hook.path) }
    func setLogin(_ enabled: Bool) {
        do {
            if enabled { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
            launchAtLogin = SMAppService.mainApp.status == .enabled
            var updated = preferences; updated.launchAtLogin = enabled
            try store.save(updated); preferences = updated
        } catch { self.error = error.localizedDescription }
    }
    func setLaunchesEnabled(_ enabled: Bool) { var value = preferences; value.protectionEnabled = enabled; commit(value) }
    func chooseProject() {
        let panel = NSOpenPanel(); panel.canChooseDirectories = true; panel.canChooseFiles = false; panel.prompt = "Choose Folder"
        panel.directoryURL = URL(fileURLWithPath: projectPath)
        if panel.runModal() == .OK, let url = panel.url { projectPath = url.path; defaults.set(projectPath, forKey: "projectPath") }
    }
    func launch(_ item: ProtectedItem) {
        guard item.isEnabled, preferences.protectionEnabled, helperSupported else { error = "Enable the rule and ensure the bundled runner and macOS isolation tool are available."; return }
        if item.kind == .application { pendingDesktopLaunch = item; return }
        Task { await run(item) }
    }
    func run(_ item: ProtectedItem) async {
        error = nil
        do {
            let folder = store.url.deletingLastPathComponent().appendingPathComponent("Launchers", isDirectory: true)
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            if item.kind == .command {
                let script = folder.appendingPathComponent(item.id.uuidString + ".command")
                let text = "#!/bin/zsh\ncd -- \(ShellArgument.quote(projectPath)) || exit 1\n\(ShellArgument.quote(runnerPath)) --rule \(ShellArgument.quote(item.id.uuidString)) --config \(ShellArgument.quote(store.url.path)) --\nresult=$?\nif [[ $result -ne 0 ]]; then printf '\\nVPNGuard stopped this launch (status %s).\\n' \"$result\"; fi\nexit $result\n"
                try Data(text.utf8).write(to: script, options: .atomic)
                try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)
                guard let terminal = NSWorkspace.shared.urlForApplication(withBundleIdentifier: "com.apple.Terminal") else { throw GuardError.invalid("Terminal was not found.") }
                let config = NSWorkspace.OpenConfiguration(); config.activates = true
                _ = try await NSWorkspace.shared.open([script], withApplicationAt: terminal, configuration: config)
            } else {
                let logs = store.url.deletingLastPathComponent().appendingPathComponent("Sessions", isDirectory: true)
                try FileManager.default.createDirectory(at: logs, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
                let log = logs.appendingPathComponent("launch-" + item.id.uuidString + ".log")
                FileManager.default.createFile(atPath: log.path, contents: nil, attributes: [.posixPermissions: 0o600])
                let output = try FileHandle(forWritingTo: log)
                let process = Process(); process.executableURL = URL(fileURLWithPath: runnerPath)
                process.arguments = ["--rule", item.id.uuidString, "--config", store.url.path, "--"]
                process.currentDirectoryURL = URL(fileURLWithPath: projectPath)
                process.standardInput = FileHandle.nullDevice; process.standardOutput = output; process.standardError = output
                let id = item.id
                process.terminationHandler = { [weak self] process in
                    try? output.close()
                    Task { @MainActor in
                        self?.childProcesses[id] = nil; self?.loadSessions()
                        if process.terminationStatus != 0 {
                            let text = (try? String(contentsOf: log, encoding: .utf8)) ?? "The app could not complete a protected launch."
                            self?.error = String(text.suffix(3000))
                        }
                    }
                }
                try process.run(); childProcesses[id] = process
            }
            notice = "The launcher verifies the VPN before starting \(item.name)."
            loadSessions()
        } catch { self.error = error.localizedDescription }
    }
    func loadSessions() {
        let folder = store.url.deletingLastPathComponent().appendingPathComponent("Sessions", isDirectory: true)
        let files = (try? FileManager.default.contentsOfDirectory(at: folder, includingPropertiesForKeys: [.contentModificationDateKey], options: .skipsHiddenFiles)) ?? []
        sessions = files.filter { $0.pathExtension == "json" }.sorted {
            let a = (try? $0.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
            let b = (try? $1.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
            return a > b
        }.prefix(100).compactMap { url in
            guard let data = try? Data(contentsOf: url), data.count < 100_000 else { return nil }
            return try? JSONDecoder().decode(GuardSessionRecord.self, from: data)
        }.sorted { $0.updatedAt > $1.updatedAt }
    }
    func reveal(_ path: String) { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)]) }
}
