import Foundation
import AppKit
import Darwin
import VPNGuardCore

private func writeError(_ message: String) {
    FileHandle.standardError.write(Data(("VPNGuard: " + message + "\n").utf8))
}

private struct Invocation {
    var rule: UUID
    var config: URL?
    var arguments: [String]
    init(_ values: [String]) throws {
        var id: UUID?, config: URL?, index = 0
        var forwarded: [String] = []
        var separator = false
        while index < values.count {
            let value = values[index]
            if value == "--" { forwarded = Array(values.dropFirst(index + 1)); separator = true; break }
            guard index + 1 < values.count else { throw GuardError.invalid(Self.usage) }
            switch value {
            case "--rule":
                guard id == nil, let parsed = UUID(uuidString: values[index + 1]) else { throw GuardError.invalid(Self.usage) }
                id = parsed
            case "--config":
                let path = values[index + 1]
                guard config == nil, path.hasPrefix("/"), !path.contains("\0") else { throw GuardError.invalid("--config requires one absolute JSON path.") }
                config = URL(fileURLWithPath: path)
            default: throw GuardError.invalid(Self.usage)
            }
            index += 2
        }
        guard let id, separator else { throw GuardError.invalid(Self.usage) }
        self.rule = id; self.config = config; self.arguments = forwarded
    }
    static let usage = "Usage: VPNGuardRun --rule UUID [--config /absolute/rules.json] -- [arguments...]"
}

private func resolve(_ item: ProtectedItem) throws -> String {
    let path: String
    if item.kind == .application {
        let url = URL(fileURLWithPath: item.targetPath).standardizedFileURL.resolvingSymlinksInPath()
        guard let bundle = Bundle(url: url), let executable = bundle.executableURL,
              executable.standardizedFileURL.resolvingSymlinksInPath().path.hasPrefix(url.path + "/Contents/MacOS/") else {
            throw GuardError.invalid("The app bundle has no valid CFBundleExecutable in Contents/MacOS.")
        }
        let running = NSWorkspace.shared.runningApplications.contains { app in
            if let runningURL = app.bundleURL?.standardizedFileURL.resolvingSymlinksInPath(), runningURL == url { return true }
            return bundle.bundleIdentifier != nil && app.bundleIdentifier == bundle.bundleIdentifier
        }
        guard !running else { throw GuardError.invalid("Quit \(item.name) first. An existing instance cannot be brought inside the protected launch.") }
        // There is no reliable generic Electron detection or safe way to override every
        // app's own Chromium flags. Environment-only compatibility is fail closed.
        writeError("Launching the app executable directly. Only proxy-compatible traffic works; normal Finder launches and handoff to existing services are outside this mode.")
        path = executable.path
    } else { path = URL(fileURLWithPath: item.targetPath).resolvingSymlinksInPath().path }
    guard FileManager.default.isExecutableFile(atPath: path) else { throw GuardError.invalid("The selected executable is missing or cannot be executed.") }
    guard path != Bundle.main.executableURL?.resolvingSymlinksInPath().path else { throw GuardError.invalid("A rule cannot point back to VPNGuardRun.") }
    return path
}

private func main() throws -> Int32 {
    guard geteuid() != 0 else { throw GuardError.invalid("Run VPNGuardRun as your normal user, without sudo.") }
    let invocation = try Invocation(Array(CommandLine.arguments.dropFirst()))
    let settings = try RuleStore(url: invocation.config).load()
    guard let item = settings.items.first(where: { $0.id == invocation.rule }) else { throw GuardError.invalid("The protected rule no longer exists. Update your command integration.") }
    let journal = try SessionJournal(rule: item, storeURL: RuleStore(url: invocation.config).url)
    let session = ManagedProcessSession()
    let policy = SessionPolicyWatcher(ruleID:invocation.rule,store:RuleStore(url:invocation.config)) {
        journal.update(phase:"ending",message:"The rule was removed, excluded, disabled, or unreadable. Terminating this protected process group.")
        session.requestStop()
    }
    policy.start()
    defer { policy.stop(); session.requestStop() }
    do {
        guard settings.protectionEnabled else { throw GuardError.invalid("Protection is disabled. Enable it before launching; this wrapper will not launch unprotected.") }
        guard item.isEnabled else { throw GuardError.invalid("This rule is disabled. Enable it before launching; this wrapper will not launch unprotected.") }
        let executable = try resolve(item)
        guard FileManager.default.isExecutableFile(atPath: SandboxLaunch.executablePath) else { throw GuardError.invalid("sandbox-exec is unavailable; protected launch refused.") }
        let hostURL = Bundle.main.executableURL!.deletingLastPathComponent().appendingPathComponent("VPNGuardProcessHost")
        guard FileManager.default.isExecutableFile(atPath:hostURL.path) else { throw GuardError.invalid("The session supervisor is missing; protected launch refused.") }
        let monitor = GenericVPNMonitor()
        let verification = try monitor.verify()
        let proxy = VPNBoundProxy(verification: verification, monitor: monitor, onEvent: { message in
            writeError(message)
        }, onStateChange: { state in
            switch state {
            case .blocked:
                journal.update(phase: "blocked", message: "Connections blocked. Reconnect the VPN or choose Reset connections. This session will reverify automatically.")
            case .running:
                journal.update(phase: "running", message: "VPN reverified. Retry your last prompt in the existing terminal; direct connections remain restricted.")
            }
        })
        let info = try proxy.start()
        journal.setResetHandler { [weak proxy] in proxy?.resetConnections() }
        defer { proxy.stop() }
        let arguments = try SandboxLaunch.arguments(executable: executable, forwarded: invocation.arguments, proxyPort: info.port)
        journal.update(phase: "running", message: "Guarded launch active. Direct child sockets are restricted to its private proxy.")
        policy.checkNow()
        guard !session.isStopped else { throw GuardError.invalid("The protected session was cancelled before launch.") }
        let host = Bundle.main.executableURL!.deletingLastPathComponent().appendingPathComponent("VPNGuardProcessHost")
        let status = try session.run(host:host, executable:SandboxLaunch.executablePath, arguments:arguments,
                                    environment:SandboxLaunch.environment(base:ProcessInfo.processInfo.environment,proxyURL:info.proxyURL)) { identity in
            journal.setProcessIdentity(identity)
        }
        journal.update(phase: "ended", message: "Guarded process ended with status \(status).")
        return status
    } catch {
        journal.update(phase: "ended", message: "Protected launch refused: " + error.localizedDescription)
        throw error
    }
}

do { exit(try main()) }
catch { writeError(error.localizedDescription); exit(125) }
