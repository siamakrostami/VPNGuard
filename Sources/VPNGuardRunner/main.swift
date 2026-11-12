import Foundation
import AppKit
import Darwin
import VPNGuardCore

nonisolated(unsafe) private var childGroup: pid_t = 0
private func forwardSignal(_ number: Int32) {
    let group = childGroup
    if group > 0 { _ = kill(-group, number) }
}

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

/// posix_spawn avoids a shell and creates a separate child group for signal forwarding.
/// Standard file descriptors remain inherited, with terminal foreground restored on exit.
private func runChild(arguments: [String], environment: [String: String]) throws -> Int32 {
    let signals: [Int32] = [SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGUSR1, SIGUSR2, SIGWINCH, SIGCONT]
    var blocked = sigset_t(); sigemptyset(&blocked)
    for number in signals { sigaddset(&blocked, number) }
    var previous = sigset_t(); pthread_sigmask(SIG_BLOCK, &blocked, &previous)
    defer { pthread_sigmask(SIG_SETMASK, &previous, nil) }
    var attr: posix_spawnattr_t?
    guard posix_spawnattr_init(&attr) == 0 else { throw GuardError.invalid("Cannot initialize protected process launch.") }
    defer { posix_spawnattr_destroy(&attr) }
    var defaults = sigset_t(); sigemptyset(&defaults)
    for number in signals + [SIGPIPE, SIGTTOU, SIGTTIN, SIGTSTP] { sigaddset(&defaults, number) }
    var empty = sigset_t(); sigemptyset(&empty)
    posix_spawnattr_setsigmask(&attr, &empty)
    posix_spawnattr_setsigdefault(&attr, &defaults)
    posix_spawnattr_setpgroup(&attr, 0)
    posix_spawnattr_setflags(&attr, Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_CLOEXEC_DEFAULT))
    var actions: posix_spawn_file_actions_t?
    guard posix_spawn_file_actions_init(&actions) == 0 else { throw GuardError.invalid("Cannot isolate inherited descriptors.") }
    defer { posix_spawn_file_actions_destroy(&actions) }
    for descriptor in [STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO] where fcntl(descriptor, F_GETFD) >= 0 {
        guard posix_spawn_file_actions_addinherit_np(&actions, descriptor) == 0 else { throw GuardError.invalid("Cannot inherit standard input/output.") }
    }
    let argv = ([SandboxLaunch.executablePath] + arguments).map { strdup($0) } + [nil]
    let envp = environment.map { strdup($0.key + "=" + $0.value) } + [nil]
    defer { argv.forEach { free($0) }; envp.forEach { free($0) } }
    var pid: pid_t = 0
    let error = argv.withUnsafeBufferPointer { argv in envp.withUnsafeBufferPointer { envp in
        posix_spawn(&pid, SandboxLaunch.executablePath, &actions, &attr, argv.baseAddress!, envp.baseAddress!)
    } }
    guard error == 0 else { throw GuardError.invalid("Protected launch failed: \(String(cString: strerror(error))).") }
    childGroup = pid
    for number in signals { signal(number, forwardSignal) }
    let originalForeground = tcgetpgrp(STDIN_FILENO)
    let ownsTerminal = originalForeground >= 0 && originalForeground == getpgrp()
    let oldTTOU = signal(SIGTTOU, SIG_IGN)
    if ownsTerminal { _ = tcsetpgrp(STDIN_FILENO, pid) }
    pthread_sigmask(SIG_SETMASK, &previous, nil)
    defer {
        if ownsTerminal { _ = tcsetpgrp(STDIN_FILENO, originalForeground) }
        signal(SIGTTOU, oldTTOU)
        childGroup = 0
        for number in signals { signal(number, SIG_DFL) }
    }
    var status: Int32 = 0
    while true {
        let result = waitpid(pid, &status, WUNTRACED)
        if result < 0 { if errno == EINTR { continue }; throw GuardError.invalid("Cannot wait for protected process.") }
        if (status & 0xff) == 0x7f {
            if ownsTerminal { _ = tcsetpgrp(STDIN_FILENO, originalForeground) }
            _ = kill(getpid(), SIGSTOP)
            if ownsTerminal { _ = tcsetpgrp(STDIN_FILENO, pid) }
            _ = kill(-pid, SIGCONT)
            continue
        }
        break
    }
    // A proxy session ends with its primary child. Tear down lingering descendants.
    _ = kill(-pid, SIGTERM)
    if (status & 0x7f) == 0 { return (status >> 8) & 0xff }
    return 128 + (status & 0x7f)
}

private func main() throws -> Int32 {
    guard geteuid() != 0 else { throw GuardError.invalid("Run VPNGuardRun as your normal user, without sudo.") }
    let invocation = try Invocation(Array(CommandLine.arguments.dropFirst()))
    let settings = try RuleStore(url: invocation.config).load()
    guard let item = settings.items.first(where: { $0.id == invocation.rule }) else { throw GuardError.invalid("The protected rule no longer exists. Update your command integration.") }
    let journal = try SessionJournal(rule: item, storeURL: RuleStore(url: invocation.config).url)
    do {
        guard settings.protectionEnabled else { throw GuardError.invalid("Protection is disabled. Enable it before launching; this wrapper will not launch unprotected.") }
        guard item.isEnabled else { throw GuardError.invalid("This rule is disabled. Enable it before launching; this wrapper will not launch unprotected.") }
        let executable = try resolve(item)
        guard FileManager.default.isExecutableFile(atPath: SandboxLaunch.executablePath) else { throw GuardError.invalid("sandbox-exec is unavailable; protected launch refused.") }
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
        let status = try runChild(arguments: arguments, environment: SandboxLaunch.environment(base: ProcessInfo.processInfo.environment, proxyURL: info.proxyURL))
        journal.update(phase: "ended", message: "Guarded process ended with status \(status).")
        return status
    } catch {
        journal.update(phase: "blocked", message: "Protected launch refused: " + error.localizedDescription)
        throw error
    }
}

do { exit(try main()) }
catch { writeError(error.localizedDescription); exit(125) }
