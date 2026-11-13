import Foundation
import Darwin
import CProcessLifecycle

public struct ProcessIdentity: Codable, Equatable, Sendable {
    public var pid: Int32
    public var seconds: UInt64
    public var microseconds: UInt64
    public static func capture(_ pid: Int32) -> Self? {
        var value = vpg_process_identity()
        guard vpg_process_identity_read(pid, &value) == 0 else { return nil }
        return Self(pid: value.pid, seconds: value.seconds, microseconds: value.microseconds)
    }
    public var isLive: Bool { Self.capture(pid) == self }
    @discardableResult
    public func signal(_ number: Int32, group: Bool = false) -> Bool {
        let value = vpg_process_identity(pid: pid, seconds: seconds, microseconds: microseconds)
        return vpg_signal_identity(value, number, group ? 1 : 0) == 0
    }
}
public struct ProcessSessionIdentity: Codable, Equatable, Sendable {
    public var childIdentity: ProcessIdentity
    public var hostIdentity: ProcessIdentity
}

/// One runner-owned control pipe. The independent host owns spawning/reaping the
/// entire child group and treats loss of this pipe as a mandatory cleanup request.
public final class ManagedProcessSession: @unchecked Sendable {
    private let lock = NSLock()
    private var control: Int32 = -1
    private var hostIdentity: ProcessIdentity?
    private var stopRequested = false
    public init() {}
    deinit { requestStop() }
    public var isStopped:Bool { lock.lock();defer{lock.unlock()};return stopRequested }
    public func requestStop() {
        lock.lock()
        stopRequested = true
        let fd = control, host = hostIdentity
        control = -1
        lock.unlock()
        if fd >= 0 { close(fd) }
        // Also wake a stopped supervisor. Identity cookies prevent signalling a
        // reused journal PID. The pipe is the primary ownership boundary.
        if let host { host.signal(SIGCONT); host.signal(SIGTERM) }
    }
    public func run(host: URL, executable: String, arguments: [String], environment: [String: String], standardIO: [Int32:Int32] = [:], handleSignals: Bool = true, onStarted: (ProcessSessionIdentity) -> Void) throws -> Int32 {
        guard FileManager.default.isExecutableFile(atPath: host.path) else { throw GuardError.invalid("The session supervisor is missing. Rebuild VPNGuard before launching protected items.") }
        lock.lock(); let cancelled = stopRequested; lock.unlock()
        guard !cancelled else { throw GuardError.invalid("This protected session was cancelled.") }
        var pipes = [Int32]()
        func makePipe() throws -> (Int32, Int32) {
            var raw: [Int32] = [-1, -1]
            guard pipe(&raw) == 0 else { throw GuardError.invalid("Cannot create the session control channel.") }
            // High descriptors make dup2 actions independent of their source order.
            let read = fcntl(raw[0], F_DUPFD_CLOEXEC, 10)
            let write = fcntl(raw[1], F_DUPFD_CLOEXEC, 10)
            close(raw[0]); close(raw[1])
            guard read >= 0, write >= 0 else {
                if read >= 0 { close(read) }; if write >= 0 { close(write) }
                throw GuardError.invalid("Cannot isolate the session control descriptors.")
            }
            pipes += [read, write]; return (read, write)
        }
        defer { for fd in pipes { close(fd) } }
        let channel = try makePipe(), status = try makePipe()
        var attr: posix_spawnattr_t?
        guard posix_spawnattr_init(&attr) == 0 else { throw GuardError.invalid("Cannot initialize the session supervisor.") }
        defer { posix_spawnattr_destroy(&attr) }
        var mask = sigset_t(); sigemptyset(&mask)
        var defaults = sigset_t(); sigemptyset(&defaults)
        for number in [SIGTERM,SIGHUP,SIGINT,SIGQUIT,SIGTSTP,SIGTTIN,SIGTTOU,SIGCONT,SIGPIPE,SIGWINCH] { sigaddset(&defaults,number) }
        posix_spawnattr_setsigmask(&attr,&mask); posix_spawnattr_setsigdefault(&attr,&defaults)
        posix_spawnattr_setpgroup(&attr,0)
        posix_spawnattr_setflags(&attr,Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_CLOEXEC_DEFAULT))
        var actions: posix_spawn_file_actions_t?
        guard posix_spawn_file_actions_init(&actions) == 0 else { throw GuardError.invalid("Cannot prepare supervisor descriptors.") }
        defer { posix_spawn_file_actions_destroy(&actions) }
        for descriptor in [STDIN_FILENO,STDOUT_FILENO,STDERR_FILENO] {
            let result: Int32
            if let source = standardIO[descriptor] { result = posix_spawn_file_actions_adddup2(&actions,source,descriptor) }
            else if fcntl(descriptor,F_GETFD) >= 0 { result = posix_spawn_file_actions_addinherit_np(&actions,descriptor) }
            else { continue }
            guard result == 0 else { throw GuardError.invalid("Cannot inherit standard input/output.") }
        }
        guard posix_spawn_file_actions_adddup2(&actions,channel.0,3) == 0,
              posix_spawn_file_actions_adddup2(&actions,status.1,4) == 0 else { throw GuardError.invalid("Cannot prepare control channels.") }
        let foreground = tcgetpgrp(STDIN_FILENO) == getpgrp() ? getpgrp() : -1
        let values = [host.path,"--control-fd","3","--status-fd","4","--foreground-group",String(foreground),"--",executable] + arguments
        let argv = values.map { strdup($0) } + [nil]
        let envp = environment.map { strdup($0.key + "=" + $0.value) } + [nil]
        defer { argv.forEach { free($0) }; envp.forEach { free($0) } }
        var pid: pid_t = 0
        let result = argv.withUnsafeBufferPointer { argv in envp.withUnsafeBufferPointer { envp in
            posix_spawn(&pid,host.path,&actions,&attr,argv.baseAddress!,envp.baseAddress!)
        } }
        guard result == 0 else { throw GuardError.invalid("Cannot start the session supervisor: \(String(cString:strerror(result))).") }
        close(channel.0); pipes.removeAll { $0 == channel.0 }
        close(status.1); pipes.removeAll { $0 == status.1 }
        lock.lock()
        hostIdentity = ProcessIdentity.capture(pid)
        let stop = stopRequested
        if !stop { control = channel.1 }
        lock.unlock()
        pipes.removeAll { $0 == channel.1 }
        if stop { close(channel.1) }
        defer { requestStop() }
        var started: ProcessSessionIdentity?
        defer { if let started { SessionLifecycle.terminate([started]) } }
        var sources: [DispatchSourceSignal] = []
        var previousHandlers: [(Int32, sig_t?)] = []
        let queue = DispatchQueue(label:"VPNGuard.session.signals")
        for number in (handleSignals ? [SIGTERM,SIGHUP,SIGINT,SIGQUIT] : []) {
            previousHandlers.append((number,signal(number,SIG_IGN)))
            let source = DispatchSource.makeSignalSource(signal:number,queue:queue)
            source.setEventHandler { [weak self] in self?.requestStop() }
            source.resume(); sources.append(source)
        }
        defer { sources.forEach { $0.cancel() }; for (number,handler) in previousHandlers { signal(number,handler) } }
        var data = Data(), descriptor = pollfd(fd:status.0,events:Int16(POLLIN),revents:0)
        let deadline = Date().addingTimeInterval(3)
        while Date() < deadline && data.count < 4096 {
            if poll(&descriptor,1,100) <= 0 { continue }
            var byte:UInt8 = 0
            guard read(status.0,&byte,1) == 1 else { break }
            data.append(byte)
            if byte == 10 { break }
        }
        if let identity = try? JSONDecoder().decode(ProcessSessionIdentity.self,from:data), identity.hostIdentity.pid == pid {
            started = identity
            onStarted(identity)
        } else { requestStop() }
        var state:Int32 = 0
        while waitpid(pid,&state,0) < 0 {
            if errno == EINTR { continue }
            requestStop(); throw GuardError.invalid("Cannot wait for the session supervisor.")
        }
        // Do not target this PID again after it has been reaped.
        lock.lock(); hostIdentity = nil; lock.unlock()
        return state & 0x7f == 0 ? (state >> 8) & 0xff : 128 + (state & 0x7f)
    }
}

public enum SessionLifecycle {
    /// All sessions share one deadline. Each identity is checked before signalling.
    public static func terminate(_ sessions: [ProcessSessionIdentity], runners: [ProcessIdentity] = [], grace: TimeInterval = 5) {
        for session in sessions {
            session.childIdentity.signal(SIGCONT,group:true)
            session.childIdentity.signal(SIGTERM,group:true)
            session.hostIdentity.signal(SIGCONT)
            session.hostIdentity.signal(SIGTERM)
        }
        for runner in runners { runner.signal(SIGCONT); runner.signal(SIGTERM) }
        let deadline = Date().addingTimeInterval(max(0,min(grace,5)))
        while Date() < deadline && (sessions.contains(where: { $0.childIdentity.isLive || $0.hostIdentity.isLive }) || runners.contains(where: \.isLive)) { Thread.sleep(forTimeInterval:0.025) }
        for session in sessions {
            session.childIdentity.signal(SIGKILL,group:true)
            // The host owns the unreaped leader and can still terminate a group
            // whose leader is already a zombie. Do not kill it just before its
            // own deadline and strand termination-resistant descendants.
        }
        for runner in runners { runner.signal(SIGKILL) }
    }
}
