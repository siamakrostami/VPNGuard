import Foundation
import Darwin

public struct ProxySessionInfo: Sendable {
    public let port: UInt16
    public let proxyURL: String
    public init(port: UInt16, proxyURL: String) { self.port = port; self.proxyURL = proxyURL }
}

enum BoundSocket {
    static func make(path: GenericVPNPath) throws -> Int32 {
        guard NetworkParsing.routeInterface("interface: " + path.interface) != nil,
              path.interfaceIndex > 0, if_nametoindex(path.interface) == path.interfaceIndex,
              IPv4.isValid(path.address), !path.address.hasPrefix("127."), path.address != "0.0.0.0" else {
            throw GuardError.invalid("The verified VPN interface no longer exists.")
        }
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw GuardError.invalid("Cannot create a VPN socket.") }
        do {
            var index = path.interfaceIndex
            guard setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &index, socklen_t(MemoryLayout.size(ofValue: index))) == 0 else {
                throw GuardError.invalid("Cannot restrict the socket to the VPN interface.")
            }
            var source = address(path.address, port: 0)
            let result = withUnsafePointer(to: &source) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
            guard result == 0 else { throw GuardError.invalid("Cannot bind the socket to the VPN source address.") }
            configure(fd)
            return fd
        } catch { close(fd); throw error }
    }
    static func address(_ ip: String, port: UInt16) -> sockaddr_in {
        var result = sockaddr_in(); result.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        result.sin_family = sa_family_t(AF_INET); result.sin_port = port.bigEndian
        _ = ip.withCString { inet_pton(AF_INET, $0, &result.sin_addr) }
        return result
    }
    static func configure(_ fd: Int32) {
        _ = fcntl(fd, F_SETFD, FD_CLOEXEC)
        var one: Int32 = 1
        _ = setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout.size(ofValue: one)))
        var timeout = timeval(tv_sec: 5, tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout.size(ofValue: timeout)))
        _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout.size(ofValue: timeout)))
    }
    static func connect(_ fd: Int32, address ip: String, port: UInt16) throws {
        let flags = fcntl(fd, F_GETFL)
        guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0 else { throw GuardError.invalid("Cannot configure the VPN connection.") }
        defer { _ = fcntl(fd, F_SETFL, flags) }
        var target = address(ip, port: port)
        let status = withUnsafePointer(to: &target) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard status == 0 || errno == EINPROGRESS else { throw GuardError.invalid("VPN connection failed.") }
        if status != 0 {
            var p = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            var error: Int32 = 0; var size = socklen_t(MemoryLayout<Int32>.size)
            guard poll(&p, 1, 5000) > 0, getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &size) == 0, error == 0 else { throw GuardError.invalid("VPN connection timed out or failed.") }
        }
    }
    static func sendAll(_ fd: Int32, _ data: Data) -> Bool {
        data.withUnsafeBytes { bytes in
            guard let base = bytes.baseAddress else { return true }
            var offset = 0
            while offset < bytes.count {
                let count = Darwin.send(fd, base.advanced(by: offset), bytes.count - offset, 0)
                if count < 0 && errno == EINTR { continue }
                guard count > 0 else { return false }; offset += count
            }
            return true
        }
    }
}

public enum ProxyConnectionState: Sendable { case blocked, running }

public final class VPNBoundProxy: @unchecked Sendable {
    private let lock = NSLock()
    private let monitor: any VPNPathMonitoring
    private let onEvent: @Sendable (String) -> Void
    private let onStateChange: @Sendable (ProxyConnectionState) -> Void
    private let eventQueue = DispatchQueue(label: "VPNGuard.transport.events")
    private let inspectionQueue = DispatchQueue(label: "VPNGuard.transport.inspect")
    private var verification: VPNVerification
    private var stopped = false
    private var started = false
    private var paused = false
    private var generation: UInt64 = 0
    private var listener: Int32 = -1
    private var sockets = Set<Int32>()
    private var connectionCount = 0
    private var lastRecoveryAttempt = Date.distantPast
    private var watchdog: DispatchSourceTimer?
    private var inspector: DispatchSourceTimer?
    private let token = UUID().uuidString.replacingOccurrences(of: "-", with: "")
    public convenience init(verification: VPNVerification, monitor: GenericVPNMonitor,
                            onEvent: @escaping @Sendable (String) -> Void,
                            onStateChange: @escaping @Sendable (ProxyConnectionState) -> Void = { _ in }) {
        self.init(verification: verification, monitoring: monitor, onEvent: onEvent, onStateChange: onStateChange)
    }
    init(verification: VPNVerification, monitoring: any VPNPathMonitoring,
         onEvent: @escaping @Sendable (String) -> Void,
         onStateChange: @escaping @Sendable (ProxyConnectionState) -> Void = { _ in }) {
        self.verification = verification; self.monitor = monitoring
        self.onEvent = onEvent; self.onStateChange = onStateChange
    }
    deinit { stop() }
    private func locked<T>(_ body: () throws -> T) rethrows -> T { lock.lock(); defer { lock.unlock() }; return try body() }
    private func valid(_ expected: UInt64) -> Bool {
        locked { !stopped && !paused && generation == expected && verification.isFresh }
    }
    public func start() throws -> ProxySessionInfo {
        try locked {
            guard !started, !stopped, verification.isFresh else { throw GuardError.invalid("A fresh verified non-Iran VPN exit is required.") }
            started = true
        }
        do {
            guard try monitor.inspect() == verification.path else { throw GuardError.invalid("VPN topology changed before proxy startup.") }
            let fd = socket(AF_INET, SOCK_STREAM, 0)
            guard fd >= 0 else { throw GuardError.invalid("Cannot create the local proxy listener.") }
            BoundSocket.configure(fd)
            locked { listener = fd }
            var addr = BoundSocket.address("127.0.0.1", port: 0)
            let status = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
            guard status == 0, listen(fd, 16) == 0 else { throw GuardError.invalid("Cannot listen on the private loopback proxy.") }
            var length = socklen_t(MemoryLayout<sockaddr_in>.size)
            let result = withUnsafeMutablePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) } }
            guard result == 0 else { throw GuardError.invalid("Cannot inspect the private loopback port.") }
            _ = fcntl(fd, F_SETFL, O_NONBLOCK)
            startMonitoring()
            DispatchQueue.global(qos: .utility).async { [self] in acceptLoop(fd) }
            let port = UInt16(bigEndian: addr.sin_port)
            return ProxySessionInfo(port: port, proxyURL: "http://session:\(token)@127.0.0.1:\(port)")
        } catch {
            // No accept worker owns this descriptor until startup completes.
            locked { if listener >= 0 { close(listener); listener = -1 } }
            stop(); throw error
        }
    }
    public func stop() {
        locked {
            guard !stopped else { return }
            stopped = true; generation &+= 1
            watchdog?.cancel(); watchdog = nil; inspector?.cancel(); inspector = nil
            if listener >= 0 { _ = shutdown(listener, SHUT_RDWR) }
            for fd in sockets { _ = shutdown(fd, SHUT_RDWR) }
        }
    }
    /// Revoke current sockets immediately. Reuse the same authenticated endpoint only
    /// after an independent fresh verification; the sandbox and child do not change.
    public func resetConnections() {
        pause(expected: nil, message: "Resetting connections. Traffic stays blocked until the VPN is verified.")
        inspectionQueue.async { [weak self] in self?.inspectConnection(force: true) }
    }
    private func pause(expected: UInt64?, message: String) {
        locked {
            guard !stopped, expected == nil || generation == expected, !paused || expected == nil else { return }
            paused = true; generation &+= 1
            for fd in sockets { _ = shutdown(fd, SHUT_RDWR) }
            // Serialize notifications with state changes so a late blocked event
            // cannot overwrite a successful recovery in the session journal.
            notify(message, state: .blocked)
        }
    }
    private func notify(_ message: String, state: ProxyConnectionState) {
        let event = onEvent, change = onStateChange
        eventQueue.async { event(message); change(state) }
    }
    private func register(_ fd: Int32, generation expected: UInt64) -> Bool {
        locked {
            guard !stopped, !paused, generation == expected, verification.isFresh else { return false }
            sockets.insert(fd); return true
        }
    }
    private func release(_ fd: Int32) { locked { sockets.remove(fd); close(fd) } }
    private func startMonitoring() {
        let watch = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "VPNGuard.transport.freshness"))
        watch.schedule(deadline: .now() + .milliseconds(100), repeating: .milliseconds(100))
        watch.setEventHandler { [weak self] in
            guard let self else { return }
            let expired = locked { !stopped && !paused && !verification.isFresh ? generation : nil }
            if let expired { pause(expected: expired, message: "VPN verification expired. Connections blocked; waiting to reverify.") }
        }
        let inspect = DispatchSource.makeTimerSource(queue: inspectionQueue)
        inspect.schedule(deadline: .now() + 1, repeating: 1)
        inspect.setEventHandler { [weak self] in self?.inspectConnection(force: false) }
        locked { watchdog = watch; inspector = inspect }
        watch.resume(); inspect.resume()
    }
    private func inspectConnection(force: Bool) {
        let snapshot = locked { (stopped, paused, generation, verification) }
        guard !snapshot.0 else { return }
        do {
            if !snapshot.1 {
                guard try monitor.inspect() == snapshot.3.path else {
                    pause(expected: snapshot.2, message: "VPN connection changed. Connections blocked; waiting to reverify."); return
                }
                if Date().timeIntervalSince(snapshot.3.verifiedAt) < 15 { return }
            } else {
                guard force || Date().timeIntervalSince(lastRecoveryAttempt) >= 5 else { return }
                lastRecoveryAttempt = Date()
            }
            let fresh = try monitor.verify()
            guard fresh.isFresh, try monitor.inspect() == fresh.path else { throw GuardError.invalid("VPN verification is not current.") }
            // Even a newly verified path change revokes existing sockets first.
            if !snapshot.1 && fresh.path != snapshot.3.path {
                pause(expected: snapshot.2, message: "VPN connection changed. Connections blocked; waiting to reverify."); return
            }
            locked {
                guard !stopped, generation == snapshot.2, fresh.isFresh else { return }
                verification = fresh
                if paused {
                    paused = false
                    notify("VPN connection restored. Retry your last prompt. If the CLI keeps its own error, use its retry or resume command.", state: .running)
                }
            }
        } catch {
            pause(expected: snapshot.2, message: "VPN verification was lost. Connections blocked; reconnect your VPN. This session will check again automatically.")
        }
    }
    private func acceptLoop(_ fd: Int32) {
        defer { locked { if listener == fd { listener = -1 }; close(fd) } }
        while locked({ !stopped }) {
            var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            guard poll(&p, 1, 250) > 0 else { continue }
            let client = accept(fd, nil, nil)
            guard client >= 0 else { continue }
            BoundSocket.configure(client)
            let epoch = locked { () -> UInt64? in
                guard !stopped, !paused, verification.isFresh, connectionCount < 32 else { return nil }
                connectionCount += 1; sockets.insert(client); return generation
            }
            guard let epoch else {
                _ = BoundSocket.sendAll(client, Data("HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".utf8))
                close(client); continue
            }
            DispatchQueue.global(qos: .utility).async { [self] in
                defer { release(client); locked { connectionCount -= 1 } }
                handle(client, generation: epoch)
            }
        }
    }
    private func handle(_ client: Int32, generation epoch: UInt64) {
        do {
            var header = Data(); let deadline = Date().addingTimeInterval(5)
            while !header.suffix(4).elementsEqual([13,10,13,10]) {
                guard valid(epoch), Date() < deadline, header.count < 16384 else { throw GuardError.invalid("CONNECT headers exceeded bounds.") }
                var byte: UInt8 = 0
                guard recv(client, &byte, 1, 0) == 1 else { return }; header.append(byte)
            }
            let request = try ConnectRequest.parse(header)
            let expected = "Basic " + Data("session:\(token)".utf8).base64EncodedString()
            guard request.authorization == expected else {
                _ = BoundSocket.sendAll(client, Data("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"VPNGuard\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".utf8)); return
            }
            let snapshot = locked { verification }
            guard valid(epoch), try monitor.inspect() == snapshot.path else {
                pause(expected: epoch, message: "VPN connection changed. Connections blocked; waiting to reverify."); return
            }
            let addresses = try monitor.resolve(request.host, path: snapshot.path)
            guard valid(epoch), let address = addresses.first else { return }
            let upstream = try BoundSocket.make(path: snapshot.path)
            guard register(upstream, generation: epoch) else { close(upstream); return }
            defer { release(upstream) }
            try BoundSocket.connect(upstream, address: address, port: request.port)
            guard valid(epoch), BoundSocket.sendAll(client, Data("HTTP/1.1 200 Connection Established\r\n\r\n".utf8)) else { return }
            relay(client, upstream, generation: epoch)
        } catch {
            _ = BoundSocket.sendAll(client, Data("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".utf8))
        }
    }
    private func relay(_ client: Int32, _ upstream: Int32, generation epoch: UInt64) {
        var lastData = Date()
        var buffer = [UInt8](repeating: 0, count: 16384)
        while valid(epoch) && Date().timeIntervalSince(lastData) < 120 {
            var descriptors = [pollfd(fd: client, events: Int16(POLLIN), revents: 0), pollfd(fd: upstream, events: Int16(POLLIN), revents: 0)]
            let count = poll(&descriptors, 2, 500)
            if count < 0 { if errno == EINTR { continue }; return }
            for i in 0..<2 where descriptors[i].revents != 0 {
                guard descriptors[i].revents & Int16(POLLIN) != 0 else { return }
                let received = recv(descriptors[i].fd, &buffer, buffer.count, 0)
                guard received > 0, valid(epoch), BoundSocket.sendAll(descriptors[1-i].fd, Data(buffer.prefix(received))) else { return }
                lastData = Date()
            }
        }
    }
}
