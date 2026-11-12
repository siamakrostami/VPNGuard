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

public final class VPNBoundProxy: @unchecked Sendable {
    private let lock = NSLock()
    private let monitor: any VPNPathMonitoring
    private let onEvent: @Sendable (String) -> Void
    private var verification: VPNVerification
    private var stopped = false
    private var started = false
    private var sockets = Set<Int32>()
    private var connectionCount = 0
    private var watchdog: DispatchSourceTimer?
    private var inspector: DispatchSourceTimer?
    private let token = UUID().uuidString.replacingOccurrences(of: "-", with: "")
    public convenience init(verification: VPNVerification, monitor: GenericVPNMonitor, onEvent: @escaping @Sendable (String) -> Void) {
        self.init(verification: verification, monitoring: monitor, onEvent: onEvent)
    }
    init(verification: VPNVerification, monitoring: any VPNPathMonitoring, onEvent: @escaping @Sendable (String) -> Void) {
        self.verification = verification; self.monitor = monitoring; self.onEvent = onEvent
    }
    deinit { stop() }
    private func locked<T>(_ body: () throws -> T) rethrows -> T { lock.lock(); defer { lock.unlock() }; return try body() }
    private var valid: Bool { locked { !stopped && verification.isFresh } }
    public func start() throws -> ProxySessionInfo {
        try locked {
            guard !started, !stopped, verification.isFresh else { throw GuardError.invalid("A fresh verified non-Iran VPN exit is required.") }
            started = true
        }
        do {
            guard try monitor.inspect() == verification.path else { throw GuardError.invalid("VPN topology changed before proxy startup.") }
            let listener = socket(AF_INET, SOCK_STREAM, 0)
            guard listener >= 0 else { throw GuardError.invalid("Cannot create the local proxy listener.") }
            // Registered descriptors are only shut down by stop; their owning worker closes them.
            BoundSocket.configure(listener)
            guard register(listener) else { close(listener); throw GuardError.invalid("The protected session stopped.") }
            do {
                var addr = BoundSocket.address("127.0.0.1", port: 0)
                let status = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(listener, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
                guard status == 0, listen(listener, 16) == 0 else { throw GuardError.invalid("Cannot listen on the private loopback proxy.") }
                var length = socklen_t(MemoryLayout<sockaddr_in>.size)
                let result = withUnsafeMutablePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(listener, $0, &length) } }
                guard result == 0 else { throw GuardError.invalid("Cannot inspect the private loopback port.") }
                _ = fcntl(listener, F_SETFL, O_NONBLOCK)
                startMonitoring()
                DispatchQueue.global(qos: .utility).async { [self] in acceptLoop(listener) }
                let port = UInt16(bigEndian: addr.sin_port)
                return ProxySessionInfo(port: port, proxyURL: "http://session:\(token)@127.0.0.1:\(port)")
            } catch { release(listener); throw error }
        } catch { stop(); throw error }
    }
    public func stop() {
        locked {
            stopped = true
            watchdog?.cancel(); watchdog = nil; inspector?.cancel(); inspector = nil
            for fd in sockets { _ = shutdown(fd, SHUT_RDWR) }
        }
    }
    private func fail() { stop(); onEvent("Protected session closed: VPN topology or exit verification was lost.") }
    private func register(_ fd: Int32) -> Bool { locked { guard !stopped, verification.isFresh else { return false }; sockets.insert(fd); return true } }
    private func release(_ fd: Int32) { locked { sockets.remove(fd); close(fd) } }
    private func startMonitoring() {
        let watch = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "VPNGuard.transport.freshness"))
        watch.schedule(deadline: .now() + .milliseconds(100), repeating: .milliseconds(100))
        watch.setEventHandler { [weak self] in guard let self else { return }; if !valid { fail() } }
        let inspect = DispatchSource.makeTimerSource(queue: DispatchQueue(label: "VPNGuard.transport.inspect"))
        inspect.schedule(deadline: .now() + 1, repeating: 1)
        inspect.setEventHandler { [weak self] in
            guard let self, valid else { return }
            do {
                let previous = locked { verification }
                guard try monitor.inspect() == previous.path else { fail(); return }
                if Date().timeIntervalSince(previous.verifiedAt) >= 15 {
                    let fresh = try monitor.verify()
                    guard fresh.path == previous.path else { fail(); return }
                    locked { if !stopped { verification = fresh } }
                }
            } catch { fail() }
        }
        locked { watchdog = watch; inspector = inspect }
        watch.resume(); inspect.resume()
    }
    private func acceptLoop(_ listener: Int32) {
        defer { release(listener) }
        while valid {
            var p = pollfd(fd: listener, events: Int16(POLLIN), revents: 0)
            guard poll(&p, 1, 250) > 0 else { continue }
            let client = accept(listener, nil, nil)
            guard client >= 0 else { continue }
            let allowed = locked { () -> Bool in
                guard !stopped, verification.isFresh, connectionCount < 32 else { return false }
                connectionCount += 1; sockets.insert(client); return true
            }
            guard allowed else { close(client); continue }
            BoundSocket.configure(client)
            DispatchQueue.global(qos: .utility).async { [self] in
                defer { release(client); locked { connectionCount -= 1 } }
                handle(client)
            }
        }
    }
    private func handle(_ client: Int32) {
        do {
            var header = Data(); let deadline = Date().addingTimeInterval(5)
            while !header.suffix(4).elementsEqual([13,10,13,10]) {
                guard valid, Date() < deadline, header.count < 16384 else { throw GuardError.invalid("CONNECT headers exceeded bounds.") }
                var byte: UInt8 = 0
                guard recv(client, &byte, 1, 0) == 1 else { return }; header.append(byte)
            }
            let request = try ConnectRequest.parse(header)
            let expected = "Basic " + Data("session:\(token)".utf8).base64EncodedString()
            guard request.authorization == expected else {
                _ = BoundSocket.sendAll(client, Data("HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"VPNGuard\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".utf8)); return
            }
            let snapshot = locked { verification }
            guard valid, try monitor.inspect() == snapshot.path else { fail(); return }
            let addresses = try monitor.resolve(request.host, path: snapshot.path)
            guard valid else { return }
            // One selected address, no physical-interface or unbound retry path exists.
            let upstream = try BoundSocket.make(path: snapshot.path)
            guard register(upstream) else { close(upstream); return }
            defer { release(upstream) }
            try BoundSocket.connect(upstream, address: addresses[0], port: request.port)
            guard valid, BoundSocket.sendAll(client, Data("HTTP/1.1 200 Connection Established\r\n\r\n".utf8)) else { return }
            relay(client, upstream)
        } catch {
            _ = BoundSocket.sendAll(client, Data("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".utf8))
        }
    }
    private func relay(_ client: Int32, _ upstream: Int32) {
        var lastData = Date()
        var buffer = [UInt8](repeating: 0, count: 16384)
        while valid && Date().timeIntervalSince(lastData) < 120 {
            var descriptors = [pollfd(fd: client, events: Int16(POLLIN), revents: 0), pollfd(fd: upstream, events: Int16(POLLIN), revents: 0)]
            let count = poll(&descriptors, 2, 500)
            if count < 0 { if errno == EINTR { continue }; return }
            for i in 0..<2 where descriptors[i].revents != 0 {
                guard descriptors[i].revents & Int16(POLLIN) != 0 else { return }
                let received = recv(descriptors[i].fd, &buffer, buffer.count, 0)
                guard received > 0, valid, BoundSocket.sendAll(descriptors[1-i].fd, Data(buffer.prefix(received))) else { return }
                lastData = Date()
            }
        }
    }
}
