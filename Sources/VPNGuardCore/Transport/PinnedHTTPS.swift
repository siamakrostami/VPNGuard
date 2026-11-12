import Foundation
import Darwin

/// curl supplies certificate-verified TLS. A one-shot TCP bridge supplies mandatory
/// IP_BOUND_IF plus source binding, which older Darwin curl does not implement itself.
/// Neither curl nor the bridge resolves DNS or tries an alternative destination.
enum PinnedHTTPS {
    static func fetch(path: GenericVPNPath, host: String, address: String, resource: String) throws -> String {
        guard IPv4.isPublic(address), DNSHostname.isValid(host), resource.hasPrefix("/"),
              !resource.contains(where: { $0.isWhitespace || $0.asciiValue == nil }) else {
            throw GuardError.invalid("Invalid pinned HTTPS endpoint.")
        }
        let remote = try BoundSocket.make(path: path)
        do { try BoundSocket.connect(remote, address: address, port: 443) }
        catch { close(remote); throw error }
        let listener = socket(AF_INET, SOCK_STREAM, 0)
        guard listener >= 0 else { close(remote); throw GuardError.invalid("Cannot create the HTTPS transport bridge.") }
        BoundSocket.configure(listener)
        var local = BoundSocket.address("127.0.0.1", port: 0)
        let result = withUnsafePointer(to: &local) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(listener, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard result == 0, listen(listener, 1) == 0 else {
            close(listener); close(remote); throw GuardError.invalid("Cannot bind the HTTPS transport bridge.")
        }
        var size = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &local) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(listener, $0, &size) } }
        guard named == 0 else { close(listener); close(remote); throw GuardError.invalid("Cannot inspect the HTTPS transport bridge.") }
        let bridge = HTTPSBridge(listener: listener, remote: remote)
        let port = UInt16(bigEndian: local.sin_port)
        DispatchQueue.global(qos: .utility).async { bridge.run() }
        defer { bridge.stop() }
        // The URL hostname remains unchanged for SNI and certificate validation.
        // --connect-to only substitutes the TCP destination; the remote is already
        // connected to the fixed address through the bound socket above.
        let output = try CommandRunner.run("/usr/bin/curl", ["--disable", "--ipv4", "--proxy", "", "--noproxy", "*",
            "--connect-to", "\(host):443:127.0.0.1:\(port)", "--proto", "=https", "--tlsv1.2",
            "--header", "Accept: application/dns-json", "--fail", "--silent", "--show-error", "--max-filesize", "65536",
            "--connect-timeout", "3", "--max-time", "6", "https://\(host)\(resource)"], timeout: 8)
        guard output.status == 0, output.stdout.utf8.count <= 65536 else { throw GuardError.invalid("Tunnel-bound HTTPS verification failed.") }
        return output.stdout
    }
}

private final class HTTPSBridge: @unchecked Sendable {
    private let lock = NSLock()
    private var sockets: Set<Int32>
    private let listener: Int32
    private let remote: Int32
    private var stopped = false
    init(listener: Int32, remote: Int32) { self.listener = listener; self.remote = remote; sockets = [listener, remote] }
    func stop() {
        lock.lock(); defer { lock.unlock() }
        stopped = true; for fd in sockets { _ = shutdown(fd, SHUT_RDWR) }
    }
    private var active: Bool { lock.lock(); defer { lock.unlock() }; return !stopped }
    func run() {
        defer {
            lock.lock(); for fd in sockets { close(fd) }; sockets.removeAll(); stopped = true; lock.unlock()
        }
        let deadline = Date().addingTimeInterval(8)
        var p = pollfd(fd: listener, events: Int16(POLLIN), revents: 0)
        guard poll(&p, 1, 7000) > 0, active else { return }
        let local = accept(listener, nil, nil)
        guard local >= 0 else { return }
        lock.lock(); sockets.insert(local); let wasStopped = stopped; lock.unlock()
        guard !wasStopped else { return }
        BoundSocket.configure(local)
        var buffer = [UInt8](repeating: 0, count: 16384)
        var total = 0
        while active && Date() < deadline && total < 262144 {
            var descriptors = [pollfd(fd: local, events: Int16(POLLIN), revents: 0), pollfd(fd: remote, events: Int16(POLLIN), revents: 0)]
            let ready = poll(&descriptors, 2, 250)
            if ready < 0 { if errno == EINTR { continue }; return }
            for i in 0..<2 where descriptors[i].revents != 0 {
                guard descriptors[i].revents & Int16(POLLIN) != 0 else { return }
                let n = recv(descriptors[i].fd, &buffer, buffer.count, 0)
                guard n > 0, active, BoundSocket.sendAll(descriptors[1-i].fd, Data(buffer.prefix(n))) else { return }
                total += n
            }
        }
    }
}
