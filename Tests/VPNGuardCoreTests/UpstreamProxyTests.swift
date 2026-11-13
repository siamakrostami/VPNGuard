import XCTest
import Darwin
import CProxyTransport
@testable import VPNGuardCore

final class UpstreamProxyTests: XCTestCase {
    func testEndpointValidationAndSecretFreeEncoding() throws {
        for host in ["", " user", "http://localhost", "localhost/path", "user@host", "host\r\nX: y", "a?x", "a#x", "a_b"] {
            XCTAssertThrowsError(try UpstreamProxyEndpoint(kind: .http, host: host, port: 8080))
        }
        XCTAssertThrowsError(try UpstreamProxyEndpoint(kind: .http, host: "localhost", port: 0))
        let endpoint = try UpstreamProxyEndpoint(kind: .socks5, host: "::1", port: 1080, credentialID: "reference")
        XCTAssertEqual(endpoint.proxyURL, "socks5h://[::1]:1080")
        XCTAssertEqual(try JSONDecoder().decode(UpstreamProxyEndpoint.self, from: JSONEncoder().encode(endpoint)), endpoint)
        XCTAssertThrowsError(try JSONDecoder().decode(UpstreamProxyEndpoint.self, from: Data(#"{"kind":"http","host":"bad/path","port":80}"#.utf8)))
    }
    func testLegacyNumericTargetsAreRejectedBeforeProxyNegotiation() throws {
        let endpoint = try UpstreamProxyEndpoint(kind:.http,host:"127.0.0.1",port:9)
        for host in ["127.1","127.0.01","0x7f.1","0177.0.0.1","2130706433"] {
            XCTAssertThrowsError(try UpstreamProxyChannel(endpoint:endpoint,host:host,port:443)) { error in
                guard case UpstreamProxyError.invalidEndpoint = error else { XCTFail("Must reject before networking, got \(error)"); return }
            }
        }
    }
    func testHTTPConnectAndOpaquePayload() throws {
        let fake = try FakeUpstream { fd in
            let request = Self.readHeader(fd)
            XCTAssertTrue(request.hasPrefix("CONNECT does-not-resolve.invalid:443 HTTP/1.1\r\n"))
            _ = Self.write(fd, Data("HTTP/1.1 200 Connection established\r\n\r\n".utf8))
            var payload = [UInt8](repeating: 0, count: 4)
            XCTAssertEqual(recv(fd, &payload, 4, MSG_WAITALL), 4)
            XCTAssertEqual(payload, Array("ping".utf8))
            _ = Self.write(fd, Data("pong".utf8))
        }
        defer { fake.stop() }
        let channel = try UpstreamProxyChannel(endpoint: .init(kind: .http, host: "127.0.0.1", port: fake.port), host: "does-not-resolve.invalid", port: 443)
        defer { channel.close() }
        XCTAssertNotEqual(fcntl(channel.descriptor, F_GETFD) & FD_CLOEXEC, 0)
        XCTAssertTrue(channel.sendAll(Data("ping".utf8)))
        var received = [UInt8](repeating: 0, count: 4), count = -2
        for _ in 0..<100 where count == -2 {
            count = channel.receive(&received, capacity: 4)
            if count == -2 { usleep(10_000) }
        }
        XCTAssertEqual(count, 4); XCTAssertEqual(received, Array("pong".utf8))
    }
    func testGuardedSessionRelaysThroughSelectedUpstreamWithoutDirectDNS() throws {
        let fake = try FakeUpstream { fd in
            XCTAssertTrue(Self.readHeader(fd).hasPrefix("CONNECT remote-name.invalid:443 HTTP/1.1\r\n"))
            _ = Self.write(fd, Data("HTTP/1.1 200 Connection established\r\n\r\n".utf8))
            var bytes = [UInt8](repeating:0,count:4)
            XCTAssertEqual(recv(fd,&bytes,4,MSG_WAITALL),4)
            XCTAssertEqual(bytes,Array("ping".utf8))
            _ = Self.write(fd,Data("pong".utf8))
        }
        defer { fake.stop() }
        let monitor = SelectedProxyMonitor(endpoint:try .init(kind:.http,host:"127.0.0.1",port:fake.port))
        let proxy = VPNBoundProxy(verification:try monitor.verify(),monitoring:monitor,onEvent:{_ in})
        let info = try proxy.start();defer{proxy.stop()}
        let client = socket(AF_INET,SOCK_STREAM,0);defer{close(client)}
        BoundSocket.configure(client)
        try BoundSocket.connect(client,address:"127.0.0.1",port:info.port)
        let url = try XCTUnwrap(URLComponents(string:info.proxyURL))
        let auth = Data((try XCTUnwrap(url.user) + ":" + (try XCTUnwrap(url.password))).utf8).base64EncodedString()
        XCTAssertGreaterThan(Self.write(client,Data(("CONNECT remote-name.invalid:443 HTTP/1.1\r\nHost: remote-name.invalid:443\r\nProxy-Authorization: Basic " + auth + "\r\n\r\n").utf8)),0)
        XCTAssertTrue(Self.readHeader(client).hasPrefix("HTTP/1.1 200 Connection Established"))
        XCTAssertEqual(Self.write(client,Data("ping".utf8)),4)
        var received = [UInt8](repeating:0,count:4)
        XCTAssertEqual(recv(client,&received,4,MSG_WAITALL),4)
        XCTAssertEqual(received,Array("pong".utf8))
    }
    func testRejectedHTTPConnectFailsClosed() throws {
        let fake = try FakeUpstream { fd in
            _ = Self.readHeader(fd)
            _ = Self.write(fd, Data("HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n".utf8))
        }
        defer { fake.stop() }
        XCTAssertThrowsError(try UpstreamProxyChannel(endpoint: .init(kind: .http, host: "127.0.0.1", port: fake.port), host: "127.0.0.1", port: 9))
    }
    func testSOCKS5RemoteNameNegotiation() throws {
        let fake = try FakeUpstream { fd in
            var greeting = [UInt8](repeating: 0, count: 2)
            XCTAssertEqual(recv(fd, &greeting, 2, MSG_WAITALL), 2)
            var methods = [UInt8](repeating: 0, count: Int(greeting[1]))
            _ = recv(fd, &methods, methods.count, MSG_WAITALL)
            _ = Self.write(fd, Data([5, 0]))
            var header = [UInt8](repeating: 0, count: 5)
            XCTAssertEqual(recv(fd, &header, 5, MSG_WAITALL), 5)
            XCTAssertEqual(Array(header.prefix(4)), [5, 1, 0, 3])
            var name = [UInt8](repeating: 0, count: Int(header[4]) + 2)
            _ = recv(fd, &name, name.count, MSG_WAITALL)
            XCTAssertEqual(String(decoding: name.dropLast(2), as: UTF8.self), "remote-name.invalid")
            _ = Self.write(fd, Data([5, 0, 0, 1, 127, 0, 0, 1, 0, 80]))
        }
        defer { fake.stop() }
        let channel = try UpstreamProxyChannel(endpoint: .init(kind: .socks5, host: "127.0.0.1", port: fake.port), host: "remote-name.invalid", port: 443)
        channel.close()
    }
    func testSOCKS4ARemoteNameNegotiation() throws {
        let fake = try FakeUpstream { fd in
            var header = [UInt8](repeating: 0, count: 8)
            XCTAssertEqual(recv(fd, &header, 8, MSG_WAITALL), 8)
            XCTAssertEqual(header, [4, 1, 1, 187, 0, 0, 0, 1])
            var byte: UInt8 = 0
            while recv(fd, &byte, 1, 0) == 1, byte != 0 {}
            var name = Data()
            while recv(fd, &byte, 1, 0) == 1, byte != 0 { name.append(byte) }
            XCTAssertEqual(String(decoding: name, as: UTF8.self), "remote-name.invalid")
            _ = Self.write(fd, Data([0, 90, 0, 0, 0, 0, 0, 0]))
        }
        defer { fake.stop() }
        let channel = try UpstreamProxyChannel(endpoint: .init(kind: .socks4a, host: "127.0.0.1", port: fake.port), host: "remote-name.invalid", port: 443)
        channel.close()
    }
    func testHTTPBasicCredentialsPassedOnlyToProxy() throws {
        let fake = try FakeUpstream { fd in
            let request = Self.readHeader(fd)
            XCTAssertTrue(request.contains("Proxy-Authorization: Basic " + Data("test-user:test-password".utf8).base64EncodedString()))
            XCTAssertFalse(request.contains("test-password"))
            _ = Self.write(fd, Data("HTTP/1.1 200 Connection established\r\n\r\n".utf8))
        }
        defer { fake.stop() }
        var error: Int32 = 0
        let channel = vpg_connect("http://127.0.0.1:\(fake.port)", "http://remote-name.invalid:443/", "test-user", "test-password", &error)
        XCTAssertNotNil(channel, "curl code \(error)")
        vpg_close(channel)
    }
    func testEnvironmentNoProxyCannotBypassConfiguredProxy() throws {
        // NO_PROXY includes localhost on many machines; the selected proxy must still see CONNECT.
        let fake = try FakeUpstream { fd in
            XCTAssertTrue(Self.readHeader(fd).hasPrefix("CONNECT localhost:9 "))
            _ = Self.write(fd, Data("HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n".utf8))
        }
        defer { fake.stop() }
        XCTAssertThrowsError(try UpstreamProxyChannel(endpoint: .init(kind: .http, host: "127.0.0.1", port: fake.port), host: "localhost", port: 9))
    }
    func testSOCKS5CredentialsAndAuthenticationRejection() throws {
        let fake = try FakeUpstream { fd in
            var greeting = [UInt8](repeating: 0, count: 2)
            XCTAssertEqual(recv(fd, &greeting, 2, MSG_WAITALL), 2)
            var methods = [UInt8](repeating: 0, count: Int(greeting[1]))
            _ = recv(fd, &methods, methods.count, MSG_WAITALL)
            XCTAssertTrue(methods.contains(2))
            _ = Self.write(fd, Data([5, 2]))
            var auth = [UInt8](repeating: 0, count: 2)
            XCTAssertEqual(recv(fd, &auth, 2, MSG_WAITALL), 2)
            XCTAssertEqual(auth[0], 1)
            var user = [UInt8](repeating: 0, count: Int(auth[1]))
            _ = recv(fd, &user, user.count, MSG_WAITALL)
            XCTAssertEqual(String(decoding: user, as: UTF8.self), "test-user")
            var length: UInt8 = 0
            _ = recv(fd, &length, 1, MSG_WAITALL)
            var password = [UInt8](repeating: 0, count: Int(length))
            _ = recv(fd, &password, password.count, MSG_WAITALL)
            XCTAssertEqual(String(decoding: password, as: UTF8.self), "test-password")
            _ = Self.write(fd, Data([1, 1]))
        }
        defer { fake.stop() }
        var error: Int32 = 0
        let channel = vpg_connect("socks5h://127.0.0.1:\(fake.port)", "http://remote-name.invalid:443/", "test-user", "test-password", &error)
        XCTAssertNil(channel)
        XCTAssertNotEqual(error, 0)
        vpg_close(channel)
    }
    func testSelfSignedHTTPSProxyIsRejected() throws {
        let openssl = "/usr/bin/openssl"
        guard FileManager.default.isExecutableFile(atPath: openssl) else { throw XCTSkip("OpenSSL fixture tool unavailable") }
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("VPNGuard-TLS-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let key = directory.appendingPathComponent("key.pem").path
        let cert = directory.appendingPathComponent("cert.pem").path
        let generate = Process()
        generate.executableURL = URL(fileURLWithPath: openssl)
        generate.arguments = ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert, "-days", "1", "-subj", "/CN=localhost"]
        generate.standardOutput = FileHandle.nullDevice; generate.standardError = FileHandle.nullDevice
        try generate.run(); generate.waitUntilExit()
        guard generate.terminationStatus == 0 else { throw XCTSkip("Cannot generate local TLS fixture") }
        let reservation = try FakeUpstream { _ in }
        let port = reservation.port
        reservation.stop()
        let server = Process()
        server.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
        server.arguments = ["-c", """
        import socket, ssl, sys
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(sys.argv[1], sys.argv[2])
        listener = socket.socket()
        listener.bind(('127.0.0.1', int(sys.argv[3])))
        listener.listen(4)
        while True:
            client, _ = listener.accept()
            try:
                secure = ctx.wrap_socket(client, server_side=True)
                secure.close()
            except ssl.SSLError:
                client.close()
        """, cert, key, String(port)]
        server.standardInput = FileHandle.nullDevice; server.standardOutput = FileHandle.nullDevice; server.standardError = FileHandle.nullDevice
        try server.run()
        defer { if server.isRunning { server.terminate() }; server.waitUntilExit() }
        var ready = false
        for _ in 0..<300 {
            let probe = socket(AF_INET, SOCK_STREAM, 0)
            var address = sockaddr_in(); address.sin_family = sa_family_t(AF_INET)
            address.sin_addr.s_addr = inet_addr("127.0.0.1"); address.sin_port = port.bigEndian
            let result = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(probe, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
            Darwin.close(probe)
            if result == 0 { ready = true; break }
            usleep(10_000)
        }
        XCTAssertTrue(ready)
        guard ready else { return }
        let endpoint = try UpstreamProxyEndpoint(kind: .https, host: "localhost", port: port)
        XCTAssertThrowsError(try UpstreamProxyChannel(endpoint: endpoint, host: "remote-name.invalid", port: 443)) { error in
            guard case UpstreamProxyError.transport(let code) = error else { return XCTFail("Unexpected error \(error)") }
            XCTAssertEqual(code, 60, "Self-signed proxy TLS must fail certificate verification")
        }
    }
    private static func readHeader(_ fd: Int32) -> String {
        var data = Data(), byte: UInt8 = 0
        while data.count < 8192, recv(fd, &byte, 1, 0) == 1 {
            data.append(byte)
            if data.suffix(4) == Data("\r\n\r\n".utf8) { break }
        }
        return String(decoding: data, as: UTF8.self)
    }
    private static func write(_ fd: Int32, _ data: Data) -> Int {
        data.withUnsafeBytes { send(fd, $0.baseAddress, $0.count, 0) }
    }
}
private final class FakeUpstream: @unchecked Sendable {
    let fd: Int32
    let port: UInt16
    private let done = DispatchSemaphore(value: 0)
    init(handler: @escaping @Sendable (Int32) -> Void) throws {
        let listenerFD = socket(AF_INET, SOCK_STREAM, 0)
        fd = listenerFD
        var address = sockaddr_in(); address.sin_family = sa_family_t(AF_INET); address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let result = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listenerFD, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard result == 0, listen(fd, 1) == 0 else { Darwin.close(fd); throw NSError(domain: "FakeProxy", code: 1) }
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(listenerFD, $0, &length) } }
        port = UInt16(bigEndian: address.sin_port)
        let listener = fd, done = self.done
        DispatchQueue.global().async {
            let client = accept(listener, nil, nil)
            if client >= 0 {
                var timeout = timeval(tv_sec: 3, tv_usec: 0), yes: Int32 = 1
                _ = setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
                _ = setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &yes, socklen_t(MemoryLayout<Int32>.size))
                handler(client); Darwin.close(client)
            }
            done.signal()
        }
    }
    func stop() { shutdown(fd, SHUT_RDWR); Darwin.close(fd); _ = done.wait(timeout: .now() + 4) }
}

private struct SelectedProxyMonitor: VPNPathMonitoring {
    let endpoint:UpstreamProxyEndpoint
    func inspect() throws -> GenericVPNPath { GenericVPNPath(interface:"proxy",address:"",interfaceIndex:0,proxy:endpoint) }
    func verify() throws -> VPNVerification {
        let now = Date()
        return VPNVerification(path:try inspect(),exit:try ExitObservation.parse("ip=1.2.3.4\nloc=DE\n",at:now),verifiedAt:now)
    }
    func resolve(_ host:String,path:GenericVPNPath)throws->[String] {
        XCTFail("Proxy traffic must resolve at the chosen proxy, never through local DNS")
        throw GuardError.invalid("Unexpected local DNS")
    }
}
