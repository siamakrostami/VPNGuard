import XCTest
import Darwin
@testable import VPNGuardCore

final class TransportTests: XCTestCase {
    func testStrictConnectAuthorityAndHeaders() throws {
        let r = try ConnectRequest.parse(Data("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n".utf8))
        XCTAssertEqual(r.host, "example.com"); XCTAssertEqual(r.port, 443)
        for input in ["GET / HTTP/1.1\r\n\r\n", "CONNECT [::1]:443 HTTP/1.1\r\n\r\n", "CONNECT 127.0.0.1:443 HTTP/1.1\r\n\r\n", "CONNECT x.com:0 HTTP/1.1\r\n\r\n", "CONNECT x.com:443 HTTP/1.1\r\nContent-Length: 1\r\n\r\nx", "CONNECT x.com:443 HTTP/1.1\r\n Transfer-Encoding: chunked\r\n\r\n", "CONNECT x.com:443 HTTP/1.1\r\nHost: other.com:443\r\n\r\n"] {
            XCTAssertThrowsError(try ConnectRequest.parse(Data(input.utf8)), input)
        }
    }
    func testRouteSelectionRejectsAmbiguityAndPhysicalRoute() throws {
        let good = "interface: utun4\n"
        XCTAssertEqual(try TransportParsing.path(routes: [good, good], interfaceText: "utun4: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST>\n inet 10.7.0.2 --> 10.7.0.1 netmask 0xffffffff\n", index: 9).interfaceIndex, 9)
        XCTAssertThrowsError(try TransportParsing.path(routes: [good,"interface: en0\n"], interfaceText: "inet 10.7.0.2\n", index: 9))
        XCTAssertThrowsError(try TransportParsing.path(routes: [good,good], interfaceText: "inet 10.7.0.2\ninet 10.8.0.2\n", index: 9))
        XCTAssertThrowsError(try TransportParsing.path(routes: [good,good], interfaceText: "inet 10.7.0.2\n", index: 0))
    }
    func testDoHOnlyAcceptsPublicIPv4Answers() throws {
        XCTAssertEqual(try TransportParsing.doh(Data(#"{"Status":0,"Answer":[{"type":1,"data":"1.2.3.4"}]}"#.utf8)), ["1.2.3.4"])
        for json in [#"{"Status":0,"Answer":[{"type":1,"data":"127.0.0.1"}]}"#, #"{"Status":3}"#, #"{"Status":0,"Answer":[{"type":28,"data":"::1"}]}"#] {
            XCTAssertThrowsError(try TransportParsing.doh(Data(json.utf8)))
        }
    }
    func testStaleVerificationCannotStartListener() throws {
        let path = GenericVPNPath(interface: "utun9999", address: "10.0.0.2", interfaceIndex: 9999)
        let exit = try ExitObservation.parse("ip=1.2.3.4\nloc=DE\n", at: Date().addingTimeInterval(-60))
        let proxy = VPNBoundProxy(verification: VPNVerification(path: path, exit: exit, verifiedAt: Date().addingTimeInterval(-60)), monitor: GenericVPNMonitor(), onEvent: { _ in })
        XCTAssertThrowsError(try proxy.start())
        proxy.stop(); proxy.stop()
    }
    func testPinnedHTTPSBridgeRejectsNonexistentInterface() {
        let path = GenericVPNPath(interface: "utun9999", address: "10.0.0.2", interfaceIndex: UInt32.max)
        XCTAssertThrowsError(try PinnedHTTPS.fetch(path: path, host: "www.cloudflare.com", address: "104.16.123.96", resource: "/cdn-cgi/trace"))
    }
    func testNativeSocketTransferAndCloseOnExec() throws {
        var pair: [Int32] = [-1, -1]
        XCTAssertEqual(socketpair(AF_UNIX, SOCK_STREAM, 0, &pair), 0)
        defer { close(pair[0]); close(pair[1]) }
        BoundSocket.configure(pair[0]); BoundSocket.configure(pair[1])
        XCTAssertNotEqual(fcntl(pair[0], F_GETFD) & FD_CLOEXEC, 0)
        let data = Data("opaque TLS bytes\0\u{ff}".utf8)
        XCTAssertTrue(BoundSocket.sendAll(pair[0], data))
        var bytes = [UInt8](repeating: 0, count: 128)
        let n = recv(pair[1], &bytes, bytes.count, 0)
        XCTAssertEqual(Data(bytes.prefix(n)), data)
    }
    func testLiveTunnelBoundHTTPSAndProxy() throws {
        guard ProcessInfo.processInfo.environment["VPNGUARD_LIVE_TRANSPORT_TESTS"] == "1" else {
            throw XCTSkip("Set VPNGUARD_LIVE_TRANSPORT_TESTS=1 to run harmless read-only live diagnostics.")
        }
        let monitor = GenericVPNMonitor()
        let verification = try monitor.verify()
        XCTAssertFalse(try monitor.resolve("www.cloudflare.com", path: verification.path).isEmpty)
        let bound = try BoundSocket.make(path: verification.path)
        defer { close(bound) }
        var index: UInt32 = 0; var size = socklen_t(MemoryLayout<UInt32>.size)
        XCTAssertEqual(getsockopt(bound, IPPROTO_IP, IP_BOUND_IF, &index, &size), 0)
        XCTAssertEqual(index, verification.path.interfaceIndex)
        var source = sockaddr_in(); size = socklen_t(MemoryLayout<sockaddr_in>.size)
        XCTAssertEqual(withUnsafeMutablePointer(to: &source) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(bound, $0, &size) } }, 0)
        var ip = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
        _ = inet_ntop(AF_INET, &source.sin_addr, &ip, socklen_t(ip.count))
        XCTAssertEqual(String(decoding: ip.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self), verification.path.address)
        let proxy = VPNBoundProxy(verification: verification, monitor: monitor, onEvent: { _ in })
        let info = try proxy.start(); defer { proxy.stop() }
        let result = try CommandRunner.run("/usr/bin/curl", ["--disable", "--proxy", info.proxyURL, "--noproxy", "", "--fail", "--silent", "--show-error", "--connect-timeout", "10", "--max-time", "15", "https://www.cloudflare.com/cdn-cgi/trace"], timeout: 17)
        XCTAssertEqual(result.status, 0, result.stderr)
        let exit = try ExitObservation.parse(result.stdout, at: Date())
        XCTAssertEqual(exit.country, verification.exit.country)
        let unauthorized = try CommandRunner.run("/usr/bin/curl", ["--disable", "--proxy", "http://127.0.0.1:\(info.port)", "--noproxy", "", "--silent", "--max-time", "2", "https://www.cloudflare.com/"], timeout: 3)
        XCTAssertNotEqual(unauthorized.status, 0)
        proxy.stop()
        let denied = try CommandRunner.run("/usr/bin/curl", ["--disable", "--proxy", info.proxyURL, "--noproxy", "", "--silent", "--max-time", "2", "https://www.cloudflare.com/"], timeout: 3)
        XCTAssertNotEqual(denied.status, 0)
        print("Live transport verified: \(verification.path.interface), non-Iran country \(verification.exit.country); dual binding, DoH, CONNECT and stop denial passed.")
    }
    func testTopologyLossClosesAcceptedConnectionWithoutChangingNetwork() throws {
        let path = GenericVPNPath(interface: "utun9999", address: "10.0.0.2", interfaceIndex: 9999)
        let now = Date()
        let verification = VPNVerification(path: path, exit: try ExitObservation.parse("ip=1.2.3.4\nloc=DE\n", at: now), verifiedAt: now)
        let monitor = ChangingTransportMonitor(path: path)
        let proxy = VPNBoundProxy(verification: verification, monitoring: monitor, onEvent: { _ in })
        let info = try proxy.start(); defer { proxy.stop() }
        let client = socket(AF_INET, SOCK_STREAM, 0); defer { close(client) }
        BoundSocket.configure(client)
        try BoundSocket.connect(client, address: "127.0.0.1", port: info.port)
        XCTAssertTrue(BoundSocket.sendAll(client, Data("CONNECT".utf8)))
        Thread.sleep(forTimeInterval: 2)
        var byte: UInt8 = 0
        XCTAssertEqual(recv(client, &byte, 1, 0), 0)
        let later = socket(AF_INET, SOCK_STREAM, 0); defer { close(later) }
        XCTAssertThrowsError(try BoundSocket.connect(later, address: "127.0.0.1", port: info.port))
    }
    func testExpiryWatchdogClosesConnectionWhileVerifierIsStalled() throws {
        let path = GenericVPNPath(interface: "utun9999", address: "10.0.0.2", interfaceIndex: 9999)
        let old = Date().addingTimeInterval(-29)
        let verification = VPNVerification(path: path, exit: try ExitObservation.parse("ip=1.2.3.4\nloc=DE\n", at: old), verifiedAt: old)
        let proxy = VPNBoundProxy(verification: verification, monitoring: StalledTransportMonitor(path: path), onEvent: { _ in })
        let info = try proxy.start(); defer { proxy.stop() }
        let client = socket(AF_INET, SOCK_STREAM, 0); defer { close(client) }
        BoundSocket.configure(client)
        try BoundSocket.connect(client, address: "127.0.0.1", port: info.port)
        XCTAssertTrue(BoundSocket.sendAll(client, Data("CONNECT".utf8)))
        Thread.sleep(forTimeInterval: 2.2)
        var byte: UInt8 = 0
        XCTAssertEqual(recv(client, &byte, 1, 0), 0)
    }
    func testVerificationRejectsUnknownCountryAndFutureTimestamp() {
        let path = GenericVPNPath(interface: "utun1", address: "10.0.0.2", interfaceIndex: 9)
        let now = Date()
        let unknown = ExitObservation(address: "1.2.3.4", country: "ZZ", checkedAt: now)
        XCTAssertFalse(VPNVerification(path: path, exit: unknown, verifiedAt: now).isFresh)
        let future = now.addingTimeInterval(10)
        let exit = ExitObservation(address: "1.2.3.4", country: "DE", checkedAt: future)
        XCTAssertFalse(VPNVerification(path: path, exit: exit, verifiedAt: future).isFresh)
    }
    func testNativeBindingRejectsNonexistentInterface() {
        let path = GenericVPNPath(interface: "utun9999", address: "10.0.0.2", interfaceIndex: UInt32.max)
        XCTAssertThrowsError(try BoundSocket.make(path: path))
    }
}

private final class ChangingTransportMonitor: VPNPathMonitoring, @unchecked Sendable {
    let path: GenericVPNPath
    let lock = NSLock()
    var calls = 0
    init(path: GenericVPNPath) { self.path = path }
    func inspect() throws -> GenericVPNPath {
        lock.lock(); defer { lock.unlock() }; calls += 1
        guard calls == 1 else { throw GuardError.invalid("Simulated topology loss") }
        return path
    }
    func verify() throws -> VPNVerification { throw GuardError.invalid("Simulated verification failure") }
    func resolve(_ host: String, path: GenericVPNPath) throws -> [String] { throw GuardError.invalid("No test DNS") }
}

private struct StalledTransportMonitor: VPNPathMonitoring {
    let path: GenericVPNPath
    func inspect() throws -> GenericVPNPath { path }
    func verify() throws -> VPNVerification { Thread.sleep(forTimeInterval: 4); throw GuardError.invalid("Stalled verification") }
    func resolve(_ host: String, path: GenericVPNPath) throws -> [String] { throw GuardError.invalid("No test DNS") }
}
