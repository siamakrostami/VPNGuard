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
    func testNumericIPv4AliasesCannotReachLocalServicesThroughProxy() {
        for host in ["127.1","127.0.01","0x7f.1","0177.0.0.1","2130706433"] {
            XCTAssertThrowsError(try ConnectRequest.parse(Data("CONNECT \(host):443 HTTP/1.1\r\n\r\n".utf8)),host)
        }
    }
    func testPublicIPv6ConnectAuthorityIsAcceptedWithoutPrivateLiterals() throws {
        let r = try ConnectRequest.parse(Data("CONNECT [2606:4700:4700::1111]:443 HTTP/1.1\r\nHost: [2606:4700:4700::1111]:443\r\n\r\n".utf8))
        XCTAssertEqual(r.host,"2606:4700:4700::1111")
        for host in ["::1","::","fe80::1","fc00::1","::ffff:127.0.0.1"] {
            XCTAssertThrowsError(try ConnectRequest.parse(Data("CONNECT [\(host)]:443 HTTP/1.1\r\n\r\n".utf8)))
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
        proxy.resetConnections()
        let deadline = Date().addingTimeInterval(20)
        while Date() < deadline && (try? proxyResponse(port: info.port)) != "HTTP/1.1 407 Proxy Authentication Required" {
            Thread.sleep(forTimeInterval: 0.1)
        }
        let recovered = try CommandRunner.run("/usr/bin/curl", ["--disable", "--proxy", info.proxyURL, "--noproxy", "", "--fail", "--silent", "--show-error", "--max-time", "15", "https://www.cloudflare.com/cdn-cgi/trace"], timeout: 17)
        XCTAssertEqual(recovered.status, 0, recovered.stderr)
        XCTAssertNotEqual(try ExitObservation.parse(recovered.stdout, at: Date()).country, "IR")
        proxy.stop()
        let denied = try CommandRunner.run("/usr/bin/curl", ["--disable", "--proxy", info.proxyURL, "--noproxy", "", "--silent", "--max-time", "2", "https://www.cloudflare.com/"], timeout: 3)
        XCTAssertNotEqual(denied.status, 0)
        print("Live transport verified: \(verification.path.interface), non-Iran country \(verification.exit.country); dual binding, DoH, CONNECT and stop denial passed.")
    }
    func testLiveSelectedHTTPUpstreamAndRecovery() throws {
        guard ProcessInfo.processInfo.environment["VPNGUARD_LIVE_TRANSPORT_TESTS"] == "1" else { throw XCTSkip("Opt-in live proxy-path diagnostic") }
        // A second guarded broker is a real authenticated HTTP upstream. No user
        // connection settings are changed; its sockets stay bound to the live tunnel.
        let routed = GenericVPNMonitor()
        let inner = VPNBoundProxy(verification:try routed.verify(),monitor:routed,onEvent:{_ in})
        let innerInfo = try inner.start();defer{inner.stop()}
        let url = try XCTUnwrap(URLComponents(string:innerInfo.proxyURL))
        let credential = try ProxyCredentialStore.save(username:try XCTUnwrap(url.user),password:try XCTUnwrap(url.password))
        defer { try? ProxyCredentialStore.delete(id:credential) }
        let endpoint = try UpstreamProxyEndpoint(kind:.http,host:"127.0.0.1",port:innerInfo.port,credentialID:credential)
        let selected = LiveProxyMonitor(endpoint:endpoint)
        let verification = try selected.verify()
        XCTAssertNotEqual(verification.exit.country,"IR")
        let outer = VPNBoundProxy(verification:verification,monitoring:selected,onEvent:{_ in})
        let info = try outer.start();defer{outer.stop()}
        func request() throws -> CommandOutput {
            try CommandRunner.run("/usr/bin/curl",["--disable","--proxy",info.proxyURL,"--noproxy","","--fail","--silent","--show-error","--max-time","15","https://www.cloudflare.com/cdn-cgi/trace"],timeout:17)
        }
        XCTAssertEqual(try request().status,0)
        outer.resetConnections()
        let deadline = Date().addingTimeInterval(20)
        while Date() < deadline && (try? proxyResponse(port:info.port)) != "HTTP/1.1 407 Proxy Authentication Required" { Thread.sleep(forTimeInterval:0.1) }
        XCTAssertEqual(try request().status,0,"Selected upstream must recover using the same child endpoint")
        inner.stop()
        outer.resetConnections()
        XCTAssertNotEqual(try request().status,0,"An unavailable selected proxy must never fall back to the still-working routed VPN")
    }

    func testOutageRecoveryKeepsTheExistingProxyEndpoint() throws {
        let monitor = RecoveringTransportMonitor()
        let proxy = VPNBoundProxy(verification: try monitor.verify(), monitoring: monitor, onEvent: { _ in })
        let info = try proxy.start(); defer { proxy.stop() }
        monitor.setAvailable(false)
        Thread.sleep(forTimeInterval: 1.4)
        XCTAssertEqual(try proxyResponse(port: info.port), "HTTP/1.1 503 Service Unavailable")
        monitor.setPath(GenericVPNPath(interface: "utun9998", address: "10.8.0.2", interfaceIndex: 9998))
        monitor.setAvailable(true)
        let deadline = Date().addingTimeInterval(8)
        var response = ""
        repeat {
            response = (try? proxyResponse(port: info.port)) ?? "closed"
            if response == "HTTP/1.1 407 Proxy Authentication Required" { break }
            Thread.sleep(forTimeInterval: 0.1)
        } while Date() < deadline
        XCTAssertEqual(response, "HTTP/1.1 407 Proxy Authentication Required", "Existing CLI proxy endpoint must recover without a new process")
        XCTAssertEqual(try proxyResponse(port: info.port, proxyURL: info.proxyURL), "HTTP/1.1 502 Bad Gateway", "Original credentials must reach resolution using the new verified path")
    }

    func testResetClosesOldSocketsAndRejectsIranExitBeforeRecovering() throws {
        let monitor = RecoveringTransportMonitor(delayResolve: true)
        defer { monitor.releaseResolve.signal() }
        let proxy = VPNBoundProxy(verification: try monitor.verify(), monitoring: monitor, onEvent: { _ in })
        let info = try proxy.start(); defer { proxy.stop() }
        let client = socket(AF_INET, SOCK_STREAM, 0); defer { close(client) }
        BoundSocket.configure(client)
        try BoundSocket.connect(client, address: "127.0.0.1", port: info.port)
        let url = try XCTUnwrap(URLComponents(string: info.proxyURL))
        let auth = Data((try XCTUnwrap(url.user) + ":" + (try XCTUnwrap(url.password))).utf8).base64EncodedString()
        XCTAssertTrue(BoundSocket.sendAll(client, Data(("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\nProxy-Authorization: Basic " + auth + "\r\n\r\n").utf8)))
        XCTAssertEqual(monitor.resolveEntered.wait(timeout: .now() + 3), .success)
        monitor.setCountry("IR")
        proxy.resetConnections()
        var byte: UInt8 = 0
        XCTAssertEqual(recv(client, &byte, 1, 0), 0)
        Thread.sleep(forTimeInterval: 0.2)
        XCTAssertEqual(try proxyResponse(port: info.port), "HTTP/1.1 503 Service Unavailable")
        monitor.setCountry("DE")
        proxy.resetConnections()
        let deadline = Date().addingTimeInterval(3)
        while Date() < deadline && (try? proxyResponse(port: info.port)) != "HTTP/1.1 407 Proxy Authentication Required" {
            Thread.sleep(forTimeInterval: 0.05)
        }
        XCTAssertEqual(try proxyResponse(port: info.port), "HTTP/1.1 407 Proxy Authentication Required")
        // Original credentials still authorize requests (DNS deliberately fails in this test).
        XCTAssertEqual(try proxyResponse(port: info.port, proxyURL: info.proxyURL), "HTTP/1.1 502 Bad Gateway")
        proxy.stop(); proxy.resetConnections()
        Thread.sleep(forTimeInterval: 0.3)
        XCTAssertThrowsError(try proxyResponse(port: info.port))
    }

    func testVerificationFromBeforeAnotherResetCannotRestoreConnections() throws {
        let monitor = DelayedRecoveryMonitor()
        let now = Date()
        let initial = VPNVerification(path: monitor.path, exit: try ExitObservation.parse("ip=1.2.3.4\nloc=DE\n", at: now), verifiedAt: now)
        let proxy = VPNBoundProxy(verification: initial, monitoring: monitor, onEvent: { _ in })
        let info = try proxy.start(); defer { proxy.stop(); monitor.release.signal() }
        proxy.resetConnections()
        XCTAssertEqual(monitor.entered.wait(timeout: .now() + 3), .success)
        proxy.resetConnections() // Invalidates the outstanding successful verification.
        monitor.release.signal()
        XCTAssertEqual(monitor.retried.wait(timeout: .now() + 3), .success)
        XCTAssertEqual(try proxyResponse(port: info.port), "HTTP/1.1 503 Service Unavailable")
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
        XCTAssertEqual(try proxyResponse(port: info.port), "HTTP/1.1 503 Service Unavailable")
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

private func proxyResponse(port: UInt16, proxyURL: String? = nil) throws -> String {
    let fd = socket(AF_INET, SOCK_STREAM, 0); defer { close(fd) }
    BoundSocket.configure(fd)
    try BoundSocket.connect(fd, address: "127.0.0.1", port: port)
    var auth = ""
    if let proxyURL, let url = URLComponents(string: proxyURL), let user = url.user, let password = url.password {
        auth = "Proxy-Authorization: Basic " + Data((user + ":" + password).utf8).base64EncodedString() + "\r\n"
    }
    guard BoundSocket.sendAll(fd, Data(("CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n" + auth + "\r\n").utf8)) else { return "closed" }
    var data = [UInt8](repeating: 0, count: 2048)
    let n = recv(fd, &data, data.count, 0)
    guard n > 0 else { return "closed" }
    return String(decoding: data.prefix(n), as: UTF8.self).components(separatedBy: "\r\n")[0]
}

private final class RecoveringTransportMonitor: VPNPathMonitoring, @unchecked Sendable {
    private let lock = NSLock()
    private var available = true
    private var country = "DE"
    private let delayResolve: Bool
    let resolveEntered = DispatchSemaphore(value: 0), releaseResolve = DispatchSemaphore(value: 0)
    init(delayResolve: Bool = false) { self.delayResolve = delayResolve }
    private var currentPath = GenericVPNPath(interface: "utun9999", address: "10.0.0.2", interfaceIndex: 9999)
    func setPath(_ path: GenericVPNPath) { lock.lock(); currentPath = path; lock.unlock() }
    func setCountry(_ value: String) { lock.lock(); country = value; lock.unlock() }
    func setAvailable(_ value: Bool) { lock.lock(); available = value; lock.unlock() }
    func inspect() throws -> GenericVPNPath {
        lock.lock(); defer { lock.unlock() }
        guard available else { throw GuardError.invalid("Simulated VPN outage") }
        return currentPath
    }
    func verify() throws -> VPNVerification {
        let path = try inspect(), now = Date()
        lock.lock(); let country = self.country; lock.unlock()
        return VPNVerification(path: path, exit: ExitObservation(address: "1.2.3.4", country: country, checkedAt: now), verifiedAt: now)
    }
    func resolve(_ host: String, path: GenericVPNPath) throws -> [String] {
        if delayResolve { resolveEntered.signal(); _ = releaseResolve.wait(timeout: .now() + 3) }
        throw GuardError.invalid("No external network in recovery tests")
    }
}

private final class DelayedRecoveryMonitor: VPNPathMonitoring, @unchecked Sendable {
    let path = GenericVPNPath(interface: "utun9999", address: "10.0.0.2", interfaceIndex: 9999)
    let entered = DispatchSemaphore(value: 0), release = DispatchSemaphore(value: 0), retried = DispatchSemaphore(value: 0)
    private let lock = NSLock()
    private var calls = 0
    func inspect() throws -> GenericVPNPath { path }
    func verify() throws -> VPNVerification {
        lock.lock(); calls += 1; let first = calls == 1; lock.unlock()
        guard first else { retried.signal(); throw GuardError.invalid("New verification failed") }
        entered.signal(); _ = release.wait(timeout: .now() + 5)
        let now = Date()
        return VPNVerification(path: path, exit: ExitObservation(address: "1.2.3.4", country: "DE", checkedAt: now), verifiedAt: now)
    }
    func resolve(_ host: String, path: GenericVPNPath) throws -> [String] { throw GuardError.invalid("No external network in recovery tests") }
}

private struct LiveProxyMonitor: VPNPathMonitoring {
    let endpoint:UpstreamProxyEndpoint
    func inspect() throws -> GenericVPNPath { GenericVPNPath(interface:"proxy",address:"",interfaceIndex:0,proxy:endpoint) }
    func verify() throws -> VPNVerification {
        let body = try UpstreamProxyChannel.fetchTrace(endpoint:endpoint), now = Date()
        return VPNVerification(path:try inspect(),exit:try ExitObservation.parse(body,at:now),verifiedAt:now)
    }
    func resolve(_ host:String,path:GenericVPNPath)throws->[String] { throw GuardError.invalid("Proxy destinations must not resolve locally") }
}
