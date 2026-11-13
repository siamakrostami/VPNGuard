import XCTest
@testable import VPNGuardCore

final class ConnectionSelectionTests: XCTestCase {
    func testSystemHTTPSProxyMeansHTTPConnectNotTLSProxy() throws {
        let endpoints = try SystemProxyDiscovery.parse(["HTTPSEnable":1, "HTTPSProxy":"127.0.0.1", "HTTPSPort":10809, "SOCKSEnable":1, "SOCKSProxy":"127.0.0.1", "SOCKSPort":10808])
        XCTAssertEqual(endpoints.first?.kind, .http)
        XCTAssertEqual(endpoints.first?.port, 10809)
        XCTAssertEqual(endpoints.last?.kind, .socks5)
    }
    func testExplicitProxyNeverFallsBackToRoutedConnection() throws {
        var settings = ConnectionSettings(); settings.mode = .manualProxy
        XCTAssertThrowsError(try ConnectionSelection.choose(settings: settings, system: [], routed: { XCTFail("Must not fall back"); throw GuardError.invalid("No route") }))
        settings.manualProxy = try UpstreamProxyEndpoint(kind:.socks5,host:"127.0.0.1",port:10808)
        let path = try ConnectionSelection.choose(settings:settings,system:[],routed:{XCTFail("Must not inspect route");throw GuardError.invalid("No route")})
        XCTAssertEqual(path.proxy?.port,10808)
        settings.mode = .systemProxy
        XCTAssertThrowsError(try ConnectionSelection.choose(settings:settings,system:[],routed:{XCTFail("Must not fall back");throw GuardError.invalid("No route")}))
    }
    func testAutomaticPrefersSystemProxyButRoutedModeIgnoresIt() throws {
        let proxy = try UpstreamProxyEndpoint(kind:.http,host:"localhost",port:8080)
        let tunnel = GenericVPNPath(interface:"ppp0",address:"10.1.0.2",interfaceIndex:42)
        var settings = ConnectionSettings()
        XCTAssertEqual(try ConnectionSelection.choose(settings:settings,system:[proxy],routed:{tunnel}).proxy,proxy)
        settings.mode = .routedTunnel
        XCTAssertEqual(try ConnectionSelection.choose(settings:settings,system:[proxy],routed:{tunnel}),tunnel)
    }
    func testPACOnlyIsAnExplicitUnsupportedConfiguration() {
        XCTAssertThrowsError(try SystemProxyDiscovery.parse(["ProxyAutoConfigEnable":1,"ProxyAutoConfigURLString":"https://example.com/proxy.pac"]))
    }
}
