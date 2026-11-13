import XCTest
@testable import VPNGuardCore

final class RoutedTunnelTests: XCTestCase {
    func testL2TPTunnelIsAcceptedButPhysicalInterfaceIsRejected() throws {
        let ppp = "interface: ppp0\n"
        let text = "ppp0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST>\n inet 10.9.0.2 --> 10.9.0.1 netmask 0xffffffff\n"
        XCTAssertEqual(try TransportParsing.path(routes: [ppp, ppp], interfaceText: text, index: 9).interface, "ppp0")
        XCTAssertThrowsError(try TransportParsing.path(routes: ["interface: en0\n", "interface: en0\n"], interfaceText: text, index: 9))
    }
}

extension RoutedTunnelTests {
    func testIPv6TunnelIgnoresLinkLocalAndBindsExplicitGlobalSource() throws {
        let route = "interface: utun8\n"
        let text = "utun8: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST>\n inet6 fe80::1%utun8 prefixlen 64 scopeid 0x8\n inet6 2001:4860:1::2 prefixlen 64\n"
        let path = try RoutedTunnelDiscovery.path(routes: [route, route], interfaceText: text, index: 8, ipv6: true)
        XCTAssertEqual(path.address, "2001:4860:1::2")
        XCTAssertTrue(path.isIPv6)
        XCTAssertEqual(try RoutedTunnelDiscovery.select(ipv4: nil, ipv6: path), path)
        XCTAssertThrowsError(try RoutedTunnelDiscovery.select(ipv4: nil, ipv6: nil))
    }

    func testSplitFamilyRoutesAndInactiveInterfaceAreRejected() {
        let text = "ppp0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST>\n inet 10.9.0.2 --> 10.9.0.1 netmask 0xffffffff\n"
        XCTAssertThrowsError(try RoutedTunnelDiscovery.path(routes: ["interface: ppp0\n", "interface: en0\n"], interfaceText: text, index: 9, ipv6: false))
        XCTAssertThrowsError(try RoutedTunnelDiscovery.path(routes: ["interface: ppp0\n", "interface: ppp0\n"], interfaceText: text.replacingOccurrences(of: "<UP,", with: "<"), index: 9, ipv6: false))
    }

    func testIPv6DNSRejectsPrivateAndMappedDestinationsAndNeverReturnsIPv4() throws {
        let good = Data(#"{"Status":0,"Answer":[{"type":28,"data":"2606:4700:4700::1111"},{"type":1,"data":"1.1.1.1"}]}"#.utf8)
        XCTAssertEqual(try TransportParsing.doh(good, ipv6: true), ["2606:4700:4700::1111"])
        for address in ["::", "::1", "fe80::1", "fd00::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:7f00:1", "2001:db8::1", "2002:7f00:1::", "64:ff9b::7f00:1"] {
            XCTAssertFalse(IPv6.isPublic(address), address)
            let data = try JSONSerialization.data(withJSONObject: ["Status": 0, "Answer": [["type": 28, "data": address]]])
            XCTAssertThrowsError(try TransportParsing.doh(data, ipv6: true), address)
        }
        XCTAssertThrowsError(try TransportParsing.doh(Data(#"{"Status":0,"Answer":[{"type":1,"data":"1.1.1.1"}]}"#.utf8), ipv6: true))
    }

    func testIPv6ExitVerificationAcceptsOnlyPublicNonIranAddress() throws {
        let exit = try ExitObservation.parse("ip=2606:4700:4700::1111\nloc=DE\n", at: Date())
        let path = GenericVPNPath(interface: "utun8", address: "fd00::2", interfaceIndex: 8)
        XCTAssertTrue(VPNVerification(path: path, exit: exit, verifiedAt: exit.checkedAt).isFresh)
        XCTAssertThrowsError(try ExitObservation.parse("ip=fd00::1\nloc=DE\n", at: Date()))
        XCTAssertThrowsError(try ExitObservation.parse("ip=2606:4700:4700::1111\nloc=IR\n", at: Date()))
    }
}
