import XCTest
@testable import VPNGuardCore

final class InternetAddressTests: XCTestCase {
    func testInvalidAndPrivateIPv4DestinationsAreRejected() {
        for value in ["1.2.3.999", "1.2.3", "1.2.3.4;echo", "01.2.3.4", "", "::1", "1.2.3.-1"] {
            XCTAssertFalse(IPv4.isValid(value), value)
        }
        for value in ["127.0.0.1", "0.0.0.0", "192.168.1.1", "224.0.0.1", "169.254.1.2"] {
            XCTAssertFalse(IPv4.isPublic(value), value)
        }
        XCTAssertTrue(IPv4.isPublic("8.8.8.8"))
    }
    func testIranAndUnknownExitCountriesAreRejected() throws {
        for text in ["ip=8.8.8.8\nloc=IR", "ip=8.8.8.8\nloc=XX", "ip=127.0.0.1\nloc=DE", "ip=8.8.8.8\nloc=DE\nloc=US"] {
            XCTAssertThrowsError(try ExitObservation.parse(text, at: Date()))
        }
        XCTAssertEqual(try ExitObservation.parse("ip=8.8.8.8\nloc=DE", at: Date()).country, "DE")
    }
    func testDNSNamesCannotContainInjectedRequestSyntax() {
        XCTAssertTrue(DNSHostname.isValid("api.example.com"))
        for text in ["", "1.2.3.4", "api.example.com/path", "host\r\nInjected", "bad;command.example", "-bad.example", "a..example"] {
            XCTAssertFalse(DNSHostname.isValid(text), text)
        }
    }
}
