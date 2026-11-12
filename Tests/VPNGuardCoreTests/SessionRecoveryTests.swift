import XCTest
@testable import VPNGuardCore

final class SessionRecoveryTests: XCTestCase {
    func testResetRequestTargetsOnlyOneSessionAndIsConsumedOnce() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: folder) }
        let store = folder.appendingPathComponent("rules.json"), a = UUID(), b = UUID()
        try SessionConnectionReset.request(sessionID: a, storeURL: store)
        XCTAssertFalse(SessionConnectionReset.consume(sessionID: b, storeURL: store))
        XCTAssertTrue(SessionConnectionReset.consume(sessionID: a, storeURL: store))
        XCTAssertFalse(SessionConnectionReset.consume(sessionID: a, storeURL: store))
    }
}
