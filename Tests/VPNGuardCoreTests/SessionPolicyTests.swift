import XCTest
@testable import VPNGuardCore

final class SessionPolicyTests: XCTestCase {
    func testExcludingOrRemovingRuleRevokesExistingSession() throws {
        let item = try ProtectedItem(name:"Harmless",kind:.command,targetPath:"/bin/sleep",commandName:"probe")
        var settings = GuardPreferences();settings.items = [item]
        XCTAssertTrue(SessionPolicy.permits(ruleID:item.id,settings:settings))
        settings.items[0].isEnabled = false
        XCTAssertFalse(SessionPolicy.permits(ruleID:item.id,settings:settings))
        settings.items = []
        XCTAssertFalse(SessionPolicy.permits(ruleID:item.id,settings:settings))
    }
    func testTurningProtectionOffRevokesExistingSession() throws {
        let item = try ProtectedItem(name:"Harmless",kind:.command,targetPath:"/bin/sleep",commandName:"probe")
        var settings = GuardPreferences();settings.items = [item];settings.protectionEnabled = false
        XCTAssertFalse(SessionPolicy.permits(ruleID:item.id,settings:settings))
    }
}
