import XCTest
@testable import VPNGuardCore
final class RuleTests: XCTestCase {
    func testCommandNamesCannotBecomeShellSyntax() {
        XCTAssertTrue(ProtectedItem.validCommandName("claude"))
        for x in ["../claude", "claude;echo", "", "two words", "-x", "$(x)", "if", "then", "for", "function"] { XCTAssertFalse(ProtectedItem.validCommandName(x)) }
    }
    func testRulesRoundTripAndDuplicateIDsAreRejected() throws {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).appendingPathComponent("rules.json")
        defer { try? FileManager.default.removeItem(at: url.deletingLastPathComponent()) }
        let store = RuleStore(url: url)
        let item = try ProtectedItem(name: "Claude CLI", kind: .command, targetPath: "/usr/bin/true", commandName: "claude")
        var settings = GuardPreferences(); settings.items = [item]
        try store.save(settings)
        XCTAssertEqual(try store.load().items, [item])
        settings.items.append(item)
        XCTAssertThrowsError(try store.save(settings))
    }
    func testSameCommandNameCannotShadowAnotherRule() throws {
        let a = try ProtectedItem(name: "A", kind: .command, targetPath: "/usr/bin/true", commandName: "claude")
        let b = try ProtectedItem(name: "B", kind: .command, targetPath: "/usr/bin/false", commandName: "claude")
        XCTAssertThrowsError(try GuardPreferences.validate(items: [a,b]))
    }
}
