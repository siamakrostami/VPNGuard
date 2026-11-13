import XCTest
import Darwin
@testable import VPNGuardCore

final class SessionShutdownTests: XCTestCase {
    func testCheckingRunnerIsTrackedBeforeAnyChildExists() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer{try? FileManager.default.removeItem(at:home)}
        let store = home.appendingPathComponent("rules.json"), sessions = home.appendingPathComponent("Sessions")
        try FileManager.default.createDirectory(at:sessions,withIntermediateDirectories:true)
        var record = GuardSessionRecord(ruleID:UUID(),name:"Harmless",phase:"checking",message:"Checking")
        record.runnerIdentity = ProcessIdentity.capture(getpid())
        XCTAssertNotNil(record.runnerIdentity)
        XCTAssertNil(record.processSession)
        try JSONEncoder().encode(record).write(to:sessions.appendingPathComponent(record.id.uuidString + ".json"))
        let pending = SessionShutdown.records(storeURL:store)
        XCTAssertEqual(pending.count,1)
        XCTAssertEqual(pending.first?.runnerIdentity,record.runnerIdentity)
    }
    func testShutdownTerminatesAnOwnerStillCheckingWithoutAChild() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer{try? FileManager.default.removeItem(at:home)}
        let marker = home.appendingPathComponent("Sessions/" + UUID().uuidString + ".json")
        let process = Process()
        process.executableURL = Bundle(for:SessionShutdownTests.self).bundleURL.deletingLastPathComponent().appendingPathComponent("VPNGuardSessionFixture")
        process.arguments = [marker.path,"--checking"]
        process.standardInput = FileHandle.nullDevice;process.standardOutput = FileHandle.nullDevice;process.standardError = FileHandle.nullDevice
        try process.run()
        defer{if process.isRunning{kill(process.processIdentifier,SIGKILL)};process.waitUntilExit()}
        let ready = Date().addingTimeInterval(3)
        while !FileManager.default.fileExists(atPath:marker.path) && Date() < ready { Thread.sleep(forTimeInterval:0.01) }
        XCTAssertTrue(FileManager.default.fileExists(atPath:marker.path))
        SessionShutdown.stopAll(storeURL:home.appendingPathComponent("rules.json"))
        XCTAssertFalse(process.isRunning,"Quit must cancel a checking owner before it can launch anything")
    }
    func testPolicyFileRevocationNotifiesOnlyOnce() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer{try? FileManager.default.removeItem(at:home)}
        let store = RuleStore(url:home.appendingPathComponent("rules.json"))
        let item = try ProtectedItem(name:"Harmless",kind:.command,targetPath:"/bin/sleep",commandName:"probe")
        var settings = GuardPreferences();settings.items = [item];try store.save(settings)
        let revoked = expectation(description:"Revocation delivered once")
        revoked.assertForOverFulfill = true
        let watcher = SessionPolicyWatcher(ruleID:item.id,store:store) { revoked.fulfill() }
        watcher.checkNow()
        try Data("invalid JSON".utf8).write(to:store.url)
        watcher.checkNow();watcher.checkNow()
        wait(for:[revoked],timeout:1)
    }
}
