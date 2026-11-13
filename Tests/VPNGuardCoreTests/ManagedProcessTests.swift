import XCTest
import Darwin
@testable import VPNGuardCore

final class ManagedProcessTests: XCTestCase {
    private var host:URL {
        Bundle(for:ManagedProcessTests.self).bundleURL.deletingLastPathComponent().appendingPathComponent("VPNGuardProcessHost")
    }
    func testUnexpectedHostDeathStillTerminatesHarmlessChild() throws {
        let session = ManagedProcessSession()
        let marker = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at:marker) }
        let fixture = host.deletingLastPathComponent().appendingPathComponent("VPNGuardProcessFixture")
        var identity:ProcessSessionIdentity?
        let status = try session.run(host:host,executable:fixture.path,arguments:["ignore-term",marker.path],environment:ProcessInfo.processInfo.environment,handleSignals:false) { value in
            identity = value
            let deadline = Date().addingTimeInterval(2)
            while !FileManager.default.fileExists(atPath:marker.path) && Date() < deadline { Thread.sleep(forTimeInterval:0.01) }
            XCTAssertTrue(FileManager.default.fileExists(atPath:marker.path),"The child must be executing before its host is killed")
            XCTAssertTrue(value.hostIdentity.signal(SIGKILL))
        }
        XCTAssertEqual(status,137)
        XCTAssertFalse(try XCTUnwrap(identity).childIdentity.isLive)
    }
    func testExcludingRuleDuringSessionTerminatesItsChild() throws {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at:folder) }
        let store = RuleStore(url:folder.appendingPathComponent("rules.json"))
        let item = try ProtectedItem(name:"Harmless",kind:.command,targetPath:"/bin/sleep",commandName:"probe")
        var settings = GuardPreferences();settings.items = [item];try store.save(settings)
        let session = ManagedProcessSession()
        let watcher = SessionPolicyWatcher(ruleID:item.id,store:store) { session.requestStop() }
        var identity:ProcessSessionIdentity?
        var fileError:Error?
        let result = try session.run(host:host,executable:"/bin/sleep",arguments:["30"],environment:ProcessInfo.processInfo.environment,handleSignals:false) { value in
            identity = value
            settings.items = []
            do { try store.save(settings) } catch { fileError = error }
            watcher.checkNow()
        }
        XCTAssertNil(fileError)
        XCTAssertNotEqual(result,0)
        XCTAssertFalse(try XCTUnwrap(identity).childIdentity.isLive)
    }
    func testSupervisedCommandTimeoutIsBounded() throws {
        let start = Date()
        XCTAssertThrowsError(try CommandRunner.run("/bin/sleep",["30"],timeout:0.1,supervisor:host)) { error in
            XCTAssertTrue(error.localizedDescription.contains("System command timed out"),error.localizedDescription)
        }
        XCTAssertGreaterThanOrEqual(Date().timeIntervalSince(start),0.08)
        XCTAssertLessThan(Date().timeIntervalSince(start),7)
    }
    func testRunnerSignalHandlerCleansStoppedChildUsingHarmlessFixture() throws {
        try exerciseFixture(signal:SIGTERM,stopChild:true)
    }
    func testAbruptRunnerDeathClosesLeaseAndLeavesNoLiveChild() throws {
        try exerciseFixture(signal:SIGKILL,stopChild:false)
    }
    private func exerciseFixture(signal number:Int32,stopChild:Bool) throws {
        let marker = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer{try? FileManager.default.removeItem(at:marker)}
        let process = Process()
        process.executableURL = host.deletingLastPathComponent().appendingPathComponent("VPNGuardSessionFixture")
        process.arguments = [marker.path,"/bin/sleep","30"]
        process.standardInput = FileHandle.nullDevice;process.standardOutput = FileHandle.nullDevice;process.standardError = FileHandle.nullDevice
        try process.run()
        defer{if process.isRunning{kill(process.processIdentifier,SIGKILL)};process.waitUntilExit()}
        var identity:ProcessSessionIdentity?
        let ready = Date().addingTimeInterval(3)
        while Date() < ready {
            if let data = try? Data(contentsOf:marker), let decoded = try? JSONDecoder().decode(ProcessSessionIdentity.self,from:data){identity = decoded;break}
            Thread.sleep(forTimeInterval:0.01)
        }
        let child = try XCTUnwrap(identity).childIdentity
        if stopChild { XCTAssertTrue(child.signal(SIGSTOP,group:true)) }
        XCTAssertEqual(kill(process.processIdentifier,number),0)
        let deadline = Date().addingTimeInterval(7)
        while Date() < deadline && (process.isRunning || child.isLive) { Thread.sleep(forTimeInterval:0.02) }
        XCTAssertFalse(process.isRunning,"Shared runner signal path must finish within its bound")
        XCTAssertFalse(child.isLive,"Parent death must not leave a live protected group leader")
    }

}
