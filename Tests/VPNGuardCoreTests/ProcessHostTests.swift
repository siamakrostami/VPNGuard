import XCTest
import Foundation
import Darwin
import CProcessLifecycle

final class ProcessHostTests: XCTestCase {
    func testControlEOFTerminatesChildWithinBound() throws {
        let host = try HostedChild(arguments: ["/bin/sleep", "30"])
        defer { host.cleanup() }
        let started = Date()
        host.closeControl()
        XCTAssertTrue(host.waitForExit(timeout: 7), "Supervisor must finish cleanup after its parent disappears")
        XCTAssertLessThan(Date().timeIntervalSince(started), 2, "A reaped-ready leader alone must not consume the TERM grace period")
        XCTAssertFalse(host.childStillExists())
    }

    func testStoppedChildIsResumedAndTerminatedWhenHostReceivesTERM() throws {
        let host = try HostedChild(arguments: ["/bin/sleep", "30"])
        defer { host.cleanup() }
        XCTAssertEqual(kill(host.child.pid, SIGSTOP), 0)
        XCTAssertEqual(kill(host.pid, SIGTERM), 0)
        XCTAssertTrue(host.waitForExit(timeout: 7))
        XCTAssertFalse(host.childStillExists())
    }
    func testIgnoringTERMIsKilledAfterGracePeriod() throws {
        let marker = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: marker) }
        let host = try HostedChild(arguments: [HostedChild.tool("VPNGuardProcessFixture"), "ignore-term", marker.path])
        defer { host.cleanup() }
        XCTAssertTrue(waitForFile(marker))
        let started = Date()
        host.closeControl()
        XCTAssertTrue(host.waitForExit(timeout: 7), "Ignoring TERM must not leave the supervisor waiting forever")
        XCTAssertGreaterThanOrEqual(Date().timeIntervalSince(started), 4.5)
        XCTAssertFalse(host.childStillExists())
    }
    func testPrimaryExitAlsoKillsItsTERMResistantDescendant() throws {
        let marker = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: marker) }
        let host = try HostedChild(arguments: [HostedChild.tool("VPNGuardProcessFixture"), "descendant", marker.path])
        defer { host.cleanup() }
        let descendant = try waitForFixtureIdentity(marker)
        defer { _ = vpg_signal_identity(descendant, SIGKILL, 0) }
        XCTAssertTrue(host.waitForExit(timeout: 7))
        XCTAssertEqual(host.exitCode, 0)
        XCTAssertFalse(host.childStillExists())
        var current = vpg_process_identity()
        let deadline = Date().addingTimeInterval(2)
        while Date() < deadline && vpg_process_identity_read(descendant.pid, &current) == 0 { usleep(20_000) }
        XCTAssertNotEqual(vpg_process_identity_read(descendant.pid, &current), 0, "No live descendant may outlast the host")
    }

    func testLifetimeAndStatusDescriptorsAreNotInheritedByChild() throws {
        let host = try HostedChild(arguments: [HostedChild.tool("VPNGuardProcessFixture"), "fds-closed"])
        defer { host.cleanup() }
        XCTAssertTrue(host.waitForExit(timeout: 7))
        XCTAssertEqual(host.exitCode, 0)
    }

    func testUnsolicitedChildStopTriggersCleanupWithoutStoppingHost() throws {
        let host = try HostedChild(arguments: ["/bin/sleep", "30"])
        defer { host.cleanup() }
        XCTAssertEqual(kill(host.child.pid, SIGSTOP), 0)
        XCTAssertTrue(host.waitForExit(timeout: 7))
        XCTAssertFalse(host.childStillExists())
    }

    func testIdentityCheckRejectsWrongStartCookieWithoutSignallingProcess() {
        var identity = vpg_process_identity()
        XCTAssertEqual(vpg_process_identity_read(getpid(), &identity), 0)
        XCTAssertEqual(vpg_signal_identity(identity, 0, 0), 0)
        identity.microseconds += 1
        XCTAssertEqual(vpg_signal_identity(identity, SIGTERM, 0), -1)
        XCTAssertEqual(errno, ESRCH)
        XCTAssertEqual(vpg_process_identity_read(0, &identity), -1)
    }

    private func waitForFixtureIdentity(_ url: URL) throws -> vpg_process_identity {
        let deadline = Date().addingTimeInterval(2)
        while Date() < deadline {
            if let text = try? String(contentsOf: url, encoding: .utf8), let pid = Int32(text.trimmingCharacters(in: .whitespacesAndNewlines)) {
                var identity = vpg_process_identity()
                if vpg_process_identity_read(pid, &identity) == 0 { return identity }
            }
            usleep(20_000)
        }
        throw NSError(domain: "ProcessHostTests: fixture did not start", code: 4)
    }

    private func waitForFile(_ url: URL) -> Bool {
        let deadline = Date().addingTimeInterval(2)
        while Date() < deadline {
            if FileManager.default.fileExists(atPath: url.path) { return true }
            usleep(20_000)
        }
        return false
    }

}

private struct HostIdentity: Decodable {
    let pid: Int32
    let seconds: UInt64
    let microseconds: UInt64
}
private struct HostStatus: Decodable {
    let childIdentity: HostIdentity
    let hostIdentity: HostIdentity
}

private final class HostedChild {
    let pid: Int32
    let child: HostIdentity
    private var control: Int32
    private var reaped = false
    private(set) var exitCode: Int32?
    init(arguments: [String]) throws {
        let executable = Self.tool("VPNGuardProcessHost")
        guard FileManager.default.isExecutableFile(atPath: executable) else {
            XCTFail("The supervisor helper must be built by swift test: \(executable)")
            throw NSError(domain: "ProcessHostTests", code: 1)
        }
        var controlPipe: [Int32] = [-1, -1], statusPipe: [Int32] = [-1, -1]
        guard pipe(&controlPipe) == 0, pipe(&statusPipe) == 0 else { throw NSError(domain: "ProcessHostTests", code: 2) }
        let readControl = fcntl(controlPipe[0], F_DUPFD_CLOEXEC, 10)
        let writeStatus = fcntl(statusPipe[1], F_DUPFD_CLOEXEC, 10)
        close(controlPipe[0]); close(statusPipe[1])
        defer { close(readControl); close(writeStatus); close(statusPipe[0]) }
        var actions: posix_spawn_file_actions_t?, attr: posix_spawnattr_t?
        posix_spawn_file_actions_init(&actions); posix_spawnattr_init(&attr)
        defer { posix_spawn_file_actions_destroy(&actions); posix_spawnattr_destroy(&attr) }
        posix_spawn_file_actions_adddup2(&actions, readControl, 3)
        posix_spawn_file_actions_adddup2(&actions, writeStatus, 4)
        for fd in [STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO] where fcntl(fd, F_GETFD) >= 0 {
            posix_spawn_file_actions_addinherit_np(&actions, fd)
        }
        posix_spawnattr_setflags(&attr, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT))
        let values = [executable, "--control-fd", "3", "--status-fd", "4", "--foreground-group", "-1", "--"] + arguments
        let argv = values.map { strdup($0) } + [nil]
        defer { argv.forEach { free($0) } }
        let environment = ProcessInfo.processInfo.environment.map { strdup($0.key + "=" + $0.value) } + [nil]
        defer { environment.forEach { free($0) } }
        var spawned: pid_t = 0
        let result = argv.withUnsafeBufferPointer { argv in environment.withUnsafeBufferPointer { env in posix_spawn(&spawned, executable, &actions, &attr, argv.baseAddress!, env.baseAddress!) } }
        guard result == 0 else { close(controlPipe[1]); throw NSError(domain: NSPOSIXErrorDomain, code: Int(result)) }
        var bytes = Data()
        let deadline = Date().addingTimeInterval(3)
        while Date() < deadline, !bytes.contains(10) {
            var poller = pollfd(fd: statusPipe[0], events: Int16(POLLIN), revents: 0)
            if poll(&poller, 1, 100) > 0 {
                var chunk = [UInt8](repeating: 0, count: 1024)
                let count = read(statusPipe[0], &chunk, chunk.count)
                if count <= 0 { break }
                bytes.append(contentsOf: chunk.prefix(count))
            }
        }
        guard let status = try? JSONDecoder().decode(HostStatus.self, from: bytes), status.hostIdentity.pid == spawned else {
            close(controlPipe[1]); kill(spawned, SIGTERM)
            _ = waitpid(spawned, nil, 0)
            throw NSError(domain: "ProcessHostTests: missing status", code: 3)
        }
        pid = spawned; child = status.childIdentity; control = controlPipe[1]
    }
    static func tool(_ name: String) -> String {
        let binaryFolder = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent()
        // SwiftPM's XCTest executable is inside an .xctest bundle with Xcode builds.
        let candidates = [Bundle(for: ProcessHostTests.self).bundleURL.deletingLastPathComponent().appendingPathComponent(name), binaryFolder.appendingPathComponent(name), binaryFolder.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent(name)]
        return candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0.path) })?.path ?? candidates[0].path
    }
    func closeControl() { if control >= 0 { close(control); control = -1 } }
    func waitForExit(timeout: TimeInterval) -> Bool {
        if reaped { return true }
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            var status: Int32 = 0
            if waitpid(pid, &status, WNOHANG) == pid {
                reaped = true
                exitCode = status & 0x7f == 0 ? ((status >> 8) & 0xff) : 128 + (status & 0x7f)
                return true
            }
            usleep(20_000)
        }
        return false
    }
    func childStillExists() -> Bool { kill(child.pid, 0) == 0 }
    func cleanup() {
        closeControl()
        if !waitForExit(timeout: 7) {
            let identity = vpg_process_identity(pid: child.pid, seconds: child.seconds, microseconds: child.microseconds)
            _ = vpg_signal_identity(identity, SIGKILL, 1)
            if !waitForExit(timeout: 1) { kill(pid, SIGKILL); _ = waitpid(pid, nil, 0); reaped = true }
        }
    }
}
