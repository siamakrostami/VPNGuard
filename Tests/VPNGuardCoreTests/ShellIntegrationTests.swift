import XCTest
@testable import VPNGuardCore
final class ShellIntegrationTests: XCTestCase {
    func testManagedZshBlockCanBeRemovedWithoutChangingOriginalText() throws {
        for original in ["", "# personal config", "export EDITOR=vim\n"] {
            let hooked = try CommandIntegration.renderZsh(original: original, hookPath: "/Users/test/App Support/hooks.zsh")
            XCTAssertTrue(hooked.contains("VPNGuard command integration"))
            XCTAssertEqual(try CommandIntegration.removeZshBlock(hooked), original)
        }
    }
    func testMalformedMarkersAreNeverOverwritten() {
        XCTAssertThrowsError(try CommandIntegration.renderZsh(original: "# >>> VPNGuard command integration >>>\n", hookPath: "/x"))
    }
    func testWrapperForwardsArgumentsWithoutShellEvaluation() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let runner = dir.appendingPathComponent("runner with quote'")
        let output = dir.appendingPathComponent("argv")
        let stub = "#!/bin/sh\nprintf '%s\\0' \"$@\" > \(ShellArgument.quote(output.path))\n"
        try Data(stub.utf8).write(to: runner)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: runner.path)
        let item = try ProtectedItem(name: "Test", kind: .command, targetPath: "/usr/bin/true", commandName: "claude")
        let wrapper = dir.appendingPathComponent("claude")
        try Data(CommandIntegration.wrapper(item: item, runner: runner.path, config: "/tmp/a b.json").utf8).write(to: wrapper)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: wrapper.path)
        let args = ["a b", "$(touch /tmp/should-not-exist)", "single'quote", "line\nbreak", "--help"]
        let child = Process(); child.executableURL = wrapper; child.arguments = args
        try child.run(); child.waitUntilExit(); XCTAssertEqual(child.terminationStatus, 0)
        let received = try Data(contentsOf: output).split(separator: 0).map { String(decoding: $0, as: UTF8.self) }
        XCTAssertEqual(received, ["--rule",item.id.uuidString,"--config","/tmp/a b.json","--"] + args)
    }
}

extension ShellIntegrationTests {
    func testIntegrationWorksWithZshErrExitAndNoExistingAliases() throws {
        let home = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        let runner = home.appendingPathComponent("runner")
        try Data("#!/bin/sh\nprintf '%s' READY\n".utf8).write(to: runner)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: runner.path)
        let item = try ProtectedItem(name: "Probe", kind: .command, targetPath: "/usr/bin/true", commandName: "vpnguard_probe")
        let integration = CommandIntegration(home: home)
        try integration.synchronize(items: [item], runner: runner.path, config: home.appendingPathComponent("rules.json").path)
        let result = try CommandRunner.run("/bin/zsh", ["-f", "-c", "setopt ERR_EXIT; source \(ShellArgument.quote(integration.hook.path)); vpnguard_probe"])
        XCTAssertEqual(result.status, 0, result.stderr)
        XCTAssertEqual(result.stdout, "READY")
    }
}
