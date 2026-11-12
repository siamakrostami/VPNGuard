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

extension ShellIntegrationTests {
    func testUILaunchUsesChosenFolderAndLiteralRunnerArguments() throws {
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let chosen = root.appendingPathComponent("Project with spaces ' and $(literal)")
        try FileManager.default.createDirectory(at: chosen, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: root) }
        let runner = root.appendingPathComponent("runner ' tool")
        try Data("#!/bin/sh\npwd -P\nprintf '%s\\n' \"$@\"\n".utf8).write(to: runner)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: runner.path)
        let rule = UUID(), config = root.appendingPathComponent("a ' b.json").path
        let script = root.appendingPathComponent("launch.command")
        try Data(CommandLauncher.script(runner: runner.path, ruleID: rule, config: config, directory: chosen).utf8).write(to: script)
        let result = try CommandRunner.run("/bin/zsh", ["-f", script.path])
        XCTAssertEqual(result.status, 0, result.stderr)
        let lines = result.stdout.components(separatedBy: "\n")
        let actualFolder = try FileManager.default.attributesOfItem(atPath: lines[0])[.systemFileNumber] as? NSNumber
        let chosenFolder = try FileManager.default.attributesOfItem(atPath: chosen.path)[.systemFileNumber] as? NSNumber
        XCTAssertNotNil(actualFolder); XCTAssertEqual(actualFolder, chosenFolder)
        XCTAssertEqual(Array(lines.dropFirst()), ["--rule", rule.uuidString, "--config", config, "--", ""])
        try FileManager.default.removeItem(at: chosen)
        let gone = try CommandRunner.run("/bin/zsh", ["-f", script.path])
        XCTAssertNotEqual(gone.status, 0)
        XCTAssertFalse(gone.stdout.contains("--rule"), "A removed folder must never fall back to another directory")
    }
}
