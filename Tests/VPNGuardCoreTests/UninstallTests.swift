import XCTest
import Darwin
@testable import VPNGuardCore

final class UninstallTests: XCTestCase {
    private func fixture(_ body: (URL) throws -> Void) throws {
        let physical = try XCTUnwrap(realpath(FileManager.default.temporaryDirectory.path, nil))
        defer { free(physical) }
        let home = URL(fileURLWithPath: String(cString: physical)).appendingPathComponent("VPNGuard-Uninstall-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        try body(home)
    }
    private func put(_ value: Data, _ relative: String, home: URL) throws {
        let url = home.appendingPathComponent(relative)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try value.write(to: url)
    }
    private func text(_ relative: String, home: URL) throws -> String { try String(contentsOf: home.appendingPathComponent(relative), encoding: .utf8) }
    private func present(_ relative: String, home: URL) -> Bool { FileManager.default.fileExists(atPath: home.appendingPathComponent(relative).path) }
    private let support = "Library/Application Support/VPNGuard/"

    func testRestoresExactOriginalBackupAndRemovesOnlyOwnedFiles() throws {
        try fixture { home in
            let original = "# original without final newline"
            let integration = CommandIntegration(home: home)
            try put(Data(CommandIntegration.renderZsh(original: original, hookPath: integration.hook.path).utf8), ".zshrc", home: home)
            try put(Data(original.utf8), support + "Backups/zshrc-" + UUID().uuidString, home: home)
            try put(JSONEncoder().encode(GuardPreferences()), support + "rules.json", home: home)
            try put(JSONEncoder().encode(ConnectionSettings()), support + "connection.json", home: home)
            try put(Data("# Managed by VPNGuard. Reload Terminal after changing command rules.\ntrue\n".utf8), support + "commands.zsh", home: home)
            try put(Data("[]".utf8), support + "managed-commands.json", home: home)
            try put(PropertyListSerialization.data(fromPropertyList: ["launchAtLogin": false], format: .xml, options: 0), "Library/Preferences/com.siamak.VPNGuard.plist", home: home)
            try put(Data("decoy".utf8), "Library/Application Support/OtherVPN/config", home: home)
            try put(Data("decoy".utf8), "Library/Preferences/com.other.VPN.plist", home: home)
            let report = try VPNGuardUninstaller.execute(home: home)
            XCTAssertEqual(try text(".zshrc", home: home), original)
            XCTAssertFalse(present(support, home: home))
            XCTAssertFalse(present("Library/Preferences/com.siamak.VPNGuard.plist", home: home))
            XCTAssertEqual(try text("Library/Application Support/OtherVPN/config", home: home), "decoy")
            XCTAssertTrue(present("Library/Preferences/com.other.VPN.plist", home: home))
            XCTAssertFalse(report.removed.isEmpty)
            XCTAssertEqual(report.manualCommands, ["sudo rm -rf -- /private/var/db/com.siamak.VPNGuard", "sudo rm -f -- /private/var/log/VPNGuard.log"])
            XCTAssertTrue(try VPNGuardUninstaller.execute(home: home).removed.isEmpty)
        }
    }
    func testPreservesUserEditsAndUnknownItems() throws {
        try fixture { home in
            let original = "export ORIGINAL=1\n"
            let integration = CommandIntegration(home: home)
            let installed = try CommandIntegration.renderZsh(original: original, hookPath: integration.hook.path)
            try put(Data((installed + "export NEW_USER_EDIT=1\n").utf8), ".zshrc", home: home)
            try put(Data(original.utf8), support + "Backups/zshrc-" + UUID().uuidString, home: home)
            try put(Data("keep".utf8), support + "user-notes.txt", home: home)
            try put(Data("unowned script".utf8), support + "bin/custom", home: home)
            let report = try VPNGuardUninstaller.execute(home: home)
            XCTAssertEqual(try text(".zshrc", home: home), original + "export NEW_USER_EDIT=1\n")
            XCTAssertEqual(try text(support + "user-notes.txt", home: home), "keep")
            XCTAssertEqual(try text(support + "bin/custom", home: home), "unowned script")
            XCTAssertTrue(report.left.contains { $0.contains("user-notes.txt") })
        }
    }
    func testIncompleteBlockRefusesAllDeletion() throws {
        try fixture { home in
            let malformed = "# original\n" + CommandIntegration.begin + "\n"
            try put(Data(malformed.utf8), ".zshrc", home: home)
            try put(JSONEncoder().encode(GuardPreferences()), support + "rules.json", home: home)
            XCTAssertThrowsError(try VPNGuardUninstaller.execute(home: home))
            XCTAssertEqual(try text(".zshrc", home: home), malformed)
            XCTAssertTrue(present(support + "rules.json", home: home))
        }
    }
    func testSymlinkedShellFileIsRefusedWithoutTouchingTarget() throws {
        try fixture { home in
            try put(Data("target".utf8), "shell-target", home: home)
            try FileManager.default.createSymbolicLink(at: home.appendingPathComponent(".zshrc"), withDestinationURL: home.appendingPathComponent("shell-target"))
            XCTAssertThrowsError(try VPNGuardUninstaller.execute(home: home))
            XCTAssertEqual(try text("shell-target", home: home), "target")
        }
    }
    func testSymlinkedSupportAncestorIsRefused() throws {
        try fixture { home in
            try put(Data("target".utf8), "elsewhere/VPNGuard/rules.json", home: home)
            try FileManager.default.createDirectory(at: home.appendingPathComponent("Library"), withIntermediateDirectories: true)
            try FileManager.default.createSymbolicLink(at: home.appendingPathComponent("Library/Application Support"), withDestinationURL: home.appendingPathComponent("elsewhere"))
            XCTAssertThrowsError(try VPNGuardUninstaller.execute(home: home))
            XCTAssertEqual(try text("elsewhere/VPNGuard/rules.json", home: home), "target")
        }
    }
    func testSymlinkAndHardlinkInsideOwnedDirectoryAreLeftUntouched() throws {
        try fixture { home in
            try put(Data("target".utf8), "outside", home: home)
            try FileManager.default.createDirectory(at: home.appendingPathComponent(support + "bin"), withIntermediateDirectories: true)
            try FileManager.default.createSymbolicLink(at: home.appendingPathComponent(support + "rules.json"), withDestinationURL: home.appendingPathComponent("outside"))
            try FileManager.default.linkItem(at: home.appendingPathComponent("outside"), to: home.appendingPathComponent(support + "connection.json"))
            let report = try VPNGuardUninstaller.execute(home: home)
            XCTAssertEqual(try text("outside", home: home), "target")
            XCTAssertTrue(present(support + "rules.json", home: home))
            XCTAssertTrue(present(support + "connection.json", home: home))
            XCTAssertGreaterThanOrEqual(report.left.count, 2)
        }
    }
    func testManifestRequiredBeforeRemovingCommandWrappers() throws {
        try fixture { home in
            let item = try ProtectedItem(name: "Test", kind: .command, targetPath: "/usr/bin/true", commandName: "guarded")
            let wrapper = CommandIntegration.wrapper(item: item, runner: "/Applications/VPNGuard.app/Contents/MacOS/VPNGuardRun", config: home.appendingPathComponent(support + "rules.json").path)
            try put(Data(wrapper.utf8), support + "bin/guarded", home: home)
            try put(Data(wrapper.utf8), support + "bin/not-in-manifest", home: home)
            try put(JSONEncoder().encode(["guarded", "../outside"]), support + "managed-commands.json", home: home)
            _ = try VPNGuardUninstaller.execute(home: home)
            XCTAssertFalse(present(support + "bin/guarded", home: home))
            XCTAssertTrue(present(support + "bin/not-in-manifest", home: home))
        }
    }
    func testNormalInstallIncludingLaunchersAndSessionsIsFullyRemoved() throws {
        try fixture { home in
            let item = try ProtectedItem(name: "Test", kind: .command, targetPath: "/usr/bin/true", commandName: "guarded")
            var settings = GuardPreferences(); settings.items = [item]
            let config = home.appendingPathComponent(support + "rules.json").path
            let runner = "/Applications/VPNGuard.app/Contents/MacOS/VPNGuardRun"
            let launcher = CommandLauncher.script(runner: runner, ruleID: item.id, config: config, directory: URL(fileURLWithPath: "/Users/test/It's a project"))
            try put(Data(launcher.utf8), support + "Launchers/" + UUID().uuidString + ".command", home: home)
            let journal = GuardSessionRecord(ruleID: item.id, name: item.name, phase: "ended", message: "Done")
            try put(JSONEncoder().encode(journal), support + "Sessions/" + journal.id.uuidString + ".json", home: home)
            try put(Data(journal.id.uuidString.utf8), support + "Sessions/" + journal.id.uuidString + ".reset", home: home)
            try put(Data("app output".utf8), support + "Sessions/launch-" + item.id.uuidString + ".log", home: home)
            try put(JSONEncoder().encode(settings), support + "rules.json", home: home)
            try put(JSONEncoder().encode(["guarded"]), support + "managed-commands.json", home: home)
            try put(Data(CommandIntegration.wrapper(item: item, runner: runner, config: config).utf8), support + "bin/guarded", home: home)
            let report = try VPNGuardUninstaller.execute(home: home)
            XCTAssertFalse(present(support, home: home))
            XCTAssertTrue(report.left.isEmpty)
        }
    }
    func testEditedLauncherAndInvalidPreferencesArePreserved() throws {
        try fixture { home in
            let item = try ProtectedItem(name: "Test", kind: .command, targetPath: "/usr/bin/true", commandName: "guarded")
            var settings = GuardPreferences(); settings.items = [item]
            let launcher = CommandLauncher.script(runner: "/Applications/VPNGuard.app/Contents/MacOS/VPNGuardRun", ruleID: item.id, config: home.appendingPathComponent(support + "rules.json").path, directory: home) + "# user edit\n"
            let file = support + "Launchers/" + UUID().uuidString + ".command"
            try put(Data(launcher.utf8), file, home: home)
            try put(JSONEncoder().encode(settings), support + "rules.json", home: home)
            try put(Data("unknown".utf8), "Library/Preferences/com.siamak.VPNGuard.plist", home: home)
            let report = try VPNGuardUninstaller.execute(home: home)
            XCTAssertEqual(try text(file, home: home), launcher)
            XCTAssertEqual(try text("Library/Preferences/com.siamak.VPNGuard.plist", home: home), "unknown")
            XCTAssertTrue(report.left.contains { $0.contains(".command") })
        }
    }
    func testGroupWritableHomeIsRefused() throws {
        try fixture { home in
            try FileManager.default.setAttributes([.posixPermissions: 0o770], ofItemAtPath: home.path)
            defer { try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: home.path) }
            XCTAssertThrowsError(try VPNGuardUninstaller.execute(home: home))
        }
    }
    private func runScript(home: URL, arguments: [String]) throws -> (Int32, String) {
        let source = URL(fileURLWithPath: #filePath).resolvingSymlinksInPath()
        let script = source.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("scripts/uninstall.sh")
        let process = Process(); process.executableURL = URL(fileURLWithPath: "/bin/bash")
        process.arguments = [script.path] + arguments
        var environment = ProcessInfo.processInfo.environment; environment["HOME"] = home.path
        process.environment = environment
        let output = Pipe(); process.standardOutput = output; process.standardError = output
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        return (process.terminationStatus, String(decoding: data, as: UTF8.self))
    }
    private func fakeBundle(home: URL, supported: Bool, status: Int = 0) throws -> URL {
        let info: [String: Any] = ["CFBundleIdentifier": "com.siamak.VPNGuard", "VPNGuardUninstallCLI": supported]
        try put(PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0), "Fixture.app/Contents/Info.plist", home: home)
        // Harmless stand-in: prints arguments and exits. Never starts app or uninstall code.
        try put(Data(("#!/bin/sh\nprintf '%s\\n' \"$@\"\nexit " + String(status) + "\n").utf8), "Fixture.app/Contents/MacOS/VPNGuard", home: home)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: home.appendingPathComponent("Fixture.app/Contents/MacOS/VPNGuard").path)
        return home.appendingPathComponent("Fixture.app")
    }
    func testScriptDefaultsToPreviewAndExecuteForwardsOnlyUninstall() throws {
        try fixture { home in
            let app = try fakeBundle(home: home, supported: true)
            let preview = try runScript(home: home, arguments: ["--app", app.path])
            XCTAssertEqual(preview.0, 0); XCTAssertEqual(preview.1, "--uninstall\n--preview\n")
            let execute = try runScript(home: home, arguments: ["--execute", "--app", app.path])
            XCTAssertEqual(execute.0, 0); XCTAssertEqual(execute.1, "--uninstall\n")
        }
    }
    func testScriptRefusesOldAppAndPropagatesUnregistrationFailure() throws {
        try fixture { home in
            let app = try fakeBundle(home: home, supported: false)
            let unsupported = try runScript(home: home, arguments: ["--execute", "--app", app.path])
            XCTAssertNotEqual(unsupported.0, 0); XCTAssertFalse(unsupported.1.contains("--uninstall"))
            _ = try fakeBundle(home: home, supported: true, status: 17)
            let failed = try runScript(home: home, arguments: ["--execute", "--app", app.path])
            XCTAssertEqual(failed.0, 17)
        }
    }
    func testScriptRefusesSymlinkedAppAncestor() throws {
        try fixture { home in
            _ = try fakeBundle(home: home, supported: true)
            try FileManager.default.createSymbolicLink(at: home.appendingPathComponent("link"), withDestinationURL: home)
            let result = try runScript(home: home, arguments: ["--execute", "--app", home.appendingPathComponent("link/Fixture.app").path])
            XCTAssertNotEqual(result.0, 0)
            XCTAssertFalse(result.1.contains("--uninstall"))
        }
    }
    func testPreviewDoesNotWriteAnyFiles() throws {
        try fixture { home in
            let installed = try CommandIntegration.renderZsh(original: "original", hookPath: CommandIntegration(home: home).hook.path)
            try put(Data(installed.utf8), ".zshrc", home: home)
            try put(JSONEncoder().encode(GuardPreferences()), support + "rules.json", home: home)
            let report = try UninstallPlan(home: home).preview()
            XCTAssertFalse(report.removed.isEmpty)
            XCTAssertEqual(try text(".zshrc", home: home), installed)
            XCTAssertTrue(present(support + "rules.json", home: home))
        }
    }
}
