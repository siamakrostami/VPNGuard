import Foundation
import Darwin

public struct CommandOutput: Sendable {
    public let status: Int32
    public let stdout: String
    public let stderr: String
}

public enum CommandRunner {
    /// Fixed executable/arguments only. Output goes to private files to avoid pipe deadlock.
    public static func run(_ path: String, _ arguments: [String], timeout: TimeInterval = 5) throws -> CommandOutput {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("VPNGuard-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: folder) }
        let out = folder.appendingPathComponent("stdout"), err = folder.appendingPathComponent("stderr")
        FileManager.default.createFile(atPath: out.path, contents: nil, attributes: [.posixPermissions: 0o600])
        FileManager.default.createFile(atPath: err.path, contents: nil, attributes: [.posixPermissions: 0o600])
        let outHandle = try FileHandle(forWritingTo: out), errHandle = try FileHandle(forWritingTo: err)
        defer { try? outHandle.close(); try? errHandle.close() }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C", "HOME": "/var/root"]
        process.standardOutput = outHandle; process.standardError = errHandle
        process.standardInput = FileHandle.nullDevice
        try process.run()
        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.025) }
        if process.isRunning {
            process.terminate()
            Thread.sleep(forTimeInterval: 0.1)
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            process.waitUntilExit()
            throw GuardError.invalid("System command timed out: \(URL(fileURLWithPath: path).lastPathComponent).")
        }
        process.waitUntilExit()
        func read(_ url: URL) -> String {
            guard let handle = try? FileHandle(forReadingFrom: url) else { return "" }
            defer { try? handle.close() }
            return String(data: (try? handle.read(upToCount: 2_000_000)) ?? Data(), encoding: .utf8) ?? ""
        }
        return CommandOutput(status: process.terminationStatus, stdout: read(out), stderr: read(err))
    }
}

public enum NetworkParsing {
    public static func routeInterface(_ text: String) -> String? {
        let values = text.split(separator: "\n").compactMap { line -> String? in
            let p = line.split(whereSeparator: { $0.isWhitespace })
            return p.count == 2 && p[0] == "interface:" ? String(p[1]) : nil
        }
        guard values.count == 1, let name = values.first, name.hasPrefix("utun"),
              !name.dropFirst(4).isEmpty, name.dropFirst(4).allSatisfy({ $0.isASCII && $0.isNumber }) else { return nil }
        return name
    }
    public static func tunnelAddress(_ text: String) -> String? {
        let addresses = text.split(separator: "\n").compactMap { line -> String? in
            let p = line.split(whereSeparator: { $0.isWhitespace })
            return p.count >= 2 && p[0] == "inet" && IPv4.isValid(String(p[1])) ? String(p[1]) : nil
        }
        return addresses.count == 1 ? addresses[0] : nil
    }
}

public enum ShellArgument {
    public static func quote(_ value: String) -> String { "'" + value.replacingOccurrences(of: "'", with: "'\\''") + "'" }
}

