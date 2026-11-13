import Foundation
import Darwin

public struct CommandOutput: Sendable {
    public let status: Int32
    public let stdout: String
    public let stderr: String
}

public enum CommandRunner {
    /// Fixed executable/arguments only. Output goes to private files to avoid pipe deadlock.
    public static func run(_ path: String, _ arguments: [String], timeout: TimeInterval = 5, supervisor:URL? = nil) throws -> CommandOutput {
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent("VPNGuard-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        defer { try? FileManager.default.removeItem(at: folder) }
        let out = folder.appendingPathComponent("stdout"), err = folder.appendingPathComponent("stderr")
        FileManager.default.createFile(atPath: out.path, contents: nil, attributes: [.posixPermissions: 0o600])
        FileManager.default.createFile(atPath: err.path, contents: nil, attributes: [.posixPermissions: 0o600])
        let outHandle = try FileHandle(forWritingTo: out), errHandle = try FileHandle(forWritingTo: err)
        defer { try? outHandle.close(); try? errHandle.close() }
        let adjacent = Bundle.main.executableURL?.deletingLastPathComponent().appendingPathComponent("VPNGuardProcessHost")
        let selectedHost = supervisor ?? adjacent.flatMap { FileManager.default.isExecutableFile(atPath:$0.path) ? $0 : nil }
        let exitStatus:Int32
        if let selectedHost {
            let inputDescriptor = open("/dev/null",O_RDONLY | O_CLOEXEC)
            guard inputDescriptor >= 0 else { throw GuardError.invalid("Cannot open null input for a system command.") }
            defer { close(inputDescriptor) }
            let session = ManagedProcessSession(), timedOut = CommandDeadline()
            let timer = DispatchSource.makeTimerSource(queue:DispatchQueue(label:"VPNGuard.command.deadline"))
            timer.schedule(deadline:.now() + max(0,timeout))
            timer.setEventHandler { timedOut.expire(); session.requestStop() }
            timer.resume();defer{timer.cancel();session.requestStop()}
            exitStatus = try session.run(host:selectedHost,executable:path,arguments:arguments,
                environment:["PATH":"/usr/bin:/bin:/usr/sbin:/sbin","LC_ALL":"C","HOME":"/var/root"],
                standardIO:[STDIN_FILENO:inputDescriptor,STDOUT_FILENO:outHandle.fileDescriptor,STDERR_FILENO:errHandle.fileDescriptor],
                handleSignals:false,onStarted:{_ in})
            if timedOut.hasExpired { throw GuardError.invalid("System command timed out: \(URL(fileURLWithPath:path).lastPathComponent).") }
        } else {
            // Test/standalone callers without a packaged supervisor retain the
            // bounded simple-process path. Protected runner startup requires it.
            let process = Process()
            process.executableURL = URL(fileURLWithPath:path);process.arguments = arguments
            process.environment = ["PATH":"/usr/bin:/bin:/usr/sbin:/sbin","LC_ALL":"C","HOME":"/var/root"]
            process.standardOutput = outHandle;process.standardError = errHandle;process.standardInput = FileHandle.nullDevice
            try process.run()
            let deadline = Date().addingTimeInterval(timeout)
            while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval:0.025) }
            if process.isRunning {
                _ = kill(process.processIdentifier,SIGCONT)
                process.terminate()
                let grace = Date().addingTimeInterval(5)
                while process.isRunning && Date() < grace { Thread.sleep(forTimeInterval:0.025) }
                if process.isRunning { kill(process.processIdentifier,SIGKILL) }
                process.waitUntilExit()
                throw GuardError.invalid("System command timed out: \(URL(fileURLWithPath:path).lastPathComponent).")
            }
            process.waitUntilExit();exitStatus = process.terminationStatus
        }
        func read(_ url: URL) -> String {
            guard let handle = try? FileHandle(forReadingFrom: url) else { return "" }
            defer { try? handle.close() }
            return String(data: (try? handle.read(upToCount: 2_000_000)) ?? Data(), encoding: .utf8) ?? ""
        }
        return CommandOutput(status: exitStatus, stdout: read(out), stderr: read(err))
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


private final class CommandDeadline: @unchecked Sendable {
    private let lock = NSLock();private var expired = false
    func expire() { lock.lock();expired = true;lock.unlock() }
    var hasExpired:Bool { lock.lock();defer{lock.unlock()};return expired }
}
