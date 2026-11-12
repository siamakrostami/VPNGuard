import Foundation
import Darwin

/// Private, per-session requests. Never signal a PID read from an old journal.
public enum SessionConnectionReset {
    private static func location(_ id: UUID, _ storeURL: URL) -> URL {
        storeURL.deletingLastPathComponent().appendingPathComponent("Sessions", isDirectory: true).appendingPathComponent(id.uuidString + ".reset")
    }
    public static func request(sessionID: UUID, storeURL: URL) throws {
        let url = location(sessionID, storeURL), folder = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let temp = folder.appendingPathComponent("." + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: temp) }
        guard FileManager.default.createFile(atPath: temp.path, contents: Data(sessionID.uuidString.utf8), attributes: [.posixPermissions: 0o600]),
              Darwin.rename(temp.path, url.path) == 0 else { throw GuardError.invalid("Cannot request a connection reset.") }
    }
    public static func consume(sessionID: UUID, storeURL: URL) -> Bool {
        let url = location(sessionID, storeURL)
        guard let data = try? Data(contentsOf: url), data == Data(sessionID.uuidString.utf8) else { return false }
        return (try? FileManager.default.removeItem(at: url)) != nil
    }
}
