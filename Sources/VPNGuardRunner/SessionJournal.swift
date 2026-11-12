import Foundation
import Darwin
import VPNGuardCore

/// Per-launch status only: no proxy credentials, addresses, command arguments or payloads.
final class SessionJournal: @unchecked Sendable {
    private let lock = NSLock()
    private var record: GuardSessionRecord
    private let url: URL
    private var timer: DispatchSourceTimer?

    init(rule: ProtectedItem, storeURL: URL) throws {
        record = GuardSessionRecord(ruleID: rule.id, name: rule.name, phase: "checking", message: "Checking VPN route and non-Iran exit.")
        let folder = storeURL.deletingLastPathComponent().appendingPathComponent("Sessions", isDirectory: true)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        url = folder.appendingPathComponent(record.id.uuidString + ".json")
        try save()
        let timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
        timer.schedule(deadline: .now() + 3, repeating: 3)
        timer.setEventHandler { [weak self] in self?.heartbeat() }
        self.timer = timer; timer.resume()
    }
    deinit { timer?.cancel() }
    func update(phase: String, message: String) {
        lock.lock(); defer { lock.unlock() }
        record.phase = phase; record.message = message; record.updatedAt = Date()
        try? save()
        if phase == "ended" { timer?.cancel(); timer = nil }
    }
    private func heartbeat() {
        lock.lock(); defer { lock.unlock() }
        record.updatedAt = Date(); try? save()
    }
    private func save() throws {
        let data = try JSONEncoder().encode(record)
        // Set the temporary inode's permissions before atomic replacement, so the
        // public journal never has a transient world-readable creation window.
        let temp = url.deletingLastPathComponent().appendingPathComponent("." + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: temp) }
        FileManager.default.createFile(atPath: temp.path, contents: data, attributes: [.posixPermissions: 0o600])
        guard Darwin.rename(temp.path, url.path) == 0 else { throw GuardError.invalid("Cannot save protected-launch status.") }
    }
}
