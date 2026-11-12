import Foundation
import Darwin

public struct GuardSessionRecord: Identifiable, Codable, Sendable {
    public var id: UUID
    public var ruleID: UUID
    public var name: String
    public var processID: Int32
    public var startedAt: Date
    public var updatedAt: Date
    public var phase: String
    public var message: String
    public init(id: UUID = UUID(), ruleID: UUID, name: String, processID: Int32 = getpid(), phase: String, message: String) {
        self.id = id; self.ruleID = ruleID; self.name = name; self.processID = processID
        self.startedAt = Date(); self.updatedAt = Date(); self.phase = phase; self.message = message
    }
}
