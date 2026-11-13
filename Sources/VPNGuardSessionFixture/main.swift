// Unit-test-only harmless owner. Never included in the app bundle.
import Foundation
import Darwin
import VPNGuardCore

let values = CommandLine.arguments
guard values.count >= 3 else { exit(2) }
let session = ManagedProcessSession()
let marker = URL(fileURLWithPath:values[1])
if values[2] == "--checking" {
    var record = GuardSessionRecord(ruleID:UUID(),name:"Checking fixture",phase:"checking",message:"No child exists")
    record.runnerIdentity = ProcessIdentity.capture(getpid())
    try FileManager.default.createDirectory(at:marker.deletingLastPathComponent(),withIntermediateDirectories:true)
    try JSONEncoder().encode(record).write(to:marker,options:.atomic)
    while true { usleep(100_000) }
}
let host = URL(fileURLWithPath:values[0]).deletingLastPathComponent().appendingPathComponent("VPNGuardProcessHost")
do {
    let status = try session.run(host:host,executable:values[2],arguments:Array(values.dropFirst(3)),environment:ProcessInfo.processInfo.environment) { identity in
        if let data = try? JSONEncoder().encode(identity) { try? data.write(to:marker,options:.atomic) }
    }
    exit(status)
} catch { exit(125) }
