import Foundation
import Darwin
import SystemConfiguration

public enum ConnectionMode: String, Codable, CaseIterable, Sendable {
    case automatic, routedTunnel, systemProxy, manualProxy
    public var title: String {
        switch self {
        case .automatic: "Automatic"
        case .routedTunnel: "Routed VPN or tunnel"
        case .systemProxy: "System proxy"
        case .manualProxy: "Manual proxy"
        }
    }
}
public struct ConnectionSettings: Codable, Equatable, Sendable {
    public var mode: ConnectionMode = .automatic
    public var manualProxy: UpstreamProxyEndpoint?
    public init() {}
}
public struct ConnectionSettingsStore: Sendable {
    public let url: URL
    public init(url: URL? = nil) {
        self.url = url ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/VPNGuard/connection.json")
    }
    public func load() throws -> ConnectionSettings {
        guard FileManager.default.fileExists(atPath: url.path) else { return ConnectionSettings() }
        let data = try Data(contentsOf: url)
        guard data.count < 16_384 else { throw GuardError.invalid("Connection settings are unexpectedly large.") }
        return try JSONDecoder().decode(ConnectionSettings.self, from: data)
    }
    public func save(_ value: ConnectionSettings) throws {
        if value.mode == .manualProxy && value.manualProxy == nil { throw GuardError.invalid("Enter a proxy endpoint before saving manual mode.") }
        let folder = url.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let temp = folder.appendingPathComponent("." + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: temp) }
        guard FileManager.default.createFile(atPath: temp.path, contents: try JSONEncoder().encode(value), attributes: [.posixPermissions: 0o600]),
              rename(temp.path, url.path) == 0 else { throw GuardError.invalid("Cannot save connection settings.") }
    }
}
public enum SystemProxyDiscovery {
    public static func discover() throws -> [UpstreamProxyEndpoint] {
        guard let values = SCDynamicStoreCopyProxies(nil) as? [String: Any] else { return [] }
        return try parse(values)
    }
    public static func parse(_ values: [String: Any]) throws -> [UpstreamProxyEndpoint] {
        var result: [UpstreamProxyEndpoint] = []
        for (prefix, kind) in [("HTTPS", UpstreamProxyKind.http), ("HTTP", .http), ("SOCKS", .socks5)] {
            guard (values[prefix + "Enable"] as? NSNumber)?.boolValue == true else { continue }
            guard let host = values[prefix + "Proxy"] as? String,
                  let number = values[prefix + "Port"] as? NSNumber,
                  number.doubleValue == Double(number.intValue), let port = UInt16(exactly: number.intValue), port > 0 else {
                throw GuardError.invalid("The enabled system proxy has an invalid host or port. Choose Manual proxy to enter its endpoint.")
            }
            let endpoint = try UpstreamProxyEndpoint(kind: kind, host: host, port: port)
            if !result.contains(endpoint) { result.append(endpoint) }
        }
        if result.isEmpty && (["ProxyAutoConfigEnable", "ProxyAutoDiscoveryEnable"].contains { (values[$0] as? NSNumber)?.boolValue == true }) {
            throw GuardError.invalid("Only PAC/WPAD proxy discovery is configured. Choose Manual proxy and enter the client’s HTTP or SOCKS listening endpoint.")
        }
        return result
    }
}
public enum ConnectionSelection {
    public static func inspect(routed: () throws -> GenericVPNPath) throws -> GenericVPNPath {
        let settings = try ConnectionSettingsStore().load()
        let system = settings.mode == .automatic || settings.mode == .systemProxy ? try SystemProxyDiscovery.discover() : []
        return try choose(settings: settings, system: system, routed: routed)
    }
    public static func choose(settings: ConnectionSettings, system: [UpstreamProxyEndpoint], routed: () throws -> GenericVPNPath) throws -> GenericVPNPath {
        let endpoint: UpstreamProxyEndpoint?
        switch settings.mode {
        case .routedTunnel: return try routed()
        case .automatic:
            guard let first = system.first else { return try routed() }
            endpoint = first
        case .systemProxy:
            guard let first = system.first else { throw GuardError.invalid("No explicit system HTTP or SOCKS proxy is enabled. Enable your client’s system proxy, or choose Manual proxy with its listening host and port.") }
            endpoint = first
        case .manualProxy:
            guard let manual = settings.manualProxy else { throw GuardError.invalid("No manual proxy is configured. Enter its protocol, host and port in Settings.") }
            endpoint = manual
        }
        return GenericVPNPath(interface: "proxy", address: "", interfaceIndex: 0, proxy: endpoint)
    }
}
