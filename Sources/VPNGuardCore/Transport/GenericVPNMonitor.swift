import Foundation
import Darwin

public struct GenericVPNPath: Codable, Equatable, Sendable {
    public let interface: String
    public let address: String
    public let interfaceIndex: UInt32
    public let proxy: UpstreamProxyEndpoint?
    public var isIPv6: Bool { address.contains(":") }
    public init(interface: String, address: String, interfaceIndex: UInt32, proxy: UpstreamProxyEndpoint? = nil) {
        self.interface = interface; self.address = address; self.interfaceIndex = interfaceIndex; self.proxy = proxy
    }
}
public struct VPNVerification: Codable, Sendable {
    public let path: GenericVPNPath
    public let exit: ExitObservation
    public let verifiedAt: Date
    public init(path: GenericVPNPath, exit: ExitObservation, verifiedAt: Date) {
        self.path = path; self.exit = exit; self.verifiedAt = verifiedAt
    }
    private static let countryCodes = Set(Locale.Region.isoRegions.map(\.identifier))
    var isFresh: Bool {
        let age = Date().timeIntervalSince(verifiedAt)
        return age >= 0 && age < 30 && abs(exit.checkedAt.timeIntervalSince(verifiedAt)) < 2 && exit.country != "IR" && Self.countryCodes.contains(exit.country) && (IPv4.isPublic(exit.address) || IPv6.isPublic(exit.address))
    }
}

protocol VPNPathMonitoring: Sendable {
    func inspect() throws -> GenericVPNPath
    func verify() throws -> VPNVerification
    func resolve(_ host: String, path: GenericVPNPath) throws -> [String]
}

public final class GenericVPNMonitor: VPNPathMonitoring, @unchecked Sendable {
    public init() {}
    public func inspect() throws -> GenericVPNPath {
        try ConnectionSelection.inspect(routed: { try self.inspectRouted() })
    }
    func inspectRouted() throws -> GenericVPNPath {
        func candidate(ipv6: Bool) -> GenericVPNPath? {
            do {
                let probes = ipv6 ? ["2606:4700:4700::1111", "2001:4860:4860::8888", "2606:4700:4700::1001"] : ["1.1.1.1", "8.8.8.8", "104.16.123.96"]
                let routes = try probes.map { address in
                    let result = try CommandRunner.run("/sbin/route", ["-n", "get", ipv6 ? "-inet6" : "-inet", address], timeout: 2)
                    guard result.status == 0 else { throw GuardError.invalid("Could not inspect routed VPN connectivity.") }
                    return result.stdout
                }
                guard let name = routes.first.flatMap(RoutedTunnelDiscovery.tunnelInterface) else { return nil }
                let info = try CommandRunner.run("/sbin/ifconfig", [name], timeout: 2)
                guard info.status == 0 else { return nil }
                return try RoutedTunnelDiscovery.path(routes: routes, interfaceText: info.stdout, index: if_nametoindex(name), ipv6: ipv6)
            } catch { return nil }
        }
        let ipv4 = candidate(ipv6: false), ipv6 = candidate(ipv6: true)
        return try RoutedTunnelDiscovery.select(ipv4: ipv4, ipv6: ipv6)
    }
    public func verify() throws -> VPNVerification {
        let path = try inspect()
        let body: String
        if let endpoint = path.proxy {
            body = try UpstreamProxyChannel.fetchTrace(endpoint: endpoint)
        } else {
            body = try Self.https(path: path, host: path.isIPv6 ? "cloudflare-dns.com" : "www.cloudflare.com", address: path.isIPv6 ? "2606:4700:4700::1111" : "104.16.123.96", resource: "/cdn-cgi/trace")
        }
        let now = Date()
        let exit = try ExitObservation.parse(body, at: now)
        guard try inspect() == path else { throw GuardError.invalid("The VPN changed during exit verification.") }
        return VPNVerification(path: path, exit: exit, verifiedAt: now)
    }
    static func https(path: GenericVPNPath, host: String, address: String, resource: String) throws -> String {
        try PinnedHTTPS.fetch(path: path, host: host, address: address, resource: resource)
    }

    func resolve(_ host: String, path: GenericVPNPath) throws -> [String] {
        guard path.proxy == nil else { throw GuardError.invalid("Proxy destinations must use the selected proxy transport.") }
        if path.isIPv6 ? IPv6.isPublic(host) : IPv4.isPublic(host) { return [host] }
        guard DNSHostname.isValid(host) else { throw GuardError.invalid("Only public destinations in the selected tunnel family and DNS hostnames are supported.") }
        let body = try Self.https(path: path, host: "cloudflare-dns.com", address: path.isIPv6 ? "2606:4700:4700::1111" : "1.1.1.1", resource: "/dns-query?name=\(host)&type=\(path.isIPv6 ? "AAAA" : "A")&ct=application/dns-json")
        guard try inspect() == path else { throw GuardError.invalid("VPN topology changed while resolving the destination.") }
        return try TransportParsing.doh(Data(body.utf8), ipv6: path.isIPv6)
    }
}

enum TransportParsing {
    static func path(routes: [String], interfaceText: String, index: UInt32) throws -> GenericVPNPath {
        try RoutedTunnelDiscovery.path(routes: routes, interfaceText: interfaceText, index: index, ipv6: false)
    }
    static func doh(_ data: Data, ipv6: Bool = false) throws -> [String] {
        struct Response: Decodable { let Status: Int; let Answer: [Answer]? }
        struct Answer: Decodable { let type: Int; let data: String }
        let result = try JSONDecoder().decode(Response.self, from: data)
        let addresses = result.Answer?.filter { $0.type == (ipv6 ? 28 : 1) }.map(\.data) ?? []
        guard result.Status == 0, !addresses.isEmpty, addresses.count <= 32, addresses.allSatisfy({ ipv6 ? IPv6.isPublic($0) : IPv4.isPublic($0) }) else {
            throw GuardError.invalid("Tunnel DNS did not return exclusively public addresses in the selected family.")
        }
        return Array(Set(addresses)).sorted()
    }
}
