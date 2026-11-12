import Foundation
import Darwin

public struct GenericVPNPath: Codable, Equatable, Sendable {
    public let interface: String
    public let address: String
    public let interfaceIndex: UInt32
    public init(interface: String, address: String, interfaceIndex: UInt32) {
        self.interface = interface; self.address = address; self.interfaceIndex = interfaceIndex
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
        return age >= 0 && age < 30 && abs(exit.checkedAt.timeIntervalSince(verifiedAt)) < 2 && exit.country != "IR" && Self.countryCodes.contains(exit.country) && IPv4.isPublic(exit.address)
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
        let routes = try ["1.1.1.1", "8.8.8.8", "104.16.123.96"].map { address in
            let result = try CommandRunner.run("/sbin/route", ["-n", "get", "-inet", address], timeout: 2)
            guard result.status == 0 else { throw GuardError.invalid("Could not inspect IPv4 routing.") }
            return result.stdout
        }
        guard let name = NetworkParsing.routeInterface(routes[0]), routes.allSatisfy({ NetworkParsing.routeInterface($0) == name }) else {
            throw GuardError.invalid("A consistent routed IPv4 VPN tunnel is required. Split routes and proxy-only VPNs are unsupported.")
        }
        let info = try CommandRunner.run("/sbin/ifconfig", [name], timeout: 2)
        guard info.status == 0 else { throw GuardError.invalid("The routed VPN interface is unavailable.") }
        return try TransportParsing.path(routes: routes, interfaceText: info.stdout, index: if_nametoindex(name))
    }
    public func verify() throws -> VPNVerification {
        let path = try inspect()
        let body = try Self.https(path: path, host: "www.cloudflare.com", address: "104.16.123.96", resource: "/cdn-cgi/trace")
        let now = Date()
        let exit = try ExitObservation.parse(body, at: now)
        guard try inspect() == path else { throw GuardError.invalid("The VPN changed during exit verification.") }
        return VPNVerification(path: path, exit: exit, verifiedAt: now)
    }
    static func https(path: GenericVPNPath, host: String, address: String, resource: String) throws -> String {
        try PinnedHTTPS.fetch(path: path, host: host, address: address, resource: resource)
    }

    func resolve(_ host: String, path: GenericVPNPath) throws -> [String] {
        if IPv4.isPublic(host) { return [host] }
        guard DNSHostname.isValid(host) else { throw GuardError.invalid("Only public IPv4 destinations and DNS hostnames are supported.") }
        let body = try Self.https(path: path, host: "cloudflare-dns.com", address: "1.1.1.1", resource: "/dns-query?name=\(host)&type=A&ct=application/dns-json")
        guard try inspect() == path else { throw GuardError.invalid("VPN topology changed while resolving the destination.") }
        return try TransportParsing.doh(Data(body.utf8))
    }
}

enum TransportParsing {
    static func path(routes: [String], interfaceText: String, index: UInt32) throws -> GenericVPNPath {
        guard routes.count >= 2, let name = NetworkParsing.routeInterface(routes[0]),
              routes.allSatisfy({ NetworkParsing.routeInterface($0) == name }), index > 0,
              let address = NetworkParsing.tunnelAddress(interfaceText), address != "0.0.0.0", !address.hasPrefix("127."),
              interfaceText.contains("<UP,"), interfaceText.contains("RUNNING") else {
            throw GuardError.invalid("No unique active routed IPv4 VPN source is available. IPv6-only tunnels are unsupported.")
        }
        return GenericVPNPath(interface: name, address: address, interfaceIndex: index)
    }
    static func doh(_ data: Data) throws -> [String] {
        struct Response: Decodable { let Status: Int; let Answer: [Answer]? }
        struct Answer: Decodable { let type: Int; let data: String }
        let result = try JSONDecoder().decode(Response.self, from: data)
        let addresses = result.Answer?.filter { $0.type == 1 }.map(\.data) ?? []
        guard result.Status == 0, !addresses.isEmpty, addresses.count <= 32, addresses.allSatisfy(IPv4.isPublic) else {
            throw GuardError.invalid("Tunnel DNS did not return exclusively public IPv4 addresses.")
        }
        return Array(Set(addresses)).sorted()
    }
}
