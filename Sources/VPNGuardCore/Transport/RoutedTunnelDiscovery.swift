import Foundation

/// Each address family is inspected independently. A selected path never falls
/// back to a physical interface or to the other address family during transport.
enum RoutedTunnelDiscovery {
    static func isTunnelInterface(_ name: String) -> Bool {
        tunnelInterface("interface: " + name) == name
    }

    static func tunnelInterface(_ text: String) -> String? {
        let names = text.split(separator: "\n").compactMap { line -> String? in
            let fields = line.split(whereSeparator: \.isWhitespace)
            return fields.count == 2 && fields[0] == "interface:" ? String(fields[1]) : nil
        }
        guard names.count == 1, let name = names.first else { return nil }
        for prefix in ["utun", "tun", "tap", "ppp", "ipsec"] {
            let suffix = name.dropFirst(prefix.count)
            if name.hasPrefix(prefix), !suffix.isEmpty, suffix.allSatisfy({ $0.isASCII && $0.isNumber }) { return name }
        }
        return nil
    }

    static func path(routes: [String], interfaceText: String, index: UInt32, ipv6: Bool) throws -> GenericVPNPath {
        guard routes.count >= 2, let name = routes.first.flatMap(tunnelInterface),
              routes.allSatisfy({ tunnelInterface($0) == name }), index > 0,
              interfaceText.split(separator: "\n").first?.hasPrefix(name + ":") == true,
              interfaceText.contains("<UP,"), interfaceText.contains("RUNNING") else {
            throw GuardError.invalid("No consistent active routed VPN tunnel is available for this address family.")
        }
        let addresses = interfaceText.split(separator: "\n").compactMap { line -> String? in
            let fields = line.split(whereSeparator: \.isWhitespace)
            guard fields.count >= 2, fields[0] == (ipv6 ? "inet6" : "inet") else { return nil }
            let value = String(fields[1])
            if ipv6 {
                guard IPv6.isUsableSource(value), !fields.contains("deprecated"), !fields.contains("tentative"), !fields.contains("duplicated") else { return nil }
            } else {
                guard IPv4.isValid(value), !value.hasPrefix("127."), !value.hasPrefix("169.254."), value != "0.0.0.0" else { return nil }
            }
            return value
        }
        // Multiple IPv6 privacy addresses are normal; bind one explicit source.
        // Multiple IPv4 sources remain ambiguous and retain the original rejection.
        let unique = Array(Set(addresses)).sorted()
        guard let source = unique.first, ipv6 || unique.count == 1 else {
            throw GuardError.invalid("The routed VPN has no usable unambiguous source address.")
        }
        return GenericVPNPath(interface: name, address: source, interfaceIndex: index)
    }

    static func select(ipv4: GenericVPNPath?, ipv6: GenericVPNPath?) throws -> GenericVPNPath {
        guard let path = ipv4 ?? ipv6 else { throw GuardError.invalid("A routed IPv4 or IPv6 VPN tunnel is required. Physical, split, and proxy-only routes need an explicit proxy connection.") }
        return path
    }
}
