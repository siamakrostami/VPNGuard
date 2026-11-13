import Foundation
import Darwin

public enum GuardError: LocalizedError, Sendable {
    case invalid(String)
    public var errorDescription: String? { if case .invalid(let message) = self { return message }; return nil }
}

public enum IPv4 {
    public static func isValid(_ value: String) -> Bool {
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 4 && parts.allSatisfy {
            !$0.isEmpty && $0.allSatisfy(\.isASCII) && $0.allSatisfy(\.isNumber)
                && ($0.count == 1 || !$0.hasPrefix("0")) && UInt8($0) != nil
        }
    }
    /// libc/libcurl recognize legacy abbreviated, octal, hex and integer literals.
    /// Never let those spellings enter the hostname path and bypass literal checks.
    public static func isLegacyAlias(_ value: String) -> Bool {
        var address = in_addr()
        return value.withCString { inet_aton($0, &address) } == 1 && !isValid(value)
    }
    public static func isPublic(_ value: String) -> Bool {
        guard isValid(value) else { return false }
        let p = value.split(separator: ".").compactMap { Int($0) }
        if [0, 10, 127].contains(p[0]) || p[0] >= 224 { return false }
        if p[0] == 169 && p[1] == 254 { return false }
        if p[0] == 172 && (16...31).contains(p[1]) { return false }
        if p[0] == 192 && (p[1] == 168 || p[1] == 0 || (p[1] == 0 && p[2] == 2)) { return false }
        if p[0] == 100 && (64...127).contains(p[1]) { return false }
        if p[0] == 198 && [18, 19, 51].contains(p[1]) { return false }
        if p[0] == 203 && p[1] == 0 && p[2] == 113 { return false }
        return true
    }
}

public enum IPv6 {
    private static func bytes(_ value: String) -> [UInt8]? {
        guard !value.contains("%"), !value.contains("."), !value.contains(where: { $0.isWhitespace }) else { return nil }
        var address = in6_addr()
        guard value.withCString({ inet_pton(AF_INET6, $0, &address) }) == 1 else { return nil }
        return withUnsafeBytes(of: address) { Array($0) }
    }
    public static func isValid(_ value: String) -> Bool { bytes(value) != nil }
    public static func isPublic(_ value: String) -> Bool {
        guard let b = bytes(value), b[0] & 0xe0 == 0x20 else { return false }
        // IETF special assignments, documentation, and transition mechanisms
        // cannot carry arbitrary public destinations through this transport.
        if b[0] == 0x20 && b[1] == 0x01 && b[2] < 2 { return false }
        if b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8 { return false }
        if b[0] == 0x20 && b[1] == 0x02 { return false }
        if b[0] == 0x3f && b[1] == 0xff && b[2] & 0xf0 == 0 { return false }
        return true
    }
    static func isUsableSource(_ value: String) -> Bool {
        guard let b = bytes(value) else { return false }
        return isPublic(value) || b[0] & 0xfe == 0xfc
    }
}

public struct ExitObservation: Codable, Equatable, Sendable {
    public let address: String
    public let country: String
    public let checkedAt: Date
    public static func parse(_ text: String, at time: Date) throws -> Self {
        var fields: [String: String] = [:]
        for line in text.split(separator: "\n") {
            let pair = line.split(separator: "=", maxSplits: 1).map(String.init)
            guard pair.count == 2, ["ip", "loc"].contains(pair[0]) else { continue }
            guard fields[pair[0]] == nil else { throw GuardError.invalid("Ambiguous exit-location response.") }
            fields[pair[0]] = pair[1]
        }
        guard let ip = fields["ip"], (IPv4.isPublic(ip) || IPv6.isPublic(ip)), let country = fields["loc"],
              Locale.Region.isoRegions.contains(where: { $0.identifier == country }), country != "IR" else {
            throw GuardError.invalid("The VPN exit is Iran or its location could not be verified.")
        }
        return Self(address: ip, country: country, checkedAt: time)
    }
}

