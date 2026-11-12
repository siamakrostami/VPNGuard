import Foundation

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
        guard let ip = fields["ip"], IPv4.isPublic(ip), let country = fields["loc"],
              Locale.isoRegionCodes.contains(country), country != "IR" else {
            throw GuardError.invalid("The VPN exit is Iran or its location could not be verified.")
        }
        return Self(address: ip, country: country, checkedAt: time)
    }
}

