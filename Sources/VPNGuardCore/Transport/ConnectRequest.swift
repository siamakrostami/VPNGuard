import Foundation

struct ConnectRequest {
    let host: String
    let port: UInt16
    let authorization: String?
    static func parse(_ data: Data) throws -> ConnectRequest {
        func bad() -> GuardError { .invalid("Invalid HTTP CONNECT request. Only public HTTPS CONNECT destinations are supported.") }
        guard data.count <= 16384, let text = String(data: data, encoding: .ascii), text.hasSuffix("\r\n\r\n") else { throw bad() }
        let lines = text.components(separatedBy: "\r\n")
        guard let first = lines.first else { throw bad() }
        let words = first.components(separatedBy: " ")
        guard words.count == 3, words[0] == "CONNECT", ["HTTP/1.1", "HTTP/1.0"].contains(words[2]) else { throw bad() }
        let host: String, portText: String
        if words[1].hasPrefix("["), let bracket = words[1].firstIndex(of: "]") {
            host = String(words[1][words[1].index(after: words[1].startIndex)..<bracket]).lowercased()
            let suffix = words[1][words[1].index(after: bracket)...]
            guard suffix.hasPrefix(":"), IPv6.isPublic(host) else { throw bad() }
            portText = String(suffix.dropFirst())
        } else {
            let authority = words[1].components(separatedBy: ":")
            guard authority.count == 2 else { throw bad() }
            host = authority[0].lowercased(); portText = authority[1]
            guard IPv4.isPublic(host) || (DNSHostname.isValid(host) && !IPv4.isValid(host) && !IPv4.isLegacyAlias(host)) else { throw bad() }
        }
        guard let port = UInt16(portText), port > 0, String(port) == portText else { throw bad() }
        var headers: [String: String] = [:]
        for line in lines.dropFirst().dropLast(2) {
            guard !line.isEmpty, !line.hasPrefix(" "), !line.hasPrefix("\t"), let colon = line.firstIndex(of: ":") else { throw bad() }
            let key = String(line[..<colon]).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty, key.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }),
                  !value.contains(where: { $0.asciiValue.map { $0 < 32 || $0 == 127 } ?? true }), headers[key] == nil,
                  !["content-length", "transfer-encoding", "upgrade"].contains(key) else { throw bad() }
            headers[key] = value
        }
        if let header = headers["host"], header.lowercased() != words[1].lowercased() { throw bad() }
        return ConnectRequest(host: host, port: port, authorization: headers["proxy-authorization"])
    }
}
