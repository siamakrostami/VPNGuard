import Foundation

struct ConnectRequest {
    let host: String
    let port: UInt16
    let authorization: String?
    static func parse(_ data: Data) throws -> ConnectRequest {
        func bad() -> GuardError { .invalid("Invalid HTTP CONNECT request. Only public IPv4 HTTPS CONNECT is supported.") }
        guard data.count <= 16384, let text = String(data: data, encoding: .ascii), text.hasSuffix("\r\n\r\n") else { throw bad() }
        let lines = text.components(separatedBy: "\r\n")
        guard let first = lines.first else { throw bad() }
        let words = first.components(separatedBy: " ")
        guard words.count == 3, words[0] == "CONNECT", ["HTTP/1.1", "HTTP/1.0"].contains(words[2]) else { throw bad() }
        let authority = words[1].components(separatedBy: ":")
        guard authority.count == 2, let port = UInt16(authority[1]), port > 0,
              String(port) == authority[1] else { throw bad() }
        let host = authority[0].lowercased()
        guard IPv4.isPublic(host) || (DNSHostname.isValid(host) && !IPv4.isValid(host)) else { throw bad() }
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
