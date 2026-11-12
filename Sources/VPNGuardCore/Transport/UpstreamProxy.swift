import Foundation
import Security
import Darwin
import CProxyTransport

public enum UpstreamProxyKind: String, Codable, CaseIterable, Sendable {
    case http, https, socks5, socks4a
}

public struct UpstreamProxyEndpoint: Codable, Equatable, Sendable {
    public var kind: UpstreamProxyKind
    public var host: String
    public var port: UInt16
    public var credentialID: String?

    public init(kind: UpstreamProxyKind, host: String, port: UInt16, credentialID: String? = nil) throws {
        guard Self.validHost(host), port > 0,
              credentialID.map({ !$0.isEmpty && !$0.contains("\0") }) ?? true else {
            throw UpstreamProxyError.invalidEndpoint
        }
        self.kind = kind; self.host = host; self.port = port; self.credentialID = credentialID
    }
    public var displayName: String { "\(kind.rawValue.uppercased()) \(authority)" }
    public var proxyURL: String { "\(kind == .socks5 ? "socks5h" : kind.rawValue)://\(authority)" }
    private var authority: String { "\(host.contains(":") ? "[\(host)]" : host):\(port)" }
    enum CodingKeys: String, CodingKey { case kind, host, port, credentialID }
    public init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        try self.init(kind: values.decode(UpstreamProxyKind.self, forKey: .kind), host: values.decode(String.self, forKey: .host), port: values.decode(UInt16.self, forKey: .port), credentialID: values.decodeIfPresent(String.self, forKey: .credentialID))
    }
    static func validHost(_ host: String) -> Bool {
        guard !host.isEmpty, host.utf8.count <= 253 else { return false }
        if host.contains(":") {
            var address = in6_addr()
            return host.withCString { inet_pton(AF_INET6, $0, &address) } == 1
        }
        let labels = (host.hasSuffix(".") ? String(host.dropLast()) : host).split(separator: ".", omittingEmptySubsequences: false)
        return labels.allSatisfy { label in
            !label.isEmpty && label.utf8.count <= 63 && label.first != "-" && label.last != "-" && label.utf8.allSatisfy { (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
        }
    }
    func validated() throws -> Self { try Self(kind: kind, host: host, port: port, credentialID: credentialID) }
}

public enum UpstreamProxyError: Error, LocalizedError {
    case invalidEndpoint, missingCredential, invalidCredential, keychain(OSStatus), transport(Int32)
    public var errorDescription: String? {
        switch self {
        case .invalidEndpoint: "Enter a proxy hostname or IP address and a port from 1 to 65535."
        case .missingCredential: "The proxy credential is missing from Keychain. Save the credential again."
        case .invalidCredential: "The proxy credential is invalid."
        case .keychain(let status): "Keychain could not access the proxy credential (\(status))."
        case .transport(let code): "The configured proxy connection failed (\(code))."
        }
    }
}

/// Stores only an opaque reference in settings. Security IPC runs on a dedicated queue.
/// Uses the login Keychain because the app and bundled runner support ad-hoc signing,
/// which cannot use entitlement-based Data Protection Keychain sharing. The login
/// Keychain controls locking and application access; macOS may request approval
/// when the separately signed runner first reads a credential. No ACL is broadened.
public enum ProxyCredentialStore {
    private static let queue = DispatchQueue(label: "VPNGuard.ProxyCredentials")
    private struct Credential: Codable { let username: String; let password: String }
    private static func query(_ id: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: "VPNGuard.UpstreamProxy",
         kSecAttrAccount as String: id,
         kSecUseDataProtectionKeychain as String: false]
    }
    public static func save(username: String, password: String, id: String? = nil) throws -> String {
        guard !username.contains("\0"), !password.contains("\0"), id.map({ !$0.isEmpty && !$0.contains("\0") }) ?? true else { throw UpstreamProxyError.invalidCredential }
        return try queue.sync {
            let id = id ?? UUID().uuidString
            let data = try JSONEncoder().encode(Credential(username: username, password: password))
            let base = query(id)
            var add = base
            add[kSecValueData as String] = data
            let status = SecItemAdd(add as CFDictionary, nil)
            switch status {
            case errSecSuccess: return id
            case errSecDuplicateItem:
                let updated = SecItemUpdate(base as CFDictionary, [kSecValueData as String: data] as CFDictionary)
                guard updated == errSecSuccess else { throw UpstreamProxyError.keychain(updated) }
                return id
            case errSecInteractionNotAllowed: throw UpstreamProxyError.keychain(status)
            default: throw UpstreamProxyError.keychain(status)
            }
        }
    }
    public static func load(id: String) throws -> (username: String, password: String)? {
        try queue.sync {
            var request = query(id)
            request[kSecMatchLimit as String] = kSecMatchLimitOne
            request[kSecReturnData as String] = true
            var item: CFTypeRef?
            let status = SecItemCopyMatching(request as CFDictionary, &item)
            switch status {
            case errSecSuccess:
                guard let data = item as? Data else { throw UpstreamProxyError.invalidCredential }
                let value = try JSONDecoder().decode(Credential.self, from: data)
                return (value.username, value.password)
            case errSecItemNotFound: return nil
            case errSecInteractionNotAllowed: throw UpstreamProxyError.keychain(status)
            default: throw UpstreamProxyError.keychain(status)
            }
        }
    }
    public static func delete(id: String) throws {
        try queue.sync {
            let status = SecItemDelete(query(id) as CFDictionary)
            switch status {
            case errSecSuccess, errSecItemNotFound: return
            case errSecInteractionNotAllowed: throw UpstreamProxyError.keychain(status)
            default: throw UpstreamProxyError.keychain(status)
            }
        }
    }
}

/// Confine all methods to the owning worker. Other threads may shutdown descriptor to revoke
/// access, but must never close it: libcurl owns the descriptor and any proxy TLS session.
public final class UpstreamProxyChannel: @unchecked Sendable {
    public let descriptor: Int32
    private var channel: OpaquePointer?
    public init(endpoint: UpstreamProxyEndpoint, host: String, port: UInt16) throws {
        let endpoint = try endpoint.validated()
        guard UpstreamProxyEndpoint.validHost(host), !IPv4.isLegacyAlias(host), port > 0 else { throw UpstreamProxyError.invalidEndpoint }
        let target = "http://\(host.contains(":") ? "[\(host)]" : host):\(port)/"
        var error: Int32 = 0
        let handle = try Self.withCredentials(endpoint) { user, password in
            vpg_connect(endpoint.proxyURL, target, user, password, &error)
        }
        guard let handle else { throw UpstreamProxyError.transport(error) }
        channel = handle; descriptor = vpg_descriptor(handle)
    }
    public func sendAll(_ data: Data) -> Bool {
        guard let channel else { return false }
        return data.withUnsafeBytes { vpg_send(channel, $0.baseAddress, $0.count) == 1 }
    }
    public func receive(_ buffer: UnsafeMutableRawPointer, capacity: Int) -> Int {
        guard let channel, capacity > 0, capacity <= Int(Int32.max) else { return -1 }
        return Int(vpg_receive(channel, buffer, capacity))
    }
    public func close() { if let channel { self.channel = nil; vpg_close(channel) } }
    deinit { close() }

    public static func fetchTrace(endpoint: UpstreamProxyEndpoint) throws -> String {
        let endpoint = try endpoint.validated()
        var output: UnsafeMutablePointer<CChar>?
        let code = try withCredentials(endpoint) { user, password in vpg_trace(endpoint.proxyURL, user, password, &output) }
        defer { vpg_free(output) }
        guard code == 0, let output else { throw UpstreamProxyError.transport(code) }
        return String(cString: output)
    }
    private static func withCredentials<T>(_ endpoint: UpstreamProxyEndpoint, body: (UnsafePointer<CChar>?, UnsafePointer<CChar>?) -> T) throws -> T {
        guard let id = endpoint.credentialID else { return body(nil, nil) }
        guard let credential = try ProxyCredentialStore.load(id: id) else { throw UpstreamProxyError.missingCredential }
        guard !credential.username.contains("\0"), !credential.password.contains("\0") else { throw UpstreamProxyError.invalidCredential }
        return credential.username.withCString { user in credential.password.withCString { password in body(user, password) } }
    }
}
