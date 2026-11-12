import Foundation

/// A compatibility seatbelt boundary for the launched process and its descendants.
/// The proxy must remain in the unsandboxed parent process.
public enum SandboxLaunch {
    public static let executablePath = "/usr/bin/sandbox-exec"

    public static func profile(proxyPort: UInt16) throws -> String {
        guard proxyPort > 0 else { throw GuardError.invalid("The protected proxy must have a nonzero port.") }
        // Seatbelt rejects numeric hosts in remote filters. localhost + AF_INET is
        // its exact 127.0.0.1 representation here, not wildcard loopback access.
        // Native numeric probes verify 127.0.0.2 and ::1 are both denied.
        return """
        (version 1)
        (allow default)
        (deny network-outbound)
        (allow network-outbound (require-all (remote tcp "localhost:\(proxyPort)") (socket-domain AF_INET)))
        """
    }

    public static func environment(base: [String: String], proxyURL: String) -> [String: String] {
        var result = base.filter { key, _ in
            let key = key.lowercased()
            return !key.contains("proxy") && key != "curl_connect_to" && key != "curl_resolve"
        }
        for key in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] { result[key] = proxyURL }
        // ALL_PROXY is deliberately absent: SOCKS is unsupported by this CONNECT proxy.
        return result
    }

    public static func arguments(executable: String, forwarded: [String], proxyPort: UInt16) throws -> [String] {
        guard executable.hasPrefix("/"), !executable.contains("\0"), !forwarded.contains(where: { $0.contains("\0") }) else {
            throw GuardError.invalid("Protected launches require an absolute executable path and valid arguments.")
        }
        guard FileManager.default.isExecutableFile(atPath: executablePath) else {
            throw GuardError.invalid("This macOS installation has no sandbox-exec. A protected launch is unavailable.")
        }
        return ["-p", try profile(proxyPort: proxyPort), executable] + forwarded
    }
}
