import XCTest
import Darwin
@testable import VPNGuardCore

final class SandboxTests: XCTestCase {
    func testProfileAllowsOnlyOneNumericTCPProxyEndpoint() throws {
        let profile = try SandboxLaunch.profile(proxyPort: 12345)
        XCTAssertTrue(profile.contains("(deny network-outbound)"))
        XCTAssertTrue(profile.contains("(remote tcp \"localhost:12345\")"))
        XCTAssertTrue(profile.contains("(socket-domain AF_INET)"))
        XCTAssertFalse(profile.contains("127.0.0.1:*"))
        XCTAssertThrowsError(try SandboxLaunch.profile(proxyPort: 0))
    }
    func testProxyEnvironmentRemovesBypassesAndOverridesEveryCase() {
        let env = SandboxLaunch.environment(base: ["NO_PROXY": "*", "no_proxy": "localhost", "ALL_PROXY": "evil", "hTtPs_PrOxY": "evil", "PATH": "/bin"], proxyURL: "http://127.0.0.1:12345")
        XCTAssertNil(env["NO_PROXY"])
        XCTAssertNil(env["no_proxy"])
        XCTAssertNil(env["ALL_PROXY"])
        XCTAssertNil(env["hTtPs_PrOxY"])
        XCTAssertEqual(env["https_proxy"], "http://127.0.0.1:12345")
        XCTAssertEqual(env["PATH"], "/bin")
    }
    func testNumericSocketsAndDescendantsAreDeniedExceptExactProxy() throws {
        guard FileManager.default.isExecutableFile(atPath: "/usr/bin/sandbox-exec") else { throw XCTSkip("sandbox-exec unavailable") }
        let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: folder) }
        let source = folder.appendingPathComponent("probe.c")
        let probe = folder.appendingPathComponent("probe")
        try """
        #include <sys/socket.h>
        #include <sys/wait.h>
        #include <arpa/inet.h>
        #include <unistd.h>
        #include <errno.h>
        #include <stdlib.h>
        int main(int argc, char **argv) {
            if (atoi(argv[3])) { pid_t p = fork(); if (p < 0) return 91; if (p > 0) { int s; waitpid(p,&s,0); return WIFEXITED(s) ? WEXITSTATUS(s) : 92; } argv[3]="0"; execv(argv[0],argv); return 95; }
            int ipv6 = atoi(argv[4]);
            int fd = socket(ipv6 ? AF_INET6 : AF_INET, atoi(argv[6]) ? SOCK_DGRAM : SOCK_STREAM, 0);
            if (fd < 0) return errno == EPERM ? 77 : 93;
            int result;
            if (ipv6) { struct sockaddr_in6 a = {0}; a.sin6_family=AF_INET6; a.sin6_port=htons(atoi(argv[1])); inet_pton(AF_INET6,"::1",&a.sin6_addr); result=connect(fd,(struct sockaddr *)&a,sizeof(a)); }
            else { struct sockaddr_in a = {0}; a.sin_family=AF_INET; a.sin_port=htons(atoi(argv[1])); inet_pton(AF_INET,argv[5],&a.sin_addr); result=connect(fd,(struct sockaddr *)&a,sizeof(a)); }
            int code = result == 0 ? 0 : errno == EPERM ? 77 : 94; close(fd); return code;
        }
        """.write(to: source, atomically: true, encoding: .utf8)
        let compiler = Process(); compiler.executableURL = URL(fileURLWithPath: "/usr/bin/cc")
        compiler.arguments = [source.path, "-o", probe.path]; try compiler.run(); compiler.waitUntilExit()
        XCTAssertEqual(compiler.terminationStatus, 0)
        let listener = socket(AF_INET, SOCK_STREAM, 0); XCTAssertGreaterThanOrEqual(listener, 0)
        defer { close(listener) }
        var address = sockaddr_in(); address.sin_family = sa_family_t(AF_INET); address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(listener, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        XCTAssertEqual(bound, 0); XCTAssertEqual(listen(listener, 8), 0)
        var size = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(listener, $0, &size) } }
        let port = UInt16(bigEndian: address.sin_port)
        let profile = try SandboxLaunch.profile(proxyPort: port)
        func run(_ selected: UInt16, child: Bool = false, ipv6: Bool = false, host: String = "127.0.0.1", udp: Bool = false) throws -> Int32 {
            let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/sandbox-exec")
            process.arguments = ["-p", profile, probe.path, String(selected), "unused", child ? "1" : "0", ipv6 ? "1" : "0", host, udp ? "1" : "0"]
            try process.run(); process.waitUntilExit(); return process.terminationStatus
        }
        XCTAssertEqual(try run(port), 0, "Positive control: exact numeric proxy endpoint must connect")
        let other = port == 65535 ? port - 1 : port + 1
        XCTAssertEqual(try run(other), 77, "Different numeric loopback port must get EPERM")
        XCTAssertEqual(try run(port, host: "127.0.0.2"), 77, "Other loopback address must get EPERM")
        XCTAssertEqual(try run(443, host: "192.0.2.1"), 77, "Numeric external address must get EPERM without DNS")
        XCTAssertEqual(try run(other, child: true), 77, "Forked and execed descendant must inherit denial")
        XCTAssertEqual(try run(port, udp: true), 77, "UDP to the proxy port must not bypass TCP restriction")
        XCTAssertEqual(try run(port, ipv6: true), 77, "IPv6 must not bypass IPv4-only proxy")
    }
}
