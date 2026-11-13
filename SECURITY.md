# Security policy

VPNGuard is experimental security-sensitive software. It has not received a comprehensive independent audit and should not be represented as a universal leak-proof firewall.

## Supported scope

Only the current source beta is maintained. Guarded launches restrict direct sockets and inherited subprocesses using macOS process isolation and a private tunnel-bound HTTP CONNECT proxy. Normal Finder/Dock launches, direct absolute executable invocation, other shells and independently running service handoffs are not universally covered.

Supported guarded traffic is HTTPS/secure WebSockets through the private CONNECT endpoint. Upstream transport is a verified routed IPv4/IPv6 tunnel, HTTP/HTTPS CONNECT proxy, SOCKS5 remote-DNS proxy, or SOCKS4a proxy. Direct child TCP, UDP/QUIC, plain HTTP, unverified routes, PAC/WPAD-only discovery and unsupported authentication schemes are refused.

## Fail-closed expectations

- A missing rule, disabled rule, disabled launch policy, missing isolation tool or failed VPN/exit check must refuse a guarded launch.
- Routed proxy/diagnostic sockets must remain bound to the verified interface and source address in one address family. Explicit upstream proxy connections must negotiate through that endpoint, with no environment bypass or direct fallback. HTTPS proxy TLS and diagnostic target TLS must validate.
- Topology loss, failed verification or expired freshness must close payload connections and deny new ones.
- Recovery/reset must keep the same private endpoint reserved, reject old connection generations and require fresh non-Iran verification before allowing new payload connections.
- Errors must never silently retry through the physical network or launch without the isolation profile.

These expectations do not cover an administrator changing the OS, a malicious local account, service-mediated escape from a desktop app, or incorrect external IP geolocation. A periodic country check is not per-request geographic attestation. An upstream proxy/router can route destinations differently or change its own policy; VPNGuard cannot attest every remote exit. It does not test or manipulate timezone, device identity, account eligibility or provider policy. Proxy destination hostnames resolve remotely. Their resolved-address ACL is the upstream proxy’s responsibility; local CONNECT parsing rejects private numeric literals and alternate numeric IPv4 spellings but cannot attest remote DNS mappings. Proxy credentials are stored in login Keychain, never JSON logs or child environment settings.

## Process lifecycle and uninstall

The unprivileged supervisor owns each protected child group and its reaping. Startup uses a pipe gate, not task suspension. Parent EOF, termination signals, or a stopped child cause CONT/TERM/bounded-KILL cleanup; rules are rechecked throughout checking/running phases. App shutdown targets recorded runner and child/supervisor identities with start-time cookies. PID identity checks are not atomic kernel handles and do not promise malicious-code containment or survival of simultaneous forced destruction of all owners.

Command-line uninstall branches before SwiftUI/model startup and does not register anything. It must unregister its own login/legacy service before recognized file cleanup. Preview has no service/file mutation. Unknown or modified files are reported left. Neither live BTM cleanup nor OS login safety is established by source review or fixture tests.

## Reporting a vulnerability

Do not include credentials, conversation contents, private hostnames, real public IPs, complete network logs or signing material in a public issue.

If the repository's Security tab offers **Report a vulnerability**, use that private reporting channel. Otherwise contact the repository owner privately through an existing trusted channel and ask for a private reporting method. No private reporting endpoint or response-time guarantee is configured by this source package.

A useful report includes a minimal synthetic reproduction, macOS/architecture, source version, VPN transport category and whether the issue affects direct sockets, proxy routing, command integration, process inheritance or a desktop service handoff. Redact identifiers and attach only the smallest necessary logs.

## Disclosure and validation

Please allow maintainers to assess and prepare a fix before publishing an exploitable reproduction. Security fixes need a regression test that demonstrates the failure and verifies the fail-closed behavior. Never interrupt another person's active VPN or run AI account requests during routine tests.
