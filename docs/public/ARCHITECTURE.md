# Architecture and limits

## Components

- **VPNGuardApp:** native SwiftUI window, menu-bar status, rule management, integration setup and launch actions. No administrator helper or Network Extension is installed.
- **VPNGuardRun:** normal-user runner. Loads one enabled rule, verifies a usable VPN/exit, creates a session proxy and launches the child under a seatbelt profile. It preserves argument/stdin/stdout/exit boundaries and does not allow proxy/tunnel descriptors into the child.
- **VPNGuardCore:** rule validation/storage, bounded zsh edits, sandbox configuration, route discovery, diagnostic HTTPS bridge, CONNECT parsing, tunnel-bound proxy and session records.

## Launch flow

1. Resolve a rule and refuse disabled/missing policies or executables.
2. Corroborate routed control destinations on one active IPv4 `utun` interface and identify its unique source address/index.
3. Perform a pinned HTTPS diagnostic through a socket bound to that interface and address; require a known non-Iran country.
4. Start an authenticated proxy on one random IPv4 loopback port.
5. Restrict the child and inherited subprocesses to TCP on that exact local endpoint, and supply proxy settings.
6. Resolve destinations through tunnel-bound HTTPS DNS, then connect through dual-bound sockets.
7. Watch topology and refresh verification. Close payload sessions on a change/failure or expiry, using an independent freshness watchdog.

## Why the TLS bridge exists

Binding a client only to a local source address is insufficient to establish the required interface restriction on Darwin. The diagnostic and DNS path uses a local byte bridge whose outbound POSIX socket sets both `IP_BOUND_IF` and the verified source address; system curl handles normal TLS hostname/certificate validation over that bridge. Payload TLS is relayed without interception.

## Local data

Private settings, generated hooks/wrappers, backups and launch records live under the current user's Application Support folder. Launch records contain operational status, not traffic payloads or proxy credentials. Integration edits only a delimited `.zshrc` block and preserves an original backup. A linked `.zshrc` is not replaced.

## Boundaries

The UI's “VPN verified” state describes a recent tunnel/exit check, not universal coverage of all running processes. CLI wrappers apply to their selected command names in integrated zsh sessions. Applications require an explicit guarded launch and must not already be running. An app that hands work to an independent service may not inherit the launch sandbox.

This design deliberately blocks unsupported traffic rather than silently opening direct paths. It is not a replacement for OS-level per-app filtering or an assurance against malicious local code/administrators. Checks are periodic; external geolocation is not guaranteed to match another provider's classification.
