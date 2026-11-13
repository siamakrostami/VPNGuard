# Architecture and limits

## Components

- **VPNGuardApp:** native SwiftUI window, menu-bar status, rule management, integration setup and launch actions. No administrator helper or Network Extension is installed.
- **VPNGuardRun:** normal-user runner. Loads one enabled rule, verifies a usable VPN/exit, creates a session proxy and launches the child under a seatbelt profile. It preserves argument/stdin/stdout/exit boundaries and does not allow proxy/tunnel descriptors into the child.
- **VPNGuardCore:** rule validation/storage, bounded zsh edits, sandbox configuration, route discovery, diagnostic HTTPS bridge, CONNECT parsing, tunnel-bound proxy and session records.

## Launch flow

1. Resolve a rule and refuse disabled/missing policies or executables.
2. Select an explicit system/manual proxy or corroborate routed control destinations on one active virtual tunnel, choosing one IPv4/IPv6 source and interface index.
3. Perform diagnostic HTTPS through that exact transport; routed diagnostics use dual binding, proxy diagnostics use explicit libcurl proxy settings with TLS validation and an empty bypass list. Require a known non-Iran country.
4. Start an authenticated proxy on one random IPv4 loopback port.
5. Restrict the child and inherited subprocesses to TCP on that exact local endpoint, and supply proxy settings.
6. Routed traffic resolves A/AAAA through family-matched tunnel-bound HTTPS DNS and uses dual-bound sockets. Proxy traffic delegates destination DNS/CONNECT negotiation to the selected proxy (SOCKS5h/SOCKS4a or HTTP CONNECT). The C libcurl bridge retains outer HTTPS proxy TLS; payload TLS remains opaque.
7. Watch topology and refresh verification. Revoke the current connection generation and close payload sockets on a change/failure or expiry, using an independent freshness watchdog. Keep the same authenticated listener reserved, denying payload traffic with HTTP 503 until fresh verification succeeds.
8. While blocked, reverify automatically about every five seconds. A manual reset in Activity sends a private, per-session request consumed by the runner heartbeat and requests an immediate fresh check. A new verification can select a different verified tunnel; stale workers/results cannot attach to the new generation. Final stop closes the listener permanently.

Every command launch from the UI asks for a directory using a native folder picker. It captures that directory in a uniquely named launch script. Cancel does nothing, and a missing directory fails before starting the runner. Shell integration keeps the caller’s working directory.

## Why the TLS bridge exists

Binding a client only to a local source address is insufficient to establish the required interface restriction on Darwin. The diagnostic and DNS path uses a local byte bridge whose outbound POSIX socket sets both `IP_BOUND_IF` and the verified source address; system curl handles normal TLS hostname/certificate validation over that bridge. Payload TLS is relayed without interception.

## Proxy selection and credentials

Automatic mode prefers explicit system proxy settings, otherwise routed discovery. Explicit system/manual mode never changes to a direct path when unavailable. macOS HTTPSProxy settings normally describe HTTP CONNECT for HTTPS destinations, not TLS-to-proxy. PAC/WPAD-only settings need an explicit manual endpoint. Credential values stay in login Keychain and are passed to libcurl only by the parent broker; settings persist an opaque reference. Changing the endpoint/reference changes the path snapshot and revokes old sessions before re-verification.

The macOS child boundary remains the exact loopback port regardless of upstream family or protocol. SDK libcurl owns upstream proxy descriptors; other threads may shutdown registered descriptors on revoke, while only the worker cleans up libcurl.

## Local data

Private settings, generated hooks/wrappers, backups and launch records live under the current user's Application Support folder. Launch records contain operational status, not traffic payloads or proxy credentials. Integration edits only a delimited `.zshrc` block and preserves an original backup. A linked `.zshrc` is not replaced.

## Boundaries

The UI's “VPN verified” state describes a recent tunnel/exit check, not universal coverage of all running processes. CLI wrappers apply to their selected command names in integrated zsh sessions. Applications require an explicit guarded launch and must not already be running. An app that hands work to an independent service may not inherit the launch sandbox.

This design deliberately blocks unsupported traffic rather than silently opening direct paths. It is not a replacement for OS-level per-app filtering or an assurance against malicious local code/administrators. Checks are periodic; external geolocation is not guaranteed to match another provider's classification.
