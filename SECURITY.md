# Security policy

VPNGuard is experimental security-sensitive software. It has not received a comprehensive independent audit and should not be represented as a universal leak-proof firewall.

## Supported scope

Only the current source beta is maintained. Guarded launches restrict direct sockets and inherited subprocesses using macOS process isolation and a private tunnel-bound HTTP CONNECT proxy. Normal Finder/Dock launches, direct absolute executable invocation, other shells and independently running service handoffs are not universally covered.

Supported guarded traffic is HTTPS/secure WebSockets through HTTP CONNECT over IPv4. IPv6, UDP/QUIC, plain HTTP, unverified split routes and proxy-only connections are not supported.

## Fail-closed expectations

- A missing rule, disabled rule, disabled launch policy, missing isolation tool or failed VPN/exit check must refuse a guarded launch.
- Outgoing proxy and diagnostic sockets must remain bound to the verified interface and source address.
- Topology loss, failed verification or expired freshness must close payload connections and deny new ones.
- Errors must never silently retry through the physical network or launch without the isolation profile.

These expectations do not cover an administrator changing the OS, a malicious local account, service-mediated escape from a desktop app, or incorrect external IP geolocation. A periodic country check is not per-request geographic attestation.

## Reporting a vulnerability

Do not include credentials, conversation contents, private hostnames, real public IPs, complete network logs or signing material in a public issue.

If the repository's Security tab offers **Report a vulnerability**, use that private reporting channel. Otherwise contact the repository owner privately through an existing trusted channel and ask for a private reporting method. No private reporting endpoint or response-time guarantee is configured by this source package.

A useful report includes a minimal synthetic reproduction, macOS/architecture, source version, VPN transport category and whether the issue affects direct sockets, proxy routing, command integration, process inheritance or a desktop service handoff. Redact identifiers and attach only the smallest necessary logs.

## Disclosure and validation

Please allow maintainers to assess and prepare a fix before publishing an exploitable reproduction. Security fixes need a regression test that demonstrates the failure and verifies the fail-closed behavior. Never interrupt another person's active VPN or run AI account requests during routine tests.
