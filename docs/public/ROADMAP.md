# VPNGuard roadmap

This roadmap describes planned work, not delivered platform support or committed release dates. The current implementation is macOS-only.

## Current macOS beta

- CLI wrappers and explicit protected app launching, working-folder picker, recovery/reset controls.
- Routed IPv4/IPv6 virtual tunnels and explicit HTTP/HTTPS CONNECT or SOCKS5/SOCKS4a proxy endpoints.
- Automatic system proxy selection or manual endpoint settings, independent exit verification, Keychain credentials.
- Automated Apple Silicon and Intel test/build/download workflows. These builds are ad-hoc signed and are not notarized.

## Phase 1: shared connection contracts

Extract connection selection, proxy protocol negotiation, exit checks, freshness/generation state, redacted diagnostics, and conformance fixtures behind platform-neutral interfaces. Keep process isolation and credential stores platform-specific. Decide a shared runtime only after a small cross-platform CLI prototype demonstrates fail-closed behavior; do not port the macOS sandbox profile mechanically.

Acceptance: the same proxy/auth/DNS/recovery fixtures run on supported platforms, credentials stay in native secure storage, and unsupported traffic fails without direct fallback.

## Phase 2: Linux CLI preview

Prototype protected command launches with a per-session network namespace plus an isolated local broker. Evaluate nftables rules and least-privilege setup for distributions that support them. Use Secret Service or an explicitly documented native credential provider. Start with selected distributions and CLI processes; do not claim arbitrary service/container coverage.

Acceptance: child/descendant direct TCP, IPv6 and UDP are blocked; only the broker path works; loss/recovery and crash cleanup are tested; privilege setup has a reversible uninstall path. Package and test on real Linux hosts before publishing usable builds.

## Phase 3: Windows CLI preview

Prototype a small Windows Filtering Platform service/broker and process identity tracking, with a clear installer and UAC boundary. Store secrets in Windows Credential Manager or DPAPI-backed storage. Evaluate process-tree/service delegation and network transitions before exposing desktop-app protection.

Acceptance: protected processes cannot bypass the broker by numeric IP, DNS, IPv6, UDP or a child process; PID reuse cannot transfer policy; rules persist safely across service restarts and uninstall cleanly. Validate signing and distribution requirements before public installers.

## Phase 4: native UI and production distribution

Provide native connection/rule/status controls, accessibility, login startup, migration and recovery flows on each platform. Add signed installers, release checksums, reproducible build notes and upgrade/rollback testing. On macOS, obtain a suitable maintainer Developer ID and notarize conventional downloadable releases.

## Compatibility and router research

Test V2Ray/Xray client HTTP/SOCKS/mixed listeners, L2TP/ppp, OpenVPN, WireGuard, Windscribe, Nord and other clients across actual configurations. Brand names do not prove a configuration works.

For Passwall2/OpenWrt, an explicit router proxy can be selected by LAN endpoint. A transparent router's destination rules and fallback are not visible/enforceable from this Mac transport. Research router cooperation and diagnostic manifests rather than silently treating every physical default route as a protected tunnel. Group related service domains only from documented/observed evidence; one checked domain does not attest every request.

## Non-goals and unresolved limits

No universal guarantee against IP leaks, provider account bans, device fingerprinting or service eligibility checks. No timezone/device identity spoofing. PAC/WPAD evaluation, custom proxy authentication methods, unsupported transports, arbitrary background services and malicious-code containment need separate design and testing.
