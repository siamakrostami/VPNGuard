# VPNGuard

**Experimental VPN-required launches for macOS.** Add commands or compatible applications to a list, and launch them only after a routed IPv4 VPN and an exit outside Iran have been verified.

VPNGuard is a native SwiftUI app with a menu-bar companion, zsh command integration, and a separate guarded process runner. It does not require administrator access or a paid Apple Developer account for local source builds.

## Features

- Add, edit, search, enable and remove command/application rules.
- Type integrated commands normally in a new zsh session.
- Verify the VPN independently for every guarded launch.
- Restrict direct outbound sockets for the launched process and inherited children.
- Relay compatible HTTPS and secure WebSocket traffic through a session-specific authenticated HTTP CONNECT proxy.
- Bind outgoing sockets to both the selected tunnel interface and its source address.
- Close proxy connections on topology change, failed verification or expired checks.
- View local launch records and configure startup at login.

## Requirements

- macOS 14 or later.
- Xcode with Swift 6 and command-line tools for building.
- Apple's `sandbox-exec` compatibility tool, included on the macOS versions tested so far.
- A compatible routed IPv4 `utun` VPN. No VPN-provider-specific process integration is required.
- A command/application that supports the standard HTTP CONNECT proxy configuration.

**Compatibility is intentionally conservative.** Proxy-only VPNs, ambiguous/split routes, IPv6-only tunnels, plain HTTP, direct TCP, UDP and QUIC are unsupported and blocked in guarded processes.

## Build locally

```sh
swift test
./scripts/build.sh
open dist/VPNGuard.app
```

The default build uses an **ad-hoc local signature**. No personal certificate, provisioning profile or account identifier is included in this repository. This is not a notarized public binary release.

To use your own signing identity explicitly:

```sh
CODE_SIGN_IDENTITY="Developer ID Application: Your Name (YOURTEAMID)" \
  VPNGUARD_TIMESTAMP=1 ./scripts/build.sh
```

The script creates `dist/VPNGuard.app`. It does not replace an installed copy or edit system VPN/firewall settings. Notarization for public binary distribution is a separate maintainer step; see [release preparation](docs/public/RELEASING.md).

## Use

1. Connect a compatible VPN.
2. Open VPNGuard and wait for **VPN verified**.
3. In **VPN Required**, add a command executable or an application bundle.
4. For normal command spelling, install **Settings → Terminal command integration**, then open a new Terminal window. Arguments are forwarded unchanged.
5. For desktop targets, close existing instances and use **Launch** in VPNGuard.

The installed app can close while an existing guarded runner continues. Command wrappers verify independently of the UI. The startup preference opens the UI at login.

Command integration adds a bounded source block to `.zshrc`, backs up the original, and creates managed functions/wrappers under `~/Library/Application Support/VPNGuard`. It refuses to replace a linked `.zshrc`; manual instructions are shown instead. Open a new shell after rule or integration changes.

To restore ordinary command lookup, remove integration and open a new Terminal window. Explicit absolute paths, other shells, manually overriding/removing wrappers, and normal Finder/Dock launches are outside command-name integration.

## Security boundary

A guarded process runs under a macOS seatbelt profile. Its direct outbound sockets are restricted to IPv4 TCP on that session's exact loopback proxy port. The parent proxy stays outside the child sandbox and creates tunnel-bound connections. Proxy credentials and traffic payloads are not logged, and TLS is not intercepted.

Topology checks and exit checks run periodically. An independent freshness watchdog stops proxy sessions when verification expires, even if the verification worker stalls.

**This is not a universal background application firewall or malicious-code containment system.** Desktop apps can delegate work through IPC to independently running services or relaunch outside the guarded process tree. Arbitrary desktop apps and service handoffs need individual validation. Ordinary Finder/Dock launches are not intercepted.

`sandbox-exec` is deprecated. A missing or rejected isolation tool causes guarded launches to fail; the runner does not fall back to an unguarded launch. External exit geolocation can be stale, can change between checks, and can differ from a service provider's classification. VPNGuard does not guarantee geographic identity, anonymity, account eligibility, or prevention of every possible leak.

Read [SECURITY.md](SECURITY.md) and [architecture and limits](docs/public/ARCHITECTURE.md) before relying on the tool.

## Validation

Tests cover address and CONNECT validation, rule persistence, strict-shell integration, literal argument forwarding, numeric-address socket restrictions, inherited children, descriptor isolation, and simulated topology/freshness shutdown. An opt-in live test checks the currently connected tunnel, TLS/DoH and authenticated CONNECT. It sends only public diagnostic requests.

```sh
VPNGUARD_LIVE_TRANSPORT_TESTS=1 swift test \
  --filter TransportTests.testLiveTunnelBoundHTTPSAndProxy
```

The default test run skips this live diagnostic. Testing one connection is not validation of every VPN product, network transition, macOS release or desktop application. Forced outage and reboot/login testing are still needed across supported environments. CI is provided as configuration; a local passing build does not imply that a GitHub workflow has run.

## Contributing and releases

See [CONTRIBUTING.md](CONTRIBUTING.md) for safe development checks and [release preparation](docs/public/RELEASING.md) for the public-source allowlist, audit and packaging commands.

## License

[MIT](LICENSE). Copyright © 2026 Siamak.
