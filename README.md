# VPNGuard

**Experimental VPN-required launches for macOS.** Add commands or compatible applications to a list, and launch them only after a selected routed tunnel or proxy and an exit outside Iran have been verified.

VPNGuard is a native SwiftUI app with a menu-bar companion, zsh command integration, and a separate guarded process runner. It does not require administrator access or a paid Apple Developer account for local source builds.

## Features

- Add, edit, search, enable and remove command/application rules.
- Type integrated commands normally in a new zsh session.
- Verify the VPN independently for every guarded launch.
- Restrict direct outbound sockets for the launched process and inherited children.
- Relay compatible HTTPS and secure WebSocket traffic through a session-specific authenticated HTTP CONNECT proxy.
- Bind routed outgoing sockets to the selected tunnel interface/source, or relay through an explicit upstream proxy without direct fallback.
- Discover system HTTP/SOCKS proxy settings or choose a manual HTTP, HTTPS, SOCKS5 or SOCKS4a endpoint.
- Close proxy connections on topology change, failed verification or expired checks, then recover the same session only after fresh verification.
- Reset an active session’s connections from Activity without closing its CLI.
- Choose a working folder whenever you launch a command from the app.
- View local launch records and configure startup at login.

## Requirements

- macOS 14 or later.
- Xcode with Swift 6 and command-line tools for building.
- Apple's `sandbox-exec` compatibility tool, included on the macOS versions tested so far.
- A compatible routed IPv4/IPv6 virtual tunnel, or an accessible HTTP CONNECT / HTTPS CONNECT / SOCKS5 / SOCKS4a proxy.
- A command/application that supports the standard HTTP CONNECT proxy configuration.

**Compatibility is intentionally conservative.** The protected child uses the private CONNECT proxy. Plain HTTP, direct child TCP, UDP and QUIC are blocked; unverified routes/proxies are refused. A recognized transport is not proof that every product configuration has been tested.

## Downloads

Open [Actions](https://github.com/siamakrostami/VPNGuard/actions), select a **successful** `macOS checks and downloads` run, then download the Apple Silicon (`ARM64`) or Intel (`X64`) artifact. Extract the outer artifact ZIP and the inner app ZIP. GitHub may require sign-in. Checksums are included; artifacts expire after 30 days.

These automated builds are **experimental, ad-hoc signed, and not notarized**. macOS may refuse to open downloaded builds. Conventional Gatekeeper-ready distribution requires a maintainer Developer ID and notarization; do not disable system security to use a beta. Source builds remain available below.

## VPN, proxy and router compatibility

Choose **Settings → Protected connection**:

| Mode | What it uses |
| --- | --- |
| Automatic | Explicit macOS HTTPS/HTTP/SOCKS proxy settings when enabled; otherwise a recognized routed tunnel. |
| Routed VPN or tunnel | A consistent IPv4 or IPv6 virtual tunnel/source; routed sockets stay bound to that interface and address. |
| System proxy | Only the configured explicit system proxy. It does not fall back direct if those settings disappear. |
| Manual proxy | An HTTP CONNECT, HTTPS CONNECT (TLS to proxy), SOCKS5 with remote DNS, or SOCKS4a listening endpoint. |

For V2Ray/Xray clients, enter their local HTTP, SOCKS or mixed listener's host/port in manual mode, or enable their system proxy and use automatic mode. VPNGuard talks to that endpoint; the client handles VMess/VLESS/Trojan/Shadowsocks/Reality or its other remote transport. Subscription links and remote protocol URLs are not imported. For a conventional HTTP proxy used for HTTPS destinations, choose **HTTP CONNECT**; select **HTTPS CONNECT** only when the connection *to the proxy itself* uses TLS.

Routed discovery recognizes `utun`, `ppp` (including L2TP-style tunnels), `tun`, `tap` and `ipsec` interfaces. WireGuard, OpenVPN, Windscribe, Nord and similar clients can use this route-based path when their configuration satisfies the interface/source/route checks. This is transport support, not a claim that every listed product or configuration was tested. IPv4 is preferred when both families have a valid routed candidate; a failing IPv4 exit check does not silently switch families.

Save a selection and wait for **Connection verified**. Verification uses that same upstream path. Optional proxy credentials stay in macOS login Keychain; settings store only a reference. HTTP Basic and SOCKS5 username/password are supported; SOCKS4a has a userid but no password authentication. macOS may ask permission to access a saved credential.

A Passwall2/OpenWrt router can be used through an explicit HTTP/SOCKS proxy exposed on its LAN address. Transparent destination-based router rules and fallback cannot be inferred or enforced by this Mac app. A direct physical default route is not silently accepted as a verified VPN. Related domains may be routed differently by the upstream client/router, so one exit check cannot attest every destination's routing.

PAC/WPAD-only proxy discovery, custom authentication methods, UDP/QUIC and unsupported proprietary mechanisms remain outside this beta. Configure an explicit endpoint where available. No unrecognized path is allowed as a direct fallback.

For a detection failure, share the exact VPNGuard error and sanitized route/interface state privately. For a manual proxy, include protocol and listening endpoint with credentials removed. Never share subscription URLs, VPN profiles, secrets or complete network dumps.

## Build locally

```sh
swift test
zsh scripts/build.sh
open dist/VPNGuard.app
```

The default build uses an **ad-hoc local signature**. No personal certificate, provisioning profile or account identifier is included in this repository. This is not a notarized public binary release.

To use your own signing identity explicitly:

```sh
CODE_SIGN_IDENTITY="Developer ID Application: Your Name (YOURTEAMID)" \
  VPNGUARD_TIMESTAMP=1 zsh scripts/build.sh
```

The script creates `dist/VPNGuard.app`. It does not replace an installed copy or edit system VPN/firewall settings. Notarization for public binary distribution is a separate maintainer step; see [release preparation](docs/public/RELEASING.md).

## Use

1. Connect your VPN or proxy client, then select its connection mode in Settings.
2. Open VPNGuard and wait for **Connection verified**.
3. In **VPN Required**, add a command executable or an application bundle.
4. For normal command spelling, install **Settings → Terminal command integration**, then open a new Terminal window. Arguments are forwarded unchanged.
5. For desktop targets, close existing instances and use **Launch** in VPNGuard.

Command launches from the app show a folder picker, starting in your last chosen folder. Cancel opens no terminal. Commands typed in an integrated shell keep that shell’s current directory.

If the VPN disconnects, existing payload connections close and the private endpoint stays blocked. The runner checks again automatically and restores new connections only after a fresh non-Iran exit verification. In **Activity**, choose **Reset connections** to close current connections and request a fresh check, then retry the prompt in the existing terminal. Prompts are never replayed automatically; a CLI that caches its own error may need its native retry/resume flow. Sessions started by an older runner must be relaunched once after updating to gain recovery/reset support.

Closing the window keeps the menu-bar app running. **Quitting VPNGuard terminates its recorded protected sessions**, including launches still checking their connection. Shutdown/log-out notifications request the same bounded cleanup. Wrappers can verify independently when the GUI was already closed, but removal/exclusion of their rule or disabling protection terminates an existing session. Startup registration is off by default and is never restored automatically; enabling it requires an explicit user action.

Command integration adds a bounded source block to `.zshrc`, backs up the original, and creates managed functions/wrappers under `~/Library/Application Support/VPNGuard`. It refuses to replace a linked `.zshrc`; manual instructions are shown instead. Open a new shell after rule or integration changes.

To restore ordinary command lookup, remove integration and open a new Terminal window. Explicit absolute paths, other shells, manually overriding/removing wrappers, and normal Finder/Dock launches are outside command-name integration.

## Security boundary

A guarded process runs under a macOS seatbelt profile. Its direct outbound sockets are restricted to IPv4 TCP on that session's exact loopback proxy port. The parent proxy stays outside the child sandbox. Routed connections bind to the verified tunnel interface/source. Proxy connections negotiate through the selected upstream endpoint using system libcurl; environment proxy/bypass variables cannot trigger a direct fallback. Proxy credentials and traffic payloads are not logged, and TLS is not intercepted.

Topology checks and exit checks run periodically. An independent freshness watchdog blocks payload connections when verification expires, even if the verification worker stalls. The loopback listener remains reserved until its child exits. Recovery uses a new connection generation; old sockets and stale verification results cannot join it.

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

## Session lifecycle

Every protected process group is owned by the small, unprivileged `VPNGuardProcessHost` supervisor. The runner holds a private lifetime pipe; runner exit or loss of that pipe triggers cleanup even if Swift error handling cannot run. Startup uses an interruptible pipe gate, never a suspended child. Unexpected child suspension causes cleanup instead of stopping the runner.

Termination sends SIGCONT, then SIGTERM to the entire protected group, waits up to about five seconds, then uses SIGKILL. The supervisor keeps the leader unreaped until group cleanup finishes. Runner signal handling, rule removal/exclusion, protection disable, app quit and shutdown all use this lifecycle. The policy is checked while verifying and immediately before launch. Recorded process identities include start-time cookies; old unverified journal PIDs are never blindly signalled.

This covers the owned process group, not a malicious process escaping with setsid/setpgid, independently running services, or simultaneous forced destruction of every supervisor. End-to-end GUI shutdown/login behavior requires controlled system testing; unit-test success is not proof of a fixed OS login problem.

## Uninstall

Use **Settings → Uninstall VPNGuard…** in a newly built version that has the dedicated uninstall entry. This stops protected sessions, unregisters this app’s login item and requests legacy daemon unregistration where the per-bundle API can identify it, then removes recognized VPNGuard files. It does not start the ordinary app UI or install/register services during command-line uninstall.

From the source folder, preview first:

```sh
scripts/uninstall.sh
```

To execute after reviewing the preview:

```sh
scripts/uninstall.sh --execute
```

The script requires the new app’s `VPNGuardUninstallCLI` capability marker and correct bundle ID. It refuses older builds rather than passing an unrecognized flag that could start them normally. It never uses sudo or launchctl. No cleanup should be run as part of incident investigation without explicit authorization.

Recognized cleanup includes the bounded VPNGuard block in `.zshrc`, its own Application Support files and preferences plist. The exact saved shell backup is restored only when the managed block was the sole change; later user edits are preserved. Edited/unknown files, symlinks, hard links, unmanifested wrappers and unidentifiable logs are left and listed. A normal recognized install removes its entire support folder; ambiguous legacy data may leave that folder for manual review. Repeated uninstall is safe.

Proxy Keychain credentials, historical app bundles/source backups, historical BTM entries belonging to other copies, and legacy privileged firewall/hosts state are not claimed removed. New builds ship no retired helper or LaunchDaemons descriptor. Per-bundle SMAppService status may be notFound without old bundle metadata and does not prove a globally stale BTM database is clean. No global BTM reset or other VPN software is touched. After quitting, move only the VPNGuard app copies you no longer need to Trash.

Root-owned leftovers require separate administrator cleanup. The uninstaller prints these exact commands as text and **does not execute them**:

```sh
sudo rm -rf -- /private/var/db/com.siamak.VPNGuard
sudo rm -f -- /private/var/log/VPNGuard.log
```

These commands address only the two named VPNGuard leftovers. They do not repair another VPN client or restore its services. Inspect any retained legacy firewall/hosts state separately; this uninstaller does not alter system filtering or another client’s files.

## Platforms and roadmap

macOS is implemented today. Windows and Linux are planned, with platform-specific process isolation and packaging. See the [roadmap](docs/public/ROADMAP.md) for phases and acceptance criteria; no Windows/Linux protection or binaries are shipped yet.

## Contributing and releases

See [CONTRIBUTING.md](CONTRIBUTING.md) for safe development checks and [release preparation](docs/public/RELEASING.md) for the public-source allowlist, audit and packaging commands.

## License

[MIT](LICENSE). Copyright © 2026 Siamak.
