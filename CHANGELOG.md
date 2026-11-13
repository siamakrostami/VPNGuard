# Changelog

## Unreleased incident hardening (local source only)

- Remove runner self-SIGSTOP job control; stopped children now trigger cleanup.
- Add an unprivileged process-group supervisor with parent-death lease, safe startup gate, bounded CONT/TERM/KILL and identity-checked control.
- Recheck running/checking rules and cancel removed/excluded/disabled sessions; stop recorded sessions on app quit and shutdown.
- Add dedicated uninstall/preview entry, in-app action and guarded script. Unregister own services and remove only recognizable own files; print privileged leftovers for manual review.
- Unit tests use harmless fixtures only. No live app, runner, login/service or other VPN repair validation is claimed.

## 2.0.0-beta.2

- Add explicit system/manual HTTP CONNECT, HTTPS CONNECT, SOCKS5 remote-DNS and SOCKS4a upstream transports, with Keychain credentials and no direct fallback.
- Expand routed detection to IPv4/IPv6 virtual tunnel families including utun, ppp/L2TP, tun, tap and ipsec; keep payloads within one verified family.
- Show connection selection and endpoint settings in the native UI.
- Add automated Apple Silicon/Intel app ZIP and checksum downloads in GitHub Actions.
- Document Windows/Linux phases and router/proxy compatibility boundaries in the roadmap.

- Recover live protected CLI sessions after VPN reconnects without changing their authenticated proxy endpoint.
- Add Reset connections in Activity and the toolbar. Reset closes existing sockets and requires a fresh VPN/exit check; it never replays a prompt.
- Keep direct network restrictions during recovery and reject stale verification results and revoked connection workers.
- Ask for a working folder on every command launch from the app, remember the last selection, and isolate consecutive launcher scripts.
- Older running sessions need a one-time relaunch to use the new recovery behavior.

## 2.0.0-beta.1

Experimental source beta.

- General VPN-required command/application rules with a native macOS interface.
- Per-launch VPN verification and non-Iran exit requirement.
- zsh integration with bounded startup edits and backups.
- Guarded process runner with inherited network isolation and literal argument forwarding.
- Authenticated HTTP CONNECT proxy with explicit tunnel-interface/source binding.
- Periodic verification, topology monitoring and independent expiry shutdown.
- Local launch activity and startup preference.

Known limitations: compatible IPv4 `utun` tunnels only; HTTPS/secure WebSockets through CONNECT only; deprecated `sandbox-exec`; ordinary Finder launches and independently running desktop services are outside universal coverage. Public binaries are not notarized by the default local build.
