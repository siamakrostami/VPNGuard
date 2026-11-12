# Changelog

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
