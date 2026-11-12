# Contributing

Keep changes small and explain the trigger, behavior change, validation and remaining limitations. Do not weaken a fail-closed path to improve compatibility.

## Local checks

```sh
swift test
./scripts/build.sh
python3 scripts/public-source.py --check
```

The build is local and ad-hoc-signed by default. Supply your own signing identity through `CODE_SIGN_IDENTITY` if needed. Never commit certificates, private keys, provisioning profiles, credentials, local diagnostics or real user configuration.

## Network and isolation changes

Use deterministic parsing/decision tests and native numeric-address socket tests. A DNS error alone does not demonstrate that direct sockets are blocked. Cover argument boundaries, inherited descriptors and subprocesses when changing launch behavior.

The optional live transport test sends public diagnostics through a currently connected VPN. Run it only when that network use is intended. Forced disconnect, reboot and other disruptive tests require explicit consent and a recovery path.

Use synthetic hostnames and addresses in issue reports. Explain precisely which VPN/client/app/macOS combination was tested. Do not broaden compatibility claims based only on unit tests or a single working connection.

## Public source

`python3 scripts/public-source.py --check` audits an explicit allowlist. `--archive /absolute/output.zip` creates a source package using that same allowlist. The original development folder may contain ignored personal history; do not upload it wholesale.

CI configuration uses read-only repository permissions. GitHub actions have not run until the repository is published and a workflow reports a result. Report potential security vulnerabilities privately as described in SECURITY.md.
