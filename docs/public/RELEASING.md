# Release preparation

## Source beta

1. Run `swift test` and review skipped tests separately.
2. Run `zsh scripts/build.sh`; verify the produced local ad-hoc signature. Do not confuse it with a notarized distribution build.
3. Run `python3 scripts/public-source.py --check`.
4. Inspect `.gitignore` and `python3 scripts/public-source.py --list` before staging any files.
5. Create an allowlisted source archive:

   ```sh
   python3 scripts/public-source.py --archive /absolute/path/VPNGuard-source-beta.zip
   ```

6. Extract that archive in a fresh folder and verify its tests/build independently.
7. Review the MIT license, README and security/compatibility statements. Create the GitHub repository, commit and push only after the owner approves those external actions.

Do not upload `.build`, generated `.app` bundles, `Previous`, local developer notes, inspection JSON, logs, user configuration, signing material or the retired single-VPN helper. The source allowlist is narrower than the original working directory.

## Automated builds

The `macOS checks and downloads` workflow tests/builds on Apple Silicon (`macos-15`) and Intel (`macos-15-intel`). Successful runs package app ZIPs and SHA-256 files as 30-day Actions artifacts. Select the architecture-specific artifact, extract the outer artifact archive, then extract the inner app ZIP. GitHub may require sign-in for Actions downloads.

The workflow has read-only repository contents permission. It runs on main pushes, pull requests, published releases, and manual dispatch. It does not upload private local build folders or use signing secrets. A configured workflow is not a completed build; link only verified successful artifacts. macOS runner labels follow GitHub's [runner documentation](https://docs.github.com/en/actions/reference/runners/github-hosted-runners).

## Downloadable binary

A default local build uses an ad-hoc signature. It is useful for a person building the source on their own Mac; it is not a normal Gatekeeper-ready public app release.

For a conventional direct-download Mac release, the maintainer needs their own suitable Developer ID signing identity and Apple's notarization process. The repository includes no credentials, Developer ID certificate, private key, provisioning profile or notarization account. Set `CODE_SIGN_IDENTITY` and `VPNGUARD_TIMESTAMP=1` explicitly for that build; submit/staple notarization separately. Never tell users to disable Gatekeeper, reduce system security or clear quarantine as a release procedure.

## Compatibility claims

Keep the release experimental until there is broader testing of VPN brands, macOS versions, architecture, outages, suspend/resume, startup behavior and individual desktop-app/service patterns. Do not advertise “all VPNs”, “all apps”, “no leaks” or equivalent absolute claims from the current validation.

The CI workflow builds/tests a local ad-hoc version with read-only repository permissions. A workflow file's existence does not mean GitHub CI passed; inspect the actual run after publication.
