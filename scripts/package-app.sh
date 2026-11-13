#!/bin/zsh
set -eu
cd -- "${0:A:h:h}"
APP="$PWD/dist/VPNGuard.app"
[[ -d "$APP" ]] || { print -u2 "Build the app before packaging."; exit 1; }
codesign --verify --deep --strict "$APP"
ARCH=$(uname -m)
NAME="VPNGuard-macOS-${ARCH}-experimental.zip"
ditto -c -k --keepParent "$APP" "$PWD/dist/$NAME"
(cd dist && shasum -a256 "$NAME" > "$NAME.sha256")
printf 'Packaged %s (local ad-hoc build; not notarized).\n' "$NAME"
