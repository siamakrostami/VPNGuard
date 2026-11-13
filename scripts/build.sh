#!/bin/zsh
set -eu
cd -- "${0:A:h:h}"
# No certificate is required for a local source build. Supply CODE_SIGN_IDENTITY
# explicitly when building with your own Developer ID or development certificate.
IDENTITY=${CODE_SIGN_IDENTITY:--}
OUTPUT_DIR=${VPNGUARD_OUTPUT_DIR:-"$PWD/dist"}
if [[ "$OUTPUT_DIR" != /* ]]; then OUTPUT_DIR="$PWD/$OUTPUT_DIR"; fi
APP="$OUTPUT_DIR/VPNGuard.app"
# Always use a fresh staging root: old helper metadata must never survive a build.
mkdir -p "$PWD/.build"
STAGE_ROOT=$(mktemp -d "$PWD/.build/VPNGuard-staging.XXXXXX")
STAGE="$STAGE_ROOT/VPNGuard.app"
trap 'rm -rf -- "$STAGE_ROOT"' EXIT
swift build -c release --product VPNGuard
swift build -c release --product VPNGuardRun
swift build -c release --product VPNGuardProcessHost
BIN=$(swift build -c release --show-bin-path)
mkdir -p "$STAGE/Contents/MacOS" "$STAGE/Contents/Resources" "$OUTPUT_DIR"
cp "$BIN/VPNGuard" "$STAGE/Contents/MacOS/VPNGuard"
cp "$BIN/VPNGuardRun" "$STAGE/Contents/MacOS/VPNGuardRun"
cp "$BIN/VPNGuardProcessHost" "$STAGE/Contents/MacOS/VPNGuardProcessHost"
cp Packaging/Info.plist "$STAGE/Contents/Info.plist"
ICONSET="$PWD/.build/VPNGuard.iconset"
mkdir -p "$ICONSET"
xcrun swift scripts/make-icon.swift "$PWD/.build/icon.png"
for size in 16 32 128 256 512; do
  sips -z "$size" "$size" "$PWD/.build/icon.png" --out "$ICONSET/icon_${size}x${size}.png" >/dev/null
  double=$((size * 2))
  sips -z "$double" "$double" "$PWD/.build/icon.png" --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$STAGE/Contents/Resources/VPNGuard.icns"
chmod 755 "$STAGE/Contents/MacOS/VPNGuard" "$STAGE/Contents/MacOS/VPNGuardRun" "$STAGE/Contents/MacOS/VPNGuardProcessHost"
SIGNING_ARGS=(--force --options runtime --sign "$IDENTITY")
if [[ "${VPNGUARD_TIMESTAMP:-0}" == 1 ]]; then SIGNING_ARGS+=(--timestamp); else SIGNING_ARGS+=(--timestamp=none); fi
codesign "${SIGNING_ARGS[@]}" --identifier com.siamak.VPNGuard.ProcessHost "$STAGE/Contents/MacOS/VPNGuardProcessHost"
codesign "${SIGNING_ARGS[@]}" --identifier com.siamak.VPNGuard.Run "$STAGE/Contents/MacOS/VPNGuardRun"
codesign "${SIGNING_ARGS[@]}" --identifier com.siamak.VPNGuard "$STAGE"
codesign --verify --deep --strict --verbose=2 "$STAGE"
# Preserve prior output without touching a user's installed app or login item.
if [[ -e "$APP" ]]; then mv "$APP" "$OUTPUT_DIR/VPNGuard.previous-$(date +%Y%m%d%H%M%S).app"; fi
ditto "$STAGE" "$APP"
printf '\nBuilt: %s\n' "$APP"
if [[ "$IDENTITY" == - ]]; then
  printf 'Local ad-hoc signature only. This app is not notarized for public binary distribution.\n'
fi
