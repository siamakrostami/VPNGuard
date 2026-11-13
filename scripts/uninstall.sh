#!/bin/bash
# Source-only handoff: never invoke the old privileged helper or delete files here.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/uninstall.sh [--execute] [--app /absolute/path/VPNGuard.app]

Default: preview the local cleanup plan without changing files or registrations.
--execute: ask the supported app to unregister its services, then clean up only
           recognized VPNGuard files in the current user's home directory.
The app bundle is kept. Unknown files are preserved. VPN clients are untouched.
USAGE
}

execute=false
app=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --execute) execute=true; shift ;;
    --app)
      [[ $# -ge 2 ]] || { usage >&2; exit 64; }
      app="$2"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) usage >&2; exit 64 ;;
  esac
done

[[ ! -L "$0" ]] || { printf '%s\n' 'Refusing a symlinked uninstall script.' >&2; exit 1; }
script_dir="$(cd -P -- "$(dirname -- "$0")" && pwd -P)"
project_dir="$(cd -P -- "$script_dir/.." && pwd -P)"
if [[ -z "$app" ]]; then
  for candidate in "$project_dir/VPNGuard.app" "$project_dir/dist/VPNGuard.app" "$project_dir/build/VPNGuard.app"; do
    if [[ -d "$candidate" && ! -L "$candidate" ]]; then app="$candidate"; break; fi
  done
fi
[[ -n "$app" && "$app" == /* && "$app" == *.app && -d "$app" && ! -L "$app" ]] || {
  printf '%s\n' 'A supported VPNGuard.app bundle is required. Use --app with its absolute path. Nothing was changed.' >&2
  exit 1
}
# Refuse linked or traversing ancestors as well as a linked .app itself.
[[ "$app" != *$'\n'* ]] || { printf '%s\n' 'Refusing an ambiguous app path.' >&2; exit 1; }
IFS='/' read -r -a components <<< "$app"
checked=""
for component in "${components[@]}"; do
  [[ -n "$component" ]] || continue
  [[ "$component" != '.' && "$component" != '..' ]] || { printf '%s\n' 'Use an absolute app path without dot components.' >&2; exit 1; }
  checked="$checked/$component"
  [[ ! -L "$checked" ]] || { printf '%s\n' 'Refusing linked app path ancestors. Nothing was changed.' >&2; exit 1; }
done
# Reject linked bundle components; the executable must stay inside the chosen bundle.
for component in "$app/Contents" "$app/Contents/MacOS" "$app/Contents/Info.plist" "$app/Contents/MacOS/VPNGuard"; do
  [[ ! -L "$component" ]] || { printf '%s\n' 'Refusing linked app bundle components. Nothing was changed.' >&2; exit 1; }
done
info="$app/Contents/Info.plist"
executable="$app/Contents/MacOS/VPNGuard"
[[ -f "$info" && -f "$executable" && -x "$executable" ]] || {
  printf '%s\n' 'The app bundle is incomplete. Nothing was changed.' >&2; exit 1
}
identifier="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$info" 2>/dev/null || true)"
capability="$(/usr/libexec/PlistBuddy -c 'Print :VPNGuardUninstallCLI' "$info" 2>/dev/null || true)"
[[ "$identifier" == 'com.siamak.VPNGuard' && "$capability" == 'true' ]] || {
  printf '%s\n' 'This app does not declare the safe uninstall mode. Build the updated app first; nothing was changed.' >&2
  exit 1
}
if "$execute"; then
  exec "$executable" --uninstall
else
  exec "$executable" --uninstall --preview
fi
