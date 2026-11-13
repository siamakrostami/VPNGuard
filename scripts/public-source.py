#!/usr/bin/env python3
"""Audit/archive an explicit public-source allowlist. No Git/network changes."""
from __future__ import annotations
import argparse
import pathlib
import re
import sys
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
TOP = {"Package.swift", "README.md", "LICENSE", "SECURITY.md", "CONTRIBUTING.md", "CHANGELOG.md", ".gitignore"}
TREES = {"Sources": {".swift", ".c", ".h"}, "Tests": {".swift"}, "Packaging": {".plist"}, "scripts": {".sh", ".swift", ".py"}, ".github": {".yml", ".yaml", ".md"}, "docs/public": {".md"}}


def files() -> list[pathlib.Path]:
    result = [ROOT / name for name in TOP]
    for tree, suffixes in TREES.items():
        folder = ROOT / tree
        result.extend(p for p in folder.rglob("*") if p.is_file() and p.suffix in suffixes and not any(x.startswith(".") for x in p.relative_to(folder).parts[:-1]))
    result = sorted(set(result), key=lambda p: p.relative_to(ROOT).as_posix())
    for p in result:
        if not p.exists() or p.is_symlink() or not p.resolve().is_relative_to(ROOT):
            raise ValueError(f"Missing or unsafe source path: {p.relative_to(ROOT)}")
    return result


def audit(paths: list[pathlib.Path]) -> None:
    issues: list[str] = []
    for p in paths:
        rel = p.relative_to(ROOT).as_posix()
        if p.stat().st_size > 1_000_000:
            issues.append(f"{rel}: unexpectedly large source file")
        text = p.read_text(encoding="utf-8")
        patterns = [
            (r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "private key material"),
            (r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b", "GitHub credential"),
            (r"\bAKIA[A-Z0-9]{16}\b", "AWS credential identifier"),
            (r"(?<![A-Za-z0-9])[A-Fa-f0-9]{40}(?![A-Za-z0-9])", "embedded 40-digit fingerprint; review signing/personal data"),
        ]
        for pattern, label in patterns:
            if re.search(pattern, text):
                issues.append(f"{rel}: {label}")
        for match in re.finditer(r"/" + r"Users/([^/\s\"']+)", text):
            if match.group(1) not in {"you", "test", "example"}:
                issues.append(f"{rel}: machine-specific home path")
        retired_markers = ["ownerUID", "teamID =", "OpenVPNConnect.framework"]
        if rel != "Sources/VPNGuardApp/AppUninstallCoordinator.swift":
            retired_markers.append("com.siamak.VPNGuard.helper")
        if rel.startswith("Sources/") and any(x in text for x in retired_markers):
            issues.append(f"{rel}: retired helper or personal account binding")
    if issues:
        raise ValueError("Public-source audit failed:\n" + "\n".join(issues))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--archive", type=pathlib.Path)
    args = parser.parse_args()
    paths = files()
    audit(paths)
    if args.list:
        print("\n".join(p.relative_to(ROOT).as_posix() for p in paths))
    if args.archive:
        target = args.archive.expanduser().resolve()
        if target.exists():
            raise ValueError("Archive already exists; choose a new output name.")
        if target in {p.resolve() for p in paths}:
            raise ValueError("Archive cannot overwrite source.")
        target.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for p in paths:
                archive.write(p, "VPNGuard/" + p.relative_to(ROOT).as_posix())
        print(f"Created {target} with {len(paths)} allowlisted files.")
    elif not args.list:
        print(f"Public-source audit passed: {len(paths)} allowlisted files.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError, UnicodeError) as exc:
        print(exc, file=sys.stderr)
        raise SystemExit(1)
