#!/usr/bin/env python3
"""Release grindvakt-core X.Y.Z in lockstep with Grindvakt vX.Y.Z.

Usage: scripts/release.py X.Y.Z [--dry-run]

Run this BEFORE the Grindvakt app's scripts/release/release.py for the same version;
the app script refuses to tag vX.Y.Z until grindvakt-core X.Y.Z is live on crates.io.

Steps (stops at the first failure, never moves or overwrites tags):
  1. clean tree on `main`, up to date with origin/main, tag vX.Y.Z absent locally and remotely,
     X.Y.Z not already on crates.io, X.Y.Z greater than the current version (or equal when the
     current commit is an unreleased bump);
  2. set `version` in Cargo.toml and Cargo.lock; require a Keep a Changelog `## [X.Y.Z]` heading;
  3. gates: fmt, clippy (all / no default features), tests (all / no default features),
     every example, `cargo package` + `cargo publish --dry-run`;
  4. commit `release: vX.Y.Z`, annotated tag vX.Y.Z, atomic push of main + tag;
  5. `cargo publish`, then poll crates.io until X.Y.Z is visible and its checksum matches the
     local .crate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRATE = "grindvakt-core"
SEMVER = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$")
EXAMPLES = ["config_load", "vault_roundtrip", "ip_discovery", "dns_plan_dry_run", "embed_in_app"]
UA = {"User-Agent": "grindvakt-core release script (https://github.com/WeirdBrains/grindvakt-core)"}


def run(*args: str, capture: bool = False) -> str:
    print("+", " ".join(args), flush=True)
    r = subprocess.run(args, cwd=ROOT, text=True, capture_output=capture)
    if r.returncode != 0:
        if capture:
            sys.stderr.write(r.stdout + r.stderr)
        sys.exit(f"failed: {' '.join(args)}")
    return r.stdout if capture else ""


def parse(v: str) -> tuple[int, int, int]:
    m = SEMVER.match(v)
    if not m:
        sys.exit(f"not a plain X.Y.Z version: {v}")
    return tuple(int(x) for x in m.groups())  # type: ignore[return-value]


def current_version() -> str:
    m = re.search(r'^version = "([^"]+)"', (ROOT / "Cargo.toml").read_text(), re.M)
    if not m:
        sys.exit("no version in Cargo.toml")
    return m.group(1)


def crates_io_versions() -> dict[str, dict]:
    try:
        with urllib.request.urlopen(urllib.request.Request(f"https://crates.io/api/v1/crates/{CRATE}", headers=UA), timeout=20) as r:
            data = json.load(r)
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {}
        raise
    return {v["num"]: v for v in data.get("versions", [])}


def set_version(v: str) -> None:
    p = ROOT / "Cargo.toml"
    s = p.read_text()
    s = re.sub(r'^version = "[^"]+"', f'version = "{v}"', s, count=1, flags=re.M)
    p.write_text(s)
    lock = ROOT / "Cargo.lock"
    t = lock.read_text()
    t = re.sub(r'(\[\[package\]\]\nname = "grindvakt-core"\nversion = )"[^"]+"', rf'\1"{v}"', t)
    lock.write_text(t)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("version")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    v = a.version
    parse(v)
    tag = f"v{v}"

    if run("git", "status", "--porcelain", capture=True).strip():
        sys.exit("working tree not clean")
    if run("git", "rev-parse", "--abbrev-ref", "HEAD", capture=True).strip() != "main":
        sys.exit("not on main")
    run("git", "fetch", "origin", "main", "--tags")
    if run("git", "rev-parse", "HEAD", capture=True) != run("git", "rev-parse", "origin/main", capture=True):
        sys.exit("main is not equal to origin/main")
    if run("git", "tag", "-l", tag, capture=True).strip() or run("git", "ls-remote", "--tags", "origin", f"refs/tags/{tag}", capture=True).strip():
        sys.exit(f"tag {tag} already exists; tags are never moved")
    published = crates_io_versions()
    if v in published:
        sys.exit(f"{CRATE} {v} is already on crates.io")
    cur = current_version()
    if parse(v) < parse(cur) or (parse(v) == parse(cur) and cur in published):
        sys.exit(f"{v} must be newer than {cur}")
    if f"## [{v}]" not in (ROOT / "CHANGELOG.md").read_text():
        sys.exit(f"CHANGELOG.md needs a '## [{v}]' section")

    set_version(v)
    run("cargo", "fmt", "--all", "--", "--check")
    run("cargo", "clippy", "--all-targets", "--all-features", "--locked", "--", "-D", "warnings")
    run("cargo", "clippy", "--all-targets", "--no-default-features", "--locked", "--", "-D", "warnings")
    run("cargo", "test", "--all-features", "--locked")
    run("cargo", "test", "--no-default-features", "--locked")
    for e in EXAMPLES:
        run("cargo", "run", "--locked", "--all-features", "--example", e)
    run("cargo", "package", "--locked", "--allow-dirty")
    run("cargo", "publish", "--dry-run", "--locked", "--allow-dirty")
    if a.dry_run:
        run("git", "checkout", "--", "Cargo.toml", "Cargo.lock")
        print(f"dry run OK for {CRATE} {v}")
        return

    run("git", "add", "Cargo.toml", "Cargo.lock")
    if run("git", "status", "--porcelain", capture=True).strip():
        run("git", "commit", "-m", f"release: {tag}")
    run("git", "tag", "-a", tag, "-m", f"{CRATE} {v}")
    run("git", "push", "--atomic", "origin", "HEAD:refs/heads/main", f"refs/tags/{tag}")
    run("cargo", "publish", "--locked")

    target_dir = json.loads(run("cargo", "metadata", "--format-version", "1", "--no-deps", capture=True))["target_directory"]
    crate_file = Path(target_dir) / "package" / f"{CRATE}-{v}.crate"
    local = hashlib.sha256(crate_file.read_bytes()).hexdigest()
    for _ in range(60):
        live = crates_io_versions().get(v)
        if live:
            if live["checksum"] != local:
                sys.exit(f"crates.io checksum {live['checksum']} != local {local}")
            print(f"{CRATE} {v} is live on crates.io, checksum {local}")
            return
        time.sleep(10)
    sys.exit(f"{CRATE} {v} not visible on crates.io after 10 minutes")


if __name__ == "__main__":
    main()
