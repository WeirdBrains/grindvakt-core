# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions match Grindvakt app
releases one for one.

## [Unreleased]

### Added

- `fs::Privacy::ServiceAccount(name)`: private to SYSTEM, Administrators and the service's
  virtual account `NT SERVICE\<name>` (Windows), owned by SYSTEM or Administrators. Grindvakt
  1.2.0 runs its Windows service under `NT SERVICE\Grindvakt` with it. On Unix it is owner-only,
  like the other variants.
- `fs::service_sid(name)`: the `S-1-5-80-…` SID of a service's virtual account, computed (it
  exists whether or not the service is installed).
- `fs::repair_private_tree(path, privacy)`: re-applies a privacy policy to every directory and
  file under an existing tree (refusing symlinks and reparse points) and returns how many entries
  it fixed. On Windows it also gives Administrators ownership of entries owned by an account the
  policy doesn't accept, such as LocalService.

### Changed

- Releases use the shared WeirdBrains release script (`scripts/weirdnet_release.py` with
  `release.toml`) instead of `scripts/release.py`; the gates and the crates.io publish are the same.

## [1.1.4] - 2026-11-12

### Changed

- No library or API changes. Released to keep the version in lockstep with Grindvakt 1.1.4,
  which fixes its Windows service install. CI pins actions/checkout 7.0.1 by SHA, installs Rust
  with rustup and runs with a read-only token.

## [1.1.3] - 2026-11-12

### Changed

- No library or API changes. Released to keep the version in lockstep with Grindvakt 1.1.3,
  whose macOS installer is now Apple Silicon only.

## [1.1.2] - 2026-11-12

### Changed

- No library or API changes. Released to keep the version in lockstep with Grindvakt 1.1.2,
  which adds the license to its macOS and Windows installers and hardens its release workflow.

## [1.1.1] - 2026-11-11

### Changed

- No library or API changes. Released to keep the version in lockstep with Grindvakt 1.1.1,
  which is now BSD-3-Clause and public like this crate.

## [1.1.0] - 2026-11-11

### Added

- CNAME records: `Record::cname`, `RecordKind::Cname`, `RecordValue::Cname` and
  `record::normalize_target`. A name's single CNAME is kept, retargeted or created;
  targets are compared case-insensitively without the trailing dot.
- CNAME exclusivity in `plan`: wanting a CNAME where records of any other type exist,
  wanting A/AAAA/TXT where a CNAME exists, or wanting both in one plan is `Ambiguous`, so
  `apply` refuses it. Nothing is deleted.
- CNAME validation: no CNAME at the zone apex, targets must be full host names and not the
  record itself, and two CNAMEs at one name are rejected.
- `DnsProvider::types_at`, with a default built on `list`; DNSimple and DigitalOcean report
  every record type at a name. DigitalOcean CNAME data is written with the trailing dot it
  requires and read back from absolute, relative or `@` forms.
- `RecordKind::ALL`.

### Changed

- `plan` now also lists CNAME records for each name with A/AAAA/TXT records wanted, and
  every record type for each name with a CNAME wanted.

## [1.0.0] - 2026-11-11

### Added

- First release: the Grindvakt dynamic DNS engine as a library.
- A, AAAA and TXT records, several per run, including libp2p `_dnsaddr` TXT.
- Plan/apply split with dry runs, idempotent writes and ambiguity checks.
- Separate IPv4 and IPv6 discovery with `NoGlobalAddress` for CGNAT or private-only networks.
- `DnsProvider` trait with DNSimple and DigitalOcean implementations.
- Typed errors for auth, rate limits, ambiguity, missing addresses, network and provider failures.
- Optional encrypted token vault, byte-compatible with Grindvakt 0.x.
- Optional standalone support: the app's config file, paths, single-record sync and conflict detection.
- Per-user or service-grade private file writes on Unix and Windows.
- Android and iOS builds.
