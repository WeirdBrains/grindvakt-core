# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions match Grindvakt app
releases one for one.

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
