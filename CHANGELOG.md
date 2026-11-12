# Changelog

Versions match Grindvakt app releases one for one.

## 1.0.0 — 2026-11-11

First release, extracted from Grindvakt v0.7.0.

* Public IPv4 consensus, DNSimple and DigitalOcean providers behind a `DnsProvider` trait, and
  `sync_once` with dry-run support.
* Vault v1 API with no prompts (create, unlock by password or recovery phrase, change and reset
  the password, per-provider tokens). It is byte-compatible with Grindvakt 0.x vaults in both
  directions, with crypto from `weirdnet-keys` 0.1.
* Config model and TOML I/O, schedule checks, portable timing via `weirdnet-rules` cron,
  secure file writes, single-instance lock, and optional Grindvakt default paths.
