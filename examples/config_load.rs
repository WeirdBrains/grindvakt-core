//! Load, validate, change and save a Grindvakt `config.toml`.
//!
//! `cargo run --example config_load [path/to/config.toml]`
//! Without a path it uses the bundled v0.7.0 fixture and writes the edited copy to a temp dir.

use grindvakt_core::config::{AppConfig, Provider, validate};
use std::path::PathBuf;

fn main() -> grindvakt_core::Result<()> {
    let path = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/v0.7.0/config.toml")
        });
    let mut cfg = AppConfig::load(&path)?;
    println!("loaded {}", path.display());
    println!("  provider: {}", cfg.provider);
    println!("  record:   {} (ttl {})", cfg.record_fqdn(), cfg.ttl);
    println!("  schedule: {:?}", cfg.schedule);

    // Edits are plain struct updates; validate before saving.
    cfg.provider = Provider::Digitalocean;
    cfg.name = "@".into();
    cfg.ttl = 600;
    assert!(validate::is_valid_record_name(&cfg.zone, &cfg.name));
    cfg.validate()?;

    let out = std::env::temp_dir().join(format!("grindvakt-core-example-{}", std::process::id()));
    let file = out.join("config.toml");
    cfg.save(&file)?; // atomic, owner-only
    println!(
        "saved edited copy to {}:\n{}",
        file.display(),
        std::fs::read_to_string(&file).unwrap()
    );
    let _ = std::fs::remove_dir_all(&out);
    Ok(())
}
