//! Living next to a standalone Grindvakt (feature `standalone`).
//!
//! An app that keeps its own records current (such as a browser publishing `home.example.com`)
//! must not fight a standalone Grindvakt install that manages the same name: each would keep
//! "fixing" the other's change. [`find_conflicts`] reads the standalone app's config from its
//! default locations and reports installs that manage any of your names. It only reads; it
//! never creates files or takes locks that the app could notice.
//!
//! ```
//! use grindvakt_core::config::AppConfig;
//! use grindvakt_core::standalone::find_conflicts_in;
//!
//! let dir = tempfile::tempdir().unwrap();
//! let cfg = AppConfig { zone: "example.com".into(), name: "home".into(), ..AppConfig::default() };
//! cfg.save(&dir.path().join("config.toml")).unwrap();
//!
//! let found = find_conflicts_in(&[dir.path().to_path_buf()], &["HOME.example.com."]);
//! assert_eq!(found.len(), 1);
//! assert_eq!(found[0].fqdn, "home.example.com");
//! assert!(find_conflicts_in(&[dir.path().to_path_buf()], &["other.example.com"]).is_empty());
//! ```

use crate::config::{AppConfig, CONFIG_FILE_NAME, Provider};
use std::path::{Path, PathBuf};

/// A standalone Grindvakt install that manages one of your names.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct StandaloneInstall {
    /// Its `config.toml`.
    pub config_path: PathBuf,
    /// The name it manages, lowercase, without a trailing dot.
    pub fqdn: String,
    /// Its provider.
    pub provider: Provider,
    /// Whether a sync is running right now (its lock is held), when that can be checked.
    /// The standalone app runs on a timer, so `Some(false)` does not mean it is not installed.
    pub syncing: Option<bool>,
}

/// The directories a standalone Grindvakt keeps its config in: `~/.grindvakt` on Unix;
/// `%PROGRAMDATA%\Grindvakt` on Windows.
pub fn default_install_dirs() -> Vec<PathBuf> {
    crate::paths::default_data_dir().into_iter().collect()
}

/// [`find_conflicts_in`] over [`default_install_dirs`].
pub fn find_conflicts(fqdns: &[&str]) -> Vec<StandaloneInstall> {
    find_conflicts_in(&default_install_dirs(), fqdns)
}

/// Standalone configs in `dirs` whose record is one of `fqdns` (case-insensitive, trailing
/// dot ignored). Unreadable or invalid configs are skipped.
pub fn find_conflicts_in(dirs: &[PathBuf], fqdns: &[&str]) -> Vec<StandaloneInstall> {
    let wanted: Vec<String> = fqdns.iter().map(|f| canon(f)).collect();
    let mut out = Vec::new();
    for dir in dirs {
        let path = dir.join(CONFIG_FILE_NAME);
        let Ok(cfg) = AppConfig::load(&path) else {
            continue;
        };
        let fqdn = canon(&cfg.record_fqdn());
        if wanted.contains(&fqdn) {
            out.push(StandaloneInstall {
                config_path: path,
                syncing: sync_lock_held(&fqdn),
                fqdn,
                provider: cfg.provider,
            });
        }
    }
    out
}

fn canon(s: &str) -> String {
    s.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Whether the standalone app's `sync-<fqdn>` lock is held, without creating anything.
fn sync_lock_held(fqdn: &str) -> Option<bool> {
    let dir = crate::paths::default_lock_dir().ok()?;
    let path = dir.join(format!(
        "{}.lock",
        crate::lock::sanitize_name(&format!("sync-{fqdn}"))
    ));
    lock_held(&path)
}

fn lock_held(path: &Path) -> Option<bool> {
    use fs2::FileExt;
    let f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Some(false),
        Err(_) => return None,
    };
    match f.try_lock_shared() {
        Ok(()) => {
            let _ = FileExt::unlock(&f);
            Some(false)
        }
        Err(_) => Some(true),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_detection() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sync_x.lock");
        assert_eq!(lock_held(&p), Some(false));
        let held = crate::lock::SingleInstanceLock::acquire_at(&p).unwrap();
        assert_eq!(lock_held(&p), Some(true));
        drop(held);
        assert_eq!(lock_held(&p), Some(false));
    }
}
