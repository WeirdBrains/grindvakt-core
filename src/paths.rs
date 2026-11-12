//! Grindvakt's own default locations (feature `default-paths`).
//!
//! Embedding applications normally choose their own directory and pass explicit paths
//! everywhere; these exist so the Grindvakt app and tools that read its files agree.

#[cfg(not(windows))]
use crate::error::Error;
use crate::error::Result;
use std::path::{Path, PathBuf};

/// `~/.grindvakt` on Unix; `%PROGRAMDATA%\Grindvakt` on Windows.
pub fn default_data_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        Ok(program_data()?.join("Grindvakt"))
    }
    #[cfg(not(windows))]
    {
        Ok(home()?.join(".grindvakt"))
    }
}

/// `$XDG_RUNTIME_DIR/grindvakt`, else `<cache>/grindvakt/run` on Unix;
/// `%PROGRAMDATA%\Grindvakt\run` on Windows.
pub fn default_lock_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    {
        Ok(program_data()?.join("Grindvakt").join("run"))
    }
    #[cfg(not(windows))]
    {
        if let Ok(dir) = std::env::var("XDG_RUNTIME_DIR") {
            return Ok(Path::new(&dir).join("grindvakt"));
        }
        let base = directories::BaseDirs::new()
            .ok_or_else(|| Error::Config("cannot resolve base dirs".into()))?;
        Ok(base.cache_dir().join("grindvakt").join("run"))
    }
}

/// The config file inside `data_dir`.
pub fn config_file(data_dir: &Path) -> PathBuf {
    data_dir.join(crate::config::CONFIG_FILE_NAME)
}

/// The vault file inside `data_dir`.
pub fn vault_file(data_dir: &Path) -> PathBuf {
    data_dir.join(crate::vault::VAULT_FILE_NAME)
}

#[cfg(not(windows))]
fn home() -> Result<PathBuf> {
    directories::UserDirs::new()
        .map(|u| u.home_dir().to_path_buf())
        .ok_or_else(|| Error::Config("could not resolve home directory".into()))
}

#[cfg(windows)]
fn program_data() -> Result<PathBuf> {
    Ok(std::env::var("PROGRAMDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(r"C:\ProgramData")))
}
