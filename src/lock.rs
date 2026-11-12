//! A single-instance lock: an exclusive advisory lock on a file.
//!
//! ```
//! use grindvakt_core::lock::SingleInstanceLock;
//! let dir = tempfile::tempdir().unwrap();
//! let path = dir.path().join("sync.lock");
//! let held = SingleInstanceLock::acquire_at(&path).unwrap();
//! assert!(SingleInstanceLock::acquire_at(&path).is_err());
//! drop(held);
//! SingleInstanceLock::acquire_at(&path).unwrap();
//! ```

use crate::error::{Error, IoContext, Result};
use fs2::FileExt;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};

/// Held while alive; released on drop.
#[derive(Debug)]
pub struct SingleInstanceLock {
    file: File,
    path: PathBuf,
}

impl SingleInstanceLock {
    /// Locks `path`, creating it (owner-only on Unix) and its parent directory.
    /// Fails with [`Error::Locked`] if another holder has it.
    pub fn acquire_at(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).ctx(|| format!("mkdir -p {}", parent.display()))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path)
            .ctx(|| format!("open lock {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
        }
        file.try_lock_exclusive()
            .map_err(|_| Error::Locked(format!("lock {}", path.display())))?;
        Ok(Self {
            file,
            path: path.to_path_buf(),
        })
    }

    /// Locks `name` (sanitized) under Grindvakt's default lock directory
    /// ([`crate::paths::default_lock_dir`]).
    #[cfg(feature = "standalone")]
    #[cfg_attr(docsrs, doc(cfg(feature = "standalone")))]
    pub fn acquire(name: &str) -> Result<Self> {
        let path = crate::paths::default_lock_dir()?.join(format!("{}.lock", sanitize_name(name)));
        Self::acquire_at(&path)
    }

    /// The lock file.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for SingleInstanceLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

/// Replaces everything but ASCII letters and digits with `_`.
pub fn sanitize_name(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}
