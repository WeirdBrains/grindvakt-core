//! Private directories and atomic private file writes.
//!
//! * Unix: directories `0700`, files `0600`, owned by the current user; symlinks are refused;
//!   writes go to a temp file in the same directory, are fsynced, renamed into place, and the
//!   directory is fsynced.
//! * Windows: directories get a protected DACL that allows only SYSTEM, Administrators and
//!   LocalService (`D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;LS)`), and existing
//!   directories are verified against it; reparse points are refused; writes use an exclusive
//!   temp file with the same DACL and `MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)`.
//!
//! These are the rules the Grindvakt app has always applied to `~/.grindvakt` and
//! `%PROGRAMDATA%\Grindvakt`. On Windows they assume an elevated or service context, so a
//! directory owned by an ordinary user is rejected.

macro_rules! fs_err {
    ($($t:tt)*) => { crate::fs::classify(format!($($t)*)) };
}
macro_rules! fs_bail {
    ($($t:tt)*) => { return Err(fs_err!($($t)*)) };
}

pub(crate) fn classify(msg: String) -> Error {
    const REFUSALS: [&str; 7] = [
        "refusing",
        "insecure",
        "DACL",
        "Owner",
        "unexpected SID",
        "not owned",
        "exists and is not",
    ];
    if REFUSALS.iter().any(|p| msg.contains(p)) {
        Error::InsecurePath(msg)
    } else {
        Error::io(msg, std::io::Error::other("filesystem operation failed"))
    }
}

/// Adds context to fallible filesystem calls.
trait WithContext<T> {
    fn with_context<F: FnOnce() -> String>(self, f: F) -> Result<T>;
}
impl<T> WithContext<T> for std::io::Result<T> {
    fn with_context<F: FnOnce() -> String>(self, f: F) -> Result<T> {
        self.map_err(|e| Error::io(f(), e))
    }
}
impl<T> WithContext<T> for Result<T> {
    fn with_context<F: FnOnce() -> String>(self, f: F) -> Result<T> {
        self.map_err(|e| match e {
            Error::InsecurePath(m) => Error::InsecurePath(format!("{}: {m}", f())),
            other => other,
        })
    }
}
#[cfg(unix)]
impl<T> WithContext<T> for std::result::Result<T, tempfile::PersistError> {
    fn with_context<F: FnOnce() -> String>(self, f: F) -> Result<T> {
        self.map_err(|e| Error::io(f(), e.error))
    }
}

use crate::error::{Error, Result};
#[cfg(unix)]
use std::fs::OpenOptions;
use std::fs::{self};
use std::io::Write;
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, PermissionsExt};

#[cfg(target_os = "windows")]
use std::ffi::OsStr;
#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStrExt;
#[cfg(target_os = "windows")]
use std::os::windows::fs::MetadataExt as _;
#[cfg(target_os = "windows")]
use std::os::windows::io::FromRawHandle;
#[cfg(target_os = "windows")]
use std::path::PathBuf;
#[cfg(target_os = "windows")]
use widestring::U16CString;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{BOOL, HLOCAL, LocalFree};
#[cfg(target_os = "windows")]
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetNamedSecurityInfoW, SDDL_REVISION_1,
    SE_FILE_OBJECT, SE_OBJECT_TYPE,
};
#[cfg(target_os = "windows")]
use windows::Win32::Security::{
    DACL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
};
#[cfg(target_os = "windows")]
use windows::Win32::Storage::FileSystem::{
    CREATE_NEW, CreateDirectoryW, CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_WRITE_THROUGH,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_SHARE_READ, MOVEFILE_REPLACE_EXISTING,
    MOVEFILE_WRITE_THROUGH, MoveFileExW,
};
#[cfg(target_os = "windows")]
use windows::core::PCWSTR;
#[cfg(target_os = "windows")]
struct PsdGuard {
    psd: PSECURITY_DESCRIPTOR,
}
#[cfg(target_os = "windows")]
impl Drop for PsdGuard {
    fn drop(&mut self) {
        // Safe to call with null; LocalFree is no-op for NULL
        unsafe {
            let _ = LocalFree(HLOCAL(self.psd.0));
        }
    }
}
#[cfg(target_os = "windows")]
struct TempFileGuard {
    path: Option<PathBuf>,
}
#[cfg(target_os = "windows")]
impl TempFileGuard {
    fn new(p: PathBuf) -> Self {
        Self { path: Some(p) }
    }
    fn disarm(&mut self) {
        self.path = None;
    }
}
#[cfg(target_os = "windows")]
impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(p) = self.path.take() {
            let _ = fs::remove_file(p);
        }
    }
}

/// Creates `path` (and parents) as a private directory, or checks and tightens an existing one.
#[cfg(unix)]
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    // Refuse to follow symlinks
    if path.exists() {
        let lmd =
            fs::symlink_metadata(path).with_context(|| format!("lstat {}", path.display()))?;
        if lmd.file_type().is_symlink() {
            fs_bail!("refusing to operate on symlinked path {}", path.display());
        }
        let md = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
        if !md.is_dir() {
            fs_bail!("{} exists and is not a directory", path.display());
        }
        // ownership check
        let uid = md.uid();
        if uid != unsafe { libc::geteuid() } as u32 {
            fs_bail!("{} not owned by current user", path.display());
        }
        // tighten perms if needed
        let mut perms = md.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(path, perms)
            .with_context(|| format!("chmod 0700 {}", path.display()))?;
    } else {
        fs::create_dir_all(path).with_context(|| format!("mkdir -p {}", path.display()))?;
        let md = fs::metadata(path).with_context(|| format!("stat {}", path.display()))?;
        let mut perms = md.permissions();
        perms.set_mode(0o700);
        fs::set_permissions(path, perms)
            .with_context(|| format!("chmod 0700 {}", path.display()))?;
    }
    Ok(())
}

/// Atomically replaces `dest` with `data`, owner-only, creating a private parent directory.
#[cfg(unix)]
pub fn atomic_write_private(dest: &Path, data: &[u8]) -> Result<()> {
    use tempfile::NamedTempFile;
    let parent = dest
        .parent()
        .ok_or_else(|| fs_err!("no parent for {}", dest.display()))?;
    ensure_private_dir(parent)?;
    // Refuse to write through symlink destination
    if dest.exists() {
        let lmd =
            fs::symlink_metadata(dest).with_context(|| format!("lstat {}", dest.display()))?;
        if lmd.file_type().is_symlink() {
            fs_bail!("refusing to overwrite symlink {}", dest.display());
        }
    }
    let mut tmp = NamedTempFile::new_in(parent)
        .with_context(|| format!("tempfile in {}", parent.display()))?;

    // ensure 0600 perms
    let md = tmp.as_file().metadata()?;
    let mut perms = md.permissions();
    perms.set_mode(0o600);
    tmp.as_file().set_permissions(perms)?;

    tmp.as_file_mut().write_all(data)?;
    tmp.as_file_mut().flush()?;
    tmp.as_file_mut().sync_all()?;

    // Persist atomically
    let tmp_path = tmp.path().to_path_buf();
    tmp.persist(dest)
        .with_context(|| format!("rename {} -> {}", tmp_path.display(), dest.display()))?;

    // fsync parent directory to ensure rename durability
    let dir_file = OpenOptions::new()
        .read(true)
        .open(parent)
        .with_context(|| format!("open dir {}", parent.display()))?;
    dir_file.sync_all().ok();
    Ok(())
}

/// Creates `path` (and parents) with the protected Grindvakt DACL, or verifies an existing one.
#[cfg(target_os = "windows")]
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    // Reject reparse points on the path itself
    if path.exists() {
        let md = fs::symlink_metadata(path).with_context(|| format!("lstat {}", path.display()))?;
        // On Windows, junctions/symlinks are reparse points, not always is_symlink(), so check attribute
        if (md.file_attributes() & 0x400) != 0 {
            fs_bail!("refusing to operate on reparse point {}", path.display());
        }
        if !md.is_dir() {
            fs_bail!("{} exists and is not a directory", path.display());
        }
        // Validate existing ACL is secure; fail closed if not.
        verify_secure_acl(path).with_context(|| format!("insecure ACL on {}", path.display()))?;
        return Ok(());
    }
    // Validate that no ancestor (up to root) is a reparse/junction
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        if ancestor.exists() {
            let md = fs::symlink_metadata(ancestor)
                .with_context(|| format!("lstat {}", ancestor.display()))?;
            if (md.file_attributes() & 0x400) != 0 {
                fs_bail!(
                    "refusing to operate under reparse point ancestor {}",
                    ancestor.display()
                );
            }
        }
    }
    let parent = path
        .parent()
        .ok_or_else(|| fs_err!("no parent for {}", path.display()))?;
    if !parent.exists() {
        ensure_private_dir(parent)?; // recurse upward first
    }
    // Build restrictive inheritable DACL: SYSTEM/Administrators full; LOCAL SERVICE full; no Users.
    // OI|CI to propagate to files/subdirs.
    let sddl = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;LS)";
    unsafe {
        let mut psd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR::from_raw(U16CString::from_str(sddl).unwrap().as_ptr()),
            SDDL_REVISION_1,
            &mut psd as *mut _ as *mut _,
            None,
        )
        .map_err(|e| fs_err!("ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {e}"))?;
        let _psd_guard = PsdGuard { psd };
        let sa = SECURITY_ATTRIBUTES {
            lpSecurityDescriptor: psd.0,
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            bInheritHandle: BOOL(0),
        };
        let ok2 = CreateDirectoryW(
            PCWSTR::from_raw(U16CString::from_os_str(path.as_os_str()).unwrap().as_ptr()),
            Some(&sa as *const SECURITY_ATTRIBUTES),
        );
        if let Err(e) = ok2 {
            // If already exists, that's fine; otherwise error
            if !path.exists() {
                fs_bail!("failed to create directory {}: {}", path.display(), e);
            }
        }
    }
    // Always verify target ACL after creation (or if pre-existed)
    verify_secure_acl(path).with_context(|| format!("insecure ACL on {}", path.display()))?;
    Ok(())
}

/// Atomically replaces `dest` with `data` under the protected Grindvakt DACL.
#[cfg(target_os = "windows")]
pub fn atomic_write_private(dest: &Path, data: &[u8]) -> Result<()> {
    // no direct FlushFileBuffers; use File::sync_all()

    let parent = dest
        .parent()
        .ok_or_else(|| fs_err!("no parent for {}", dest.display()))?;
    ensure_private_dir(parent)?;
    // Refuse to write through symlink/reparse destination
    if dest.exists() {
        let md = fs::symlink_metadata(dest).with_context(|| format!("lstat {}", dest.display()))?;
        #[allow(deprecated)]
        if md.file_type().is_symlink()
            || (std::os::windows::fs::MetadataExt::file_attributes(&md) & 0x400) != 0
        {
            fs_bail!("refusing to overwrite reparse/symlink {}", dest.display());
        }
    }
    // Temp file in same directory, created with exclusive CREATE_NEW and restrictive DACL
    let tmp_name = format!(".{}.tmp", uuid::Uuid::new_v4().as_simple());
    let tmp_path = parent.join(tmp_name);
    // Delegate core behavior to internal helper to ensure tests exercise identical code paths.
    atomic_write_private_with_tmp(dest, &tmp_path, data)?;
    // Verify parent directory ACL after write (handles already-exist winner case too)
    verify_secure_acl(dest.parent().unwrap())?;
    Ok(())
}

// Windows internal helper used by production and tests: perform atomic write using an explicit
// temp path within the same directory. Security descriptor, exclusive create, and guarded
// cleanup are identical to production behavior. This function does not call verify_secure_acl.
#[cfg(target_os = "windows")]
pub(crate) fn atomic_write_private_with_tmp(
    dest: &Path,
    tmp_path: &Path,
    data: &[u8],
) -> Result<()> {
    // Build restrictive inheritable DACL for temp file; allow LocalService full control for atomic replace.
    let sddl = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;LS)";
    let to_w = |s: &OsStr| -> Vec<u16> { s.encode_wide().chain(std::iter::once(0)).collect() };
    unsafe {
        let mut psd: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR::default();
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR::from_raw(U16CString::from_str(sddl).unwrap().as_ptr()),
            SDDL_REVISION_1,
            &mut psd as *mut _ as *mut _,
            None,
        )
        .map_err(|e| fs_err!("ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {e}"))?;
        let _psd_guard = PsdGuard { psd };
        let sa = SECURITY_ATTRIBUTES {
            lpSecurityDescriptor: psd.0,
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            bInheritHandle: BOOL(0),
        };
        // Ensure temp cleanup even on early errors; guard drops after file is closed (declared before file)
        let tmp_w = to_w(tmp_path.as_os_str());
        let dest_w = to_w(dest.as_os_str());
        let handle = match CreateFileW(
            PCWSTR::from_raw(tmp_w.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            FILE_SHARE_READ,
            Some(&sa as *const SECURITY_ATTRIBUTES),
            CREATE_NEW,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH,
            None,
        ) {
            Ok(h) => h,
            Err(e) => {
                fs_bail!("create tmp {}: {}", tmp_path.display(), e);
            }
        };
        let mut tmp_guard = TempFileGuard::new(tmp_path.to_path_buf());
        // Convert to std::fs::File and write
        let mut file = std::fs::File::from_raw_handle(handle.0 as _);
        if let Err(e) = (|| -> Result<()> {
            file.write_all(data)?;
            file.flush()?;
            file.sync_all()?;
            Ok(())
        })() {
            drop(file); // close before cleanup
            return Err(e);
        }
        drop(file); // ensure handle closed before rename
        // Move into place atomically
        MoveFileExW(
            PCWSTR::from_raw(tmp_w.as_ptr()),
            PCWSTR::from_raw(dest_w.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
        .map_err(|e| {
            // Best-effort cleanup happens via guard drop
            fs_err!("rename {} -> {}: {}", tmp_path.display(), dest.display(), e)
        })?;
        // Disarm cleanup guard on success
        tmp_guard.disarm();
    }
    Ok(())
}

#[cfg(target_os = "windows")]
fn verify_secure_acl(path: &Path) -> Result<()> {
    unsafe {
        let mut psecuritydescriptor: PSECURITY_DESCRIPTOR = PSECURITY_DESCRIPTOR::default();
        let status = GetNamedSecurityInfoW(
            PCWSTR::from_raw(U16CString::from_os_str(path.as_os_str()).unwrap().as_ptr()),
            SE_OBJECT_TYPE(SE_FILE_OBJECT.0),
            OBJECT_SECURITY_INFORMATION(DACL_SECURITY_INFORMATION.0 | OWNER_SECURITY_INFORMATION.0),
            None,
            None,
            None,
            None,
            &mut psecuritydescriptor as *mut _ as *mut _,
        );
        status
            .ok()
            .map_err(|e| fs_err!("GetNamedSecurityInfoW failed: {e}"))?;
        let mut sddl_ptr: windows::core::PWSTR = windows::core::PWSTR::null();
        let mut sddl_len: u32 = 0;
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            psecuritydescriptor,
            SDDL_REVISION_1,
            OBJECT_SECURITY_INFORMATION(DACL_SECURITY_INFORMATION.0 | OWNER_SECURITY_INFORMATION.0),
            &mut sddl_ptr,
            Some(&mut sddl_len),
        )
        .map_err(|e| {
            let _ = LocalFree(HLOCAL(psecuritydescriptor.0));
            fs_err!("ConvertSecurityDescriptorToStringSecurityDescriptorW failed: {e}")
        })?;
        let s = {
            let slice = std::slice::from_raw_parts(sddl_ptr.0, sddl_len as usize);
            String::from_utf16_lossy(slice)
        };
        let _ = LocalFree(HLOCAL(sddl_ptr.0 as *mut core::ffi::c_void));
        let _ = LocalFree(HLOCAL(psecuritydescriptor.0));
        // Must be protected DACL (D:P...), owner SYSTEM or Administrators, and allowlist ACEs only for SY/BA/LS.
        if !s.contains("D:P") {
            fs_bail!("DACL not protected (requires D:P): {}", s);
        }
        if !(s.contains("O:SY") || s.contains("O:BA")) {
            fs_bail!("Owner must be SYSTEM or Administrators: {}", s);
        }
        // Extract ACE entries inside D:(...)
        if let Some(d_start) = s.find("D:") {
            let d = &s[d_start + 2..];
            for seg in d.split('(').skip(1) {
                if let Some(end) = seg.find(')') {
                    let ace = &seg[..end];
                    // Expect A;...;;;SID
                    if let Some(sid) = ace.rsplit(';').next() {
                        let sid = sid.trim();
                        if !(sid == "SY" || sid == "BA" || sid == "LS") {
                            fs_bail!("unexpected SID in DACL: {}", sid);
                        }
                    }
                }
            }
        }
    }
    Ok(())
}

// Windows-only unit tests for TempFileGuard ownership and cleanup semantics.
// These tests do not touch ProgramData; they operate in an isolated temp directory
// and verify that:
//  - Creating a temp file with CREATE_NEW when a colliding path already exists does not
//    delete or modify the preexisting file (guard is only armed after successful create).
//  - When creation succeeds but an early error occurs before rename, the TempFileGuard
//    removes the temporary file on drop.
#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;
    use std::fs::{self, File};
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestTempDir {
        path: PathBuf,
    }

    impl TestTempDir {
        fn new() -> Self {
            let base = std::env::temp_dir();
            let unique = format!(
                "gv-fsutil-tests-{}-{}-{:x}",
                std::process::id(),
                uuid::Uuid::new_v4().as_simple(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            let p = base.join(unique);
            fs::create_dir_all(&p).expect("create tempdir");
            Self { path: p }
        }
        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestTempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn tempfile_collision_does_not_delete_existing() {
        let td = TestTempDir::new();
        let collide = td.path().join("collide.tmp");
        // Precreate a file with known contents
        {
            let mut f = File::create(&collide).unwrap();
            f.write_all(b"baseline").unwrap();
            f.flush().unwrap();
        }
        // Destination path (must remain untouched on temp collision)
        let dest = td.path().join("dest.bin");
        // Attempt exclusive create on the same tmp path via production helper; expect an error
        let err = super::atomic_write_private_with_tmp(&dest, &collide, b"new-bytes").unwrap_err();
        let s = fs::read_to_string(&collide).unwrap();
        assert_eq!(s, "baseline", "preexisting file must remain untouched");
        assert!(
            !dest.exists(),
            "destination must not be created/modified on temp collision"
        );
        // Also ensure the error mentions create
        assert!(
            err.to_string().contains("create tmp"),
            "expected create error, got: {err}"
        );
    }

    #[test]
    fn atomic_write_successful_replace() {
        let td = TestTempDir::new();
        let dest = td.path().join("dest.bin");
        // Precreate dest with old contents
        {
            let mut f = File::create(&dest).unwrap();
            f.write_all(b"old").unwrap();
            f.flush().unwrap();
        }
        // Choose a tmp path that does not exist
        let tmp = td.path().join(".unit-tmp-file.tmp");
        assert!(!tmp.exists());
        super::atomic_write_private_with_tmp(&dest, &tmp, b"new")
            .expect("atomic write with explicit tmp");
        // After success, tmp path should be gone (moved) and dest updated
        assert!(!tmp.exists(), "tmp path should not remain after rename");
        let s = fs::read_to_string(&dest).unwrap();
        assert_eq!(s, "new");
    }

    #[test]
    fn rename_onto_existing_directory_cleans_tmp() {
        let td = TestTempDir::new();
        let dest_dir = td.path().join("destdir");
        fs::create_dir_all(&dest_dir).unwrap();
        let tmp = td.path().join(".unit-tmp-file-2.tmp");
        assert!(dest_dir.is_dir());
        // Attempt to atomically write where destination path is a directory: expect rename error,
        // and temp file must be removed by the guard.
        let res = super::atomic_write_private_with_tmp(&dest_dir, &tmp, b"bytes");
        assert!(
            res.is_err(),
            "expected error when renaming file onto directory"
        );
        assert!(
            !tmp.exists(),
            "Temp file should be removed after failed rename"
        );
        assert!(
            dest_dir.is_dir(),
            "Destination directory must remain intact"
        );
    }
}
