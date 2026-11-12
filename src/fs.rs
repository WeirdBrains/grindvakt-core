//! Private directories and atomic private file writes.
//!
//! Every function takes (or defaults) a [`Privacy`] that says *who* the data is private to:
//!
//! * [`Privacy::CurrentUser`] (the default, for apps and browsers that embed the crate): only
//!   the account running the process can read or write it.
//! * [`Privacy::Service`]: the rules the Grindvakt app applies to data a system service trusts.
//! * [`Privacy::ServiceAccount`]: data a Windows service running as its own virtual account
//!   (`NT SERVICE\<name>`) trusts. Grindvakt uses this from 1.2.0.
//!
//! On Unix both mean the same thing: directories `0700`, files `0600`, owned by the effective
//! user; symlinks are refused; writes go to a temp file in the same directory, are fsynced,
//! renamed into place, and the directory is fsynced.
//!
//! On Windows reparse points are refused, writes use an exclusive temp file and
//! `MoveFileExW(REPLACE_EXISTING | WRITE_THROUGH)`, and the DACL depends on the policy:
//!
//! | Policy | Directory DACL (protected, inherited by files) | Accepted owners |
//! |---|---|---|
//! | `CurrentUser` | current user, SYSTEM (`D:P(A;OICI;FA;;;<you>)(A;OICI;FA;;;SY)`) | you, SYSTEM, Administrators |
//! | `Service` | SYSTEM, Administrators, LocalService (`D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;LS)`) | SYSTEM, Administrators |
//! | `ServiceAccount(name)` | SYSTEM, Administrators, `NT SERVICE\<name>` (`D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;S-1-5-80-…)`) | SYSTEM, Administrators, `NT SERVICE\<name>` |
//!
//! An existing directory that fails the check is tightened when the policy is `CurrentUser` or
//! `ServiceAccount` and its owner is one the policy accepts (like `chmod 0700` on Unix);
//! otherwise it is refused with [`Error::InsecurePath`]. The service policies never trust a
//! directory an ordinary user owns, because a service must not trust files that user can swap.
//!
//! [`repair_private_tree`] re-applies a policy to an existing directory and everything in it, for
//! example to move a service's data from `Service` to `ServiceAccount` during an upgrade.

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

/// Who a private directory or file is private to. See the [module docs](self).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Privacy {
    /// Only the account running this process (plus SYSTEM on Windows). The default.
    #[default]
    CurrentUser,
    /// Data a system service trusts: on Windows, SYSTEM / Administrators / LocalService only,
    /// owned by SYSTEM or Administrators. Needs an elevated or service context on Windows.
    Service,
    /// Data a Windows service running as its virtual account `NT SERVICE\<name>` trusts:
    /// SYSTEM, Administrators and that account only (see [`service_sid`]), owned by one of them.
    /// Needs an elevated context or that service on Windows. On Unix it is the same as the others.
    ServiceAccount(&'static str),
}

/// The SID of the Windows virtual service account `NT SERVICE\<name>`, as Windows derives it:
/// `S-1-5-80-` followed by the SHA-1 of the upper-cased service name in UTF-16LE, read as five
/// little-endian 32-bit numbers. It exists whether or not the service is installed, so data can be
/// prepared for the account before the service is created. Available on every platform.
pub fn service_sid(name: &str) -> String {
    let bytes: Vec<u8> = name
        .to_uppercase()
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let h = sha1(&bytes);
    let parts: Vec<String> = h
        .chunks(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]).to_string())
        .collect();
    format!("S-1-5-80-{}", parts.join("-"))
}

/// SHA-1 (FIPS 180-4). Only used to derive service SIDs, which Windows defines with SHA-1.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];
    let mut msg = data.to_vec();
    let bit_len = (data.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for block in msg.chunks(64) {
        let mut w = [0u32; 80];
        for (i, c) in block.chunks(4).enumerate() {
            w[i] = u32::from_be_bytes([c[0], c[1], c[2], c[3]]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A827999),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (x, y) in h.iter_mut().zip([a, b, c, d, e]) {
            *x = x.wrapping_add(y);
        }
    }
    let mut out = [0u8; 20];
    for (i, x) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&x.to_be_bytes());
    }
    out
}

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

/// Creates `path` (and parents) as a directory private to the current user, or checks and
/// tightens an existing one. Same as [`ensure_private_dir_with`] with [`Privacy::CurrentUser`].
pub fn ensure_private_dir(path: &Path) -> Result<()> {
    ensure_private_dir_with(path, Privacy::CurrentUser)
}

/// Atomically replaces `dest` with `data`, private to the current user, creating a private
/// parent directory. Same as [`atomic_write_private_with`] with [`Privacy::CurrentUser`].
pub fn atomic_write_private(dest: &Path, data: &[u8]) -> Result<()> {
    atomic_write_private_with(dest, data, Privacy::CurrentUser)
}

/// Creates `path` (and parents) as a private directory under `privacy`, or checks (and where
/// allowed tightens) an existing one.
#[cfg(unix)]
pub fn ensure_private_dir_with(path: &Path, _privacy: Privacy) -> Result<()> {
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

/// Re-applies `privacy` to an existing directory tree: every directory gets the private
/// directory permissions and every file the private file permissions. Symlinks (reparse points
/// on Windows) anywhere in the tree are refused. A missing `path` is not an error. Returns the
/// number of entries visited.
///
/// On Unix every entry must be owned by the effective user; directories become `0700` and files
/// `0600`. On Windows the tree's root must be owned by an owner the policy accepts; each entry
/// gets the policy's protected DACL, and an entry owned by anyone else (for example LocalService,
/// which owned files a pre-1.2 Grindvakt service created) is given to Administrators. Run it
/// elevated (or as SYSTEM) on Windows.
#[cfg(unix)]
pub fn repair_private_tree(path: &Path, _privacy: Privacy) -> Result<usize> {
    fn walk(p: &Path, n: &mut usize) -> Result<()> {
        let md = fs::symlink_metadata(p).with_context(|| format!("lstat {}", p.display()))?;
        if md.file_type().is_symlink() {
            fs_bail!("refusing to operate on symlinked path {}", p.display());
        }
        if md.uid() != unsafe { libc::geteuid() } as u32 {
            fs_bail!("{} not owned by current user", p.display());
        }
        let mode = if md.is_dir() { 0o700 } else { 0o600 };
        fs::set_permissions(p, fs::Permissions::from_mode(mode))
            .with_context(|| format!("chmod {mode:o} {}", p.display()))?;
        *n += 1;
        if md.is_dir() {
            for e in fs::read_dir(p).with_context(|| format!("read {}", p.display()))? {
                let e = e.with_context(|| format!("read {}", p.display()))?;
                walk(&e.path(), n)?;
            }
        }
        Ok(())
    }
    let Ok(md) = fs::symlink_metadata(path) else {
        return Ok(0);
    };
    if !md.is_dir() && !md.file_type().is_symlink() {
        fs_bail!("{} exists and is not a directory", path.display());
    }
    let mut n = 0;
    walk(path, &mut n)?;
    Ok(n)
}

/// Atomically replaces `dest` with `data` under `privacy`, creating a private parent directory.
#[cfg(unix)]
pub fn atomic_write_private_with(dest: &Path, data: &[u8], privacy: Privacy) -> Result<()> {
    use tempfile::NamedTempFile;
    let parent = dest
        .parent()
        .ok_or_else(|| fs_err!("no parent for {}", dest.display()))?;
    ensure_private_dir_with(parent, privacy)?;
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

/// What a [`Privacy`] means on Windows for this process.
#[cfg(target_os = "windows")]
pub(crate) struct Policy {
    privacy: Privacy,
    /// The current user's SID in canonical SDDL form (an alias such as `LA` when one exists).
    user: String,
    /// The virtual service account's SID for [`Privacy::ServiceAccount`].
    service: String,
}

#[cfg(target_os = "windows")]
impl Policy {
    pub(crate) fn new(privacy: Privacy) -> Result<Self> {
        Ok(Self {
            privacy,
            user: current_user_sddl()?,
            service: match privacy {
                Privacy::ServiceAccount(name) => service_sid(name),
                _ => String::new(),
            },
        })
    }
    fn trustees(&self) -> Vec<&str> {
        match self.privacy {
            Privacy::Service => vec!["SY", "BA", "LS"],
            Privacy::ServiceAccount(_) => vec!["SY", "BA", self.service.as_str()],
            Privacy::CurrentUser => vec![self.user.as_str(), "SY"],
        }
    }
    fn owners(&self) -> Vec<&str> {
        match self.privacy {
            Privacy::Service => vec!["SY", "BA"],
            Privacy::ServiceAccount(_) => vec!["SY", "BA", self.service.as_str()],
            Privacy::CurrentUser => vec![self.user.as_str(), "SY", "BA"],
        }
    }
    /// Whether an existing directory with an accepted owner may be tightened to the policy.
    fn tightens(&self) -> bool {
        matches!(
            self.privacy,
            Privacy::CurrentUser | Privacy::ServiceAccount(_)
        )
    }
    fn dir_sddl(&self) -> String {
        let aces: String = self
            .trustees()
            .iter()
            .map(|t| format!("(A;OICI;FA;;;{t})"))
            .collect();
        format!("D:P{aces}")
    }
    pub(crate) fn file_sddl(&self) -> String {
        let aces: String = self
            .trustees()
            .iter()
            .map(|t| format!("(A;;FA;;;{t})"))
            .collect();
        format!("D:P{aces}")
    }
}

/// A security descriptor parsed from SDDL, freed on drop.
#[cfg(target_os = "windows")]
fn sd_from_sddl(sddl: &str) -> Result<PsdGuard> {
    let w = U16CString::from_str(sddl).map_err(|_| fs_err!("bad SDDL string"))?;
    let mut psd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR::from_raw(w.as_ptr()),
            SDDL_REVISION_1,
            &mut psd as *mut _ as *mut _,
            None,
        )
        .map_err(|e| fs_err!("ConvertStringSecurityDescriptorToSecurityDescriptorW failed: {e}"))?;
    }
    Ok(PsdGuard { psd })
}

/// SDDL text for the owner and DACL of `psd`, without the trailing NUL.
#[cfg(target_os = "windows")]
unsafe fn sddl_of(psd: PSECURITY_DESCRIPTOR, info: OBJECT_SECURITY_INFORMATION) -> Result<String> {
    let mut sddl_ptr = windows::core::PWSTR::null();
    let mut sddl_len: u32 = 0;
    unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            psd,
            SDDL_REVISION_1,
            info,
            &mut sddl_ptr,
            Some(&mut sddl_len),
        )
        .map_err(|e| fs_err!("ConvertSecurityDescriptorToStringSecurityDescriptorW failed: {e}"))?;
        let slice = std::slice::from_raw_parts(sddl_ptr.0, sddl_len as usize);
        let s = String::from_utf16_lossy(slice);
        let _ = LocalFree(HLOCAL(sddl_ptr.0 as *mut core::ffi::c_void));
        Ok(s.trim_end_matches('\0').to_string())
    }
}

/// The current process user's SID as SDDL shows it in an owner field.
#[cfg(target_os = "windows")]
fn current_user_sddl() -> Result<String> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser};
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .map_err(|e| fs_err!("OpenProcessToken failed: {e}"))?;
        let mut len = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut len);
        let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
        let got = GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut core::ffi::c_void),
            len,
            &mut len,
        );
        let _ = CloseHandle(token);
        got.map_err(|e| fs_err!("GetTokenInformation failed: {e}"))?;
        let tu = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut p = windows::core::PWSTR::null();
        ConvertSidToStringSidW(tu.User.Sid, &mut p)
            .map_err(|e| fs_err!("ConvertSidToStringSidW failed: {e}"))?;
        let sid = p.to_string().map_err(|_| fs_err!("SID is not UTF-16"));
        let _ = LocalFree(HLOCAL(p.0 as *mut core::ffi::c_void));
        let sid = sid?;
        // Round-trip through a descriptor so the text matches what GetNamedSecurityInfoW reports
        // (well-known accounts come back as aliases such as `LA` or `SY`).
        let sd = sd_from_sddl(&format!("O:{sid}"))?;
        let canon = sddl_of(sd.psd, OWNER_SECURITY_INFORMATION)?;
        Ok(canon.strip_prefix("O:").unwrap_or(&canon).to_string())
    }
}

/// Owner and DACL of `path` as SDDL text.
#[cfg(target_os = "windows")]
pub(crate) fn read_sddl(path: &Path) -> Result<String> {
    let w = U16CString::from_os_str(path.as_os_str()).map_err(|_| fs_err!("bad path"))?;
    let info =
        OBJECT_SECURITY_INFORMATION(DACL_SECURITY_INFORMATION.0 | OWNER_SECURITY_INFORMATION.0);
    unsafe {
        let mut psd = PSECURITY_DESCRIPTOR::default();
        GetNamedSecurityInfoW(
            PCWSTR::from_raw(w.as_ptr()),
            SE_OBJECT_TYPE(SE_FILE_OBJECT.0),
            info,
            None,
            None,
            None,
            None,
            &mut psd as *mut _ as *mut _,
        )
        .ok()
        .map_err(|e| fs_err!("GetNamedSecurityInfoW failed: {e}"))?;
        let guard = PsdGuard { psd };
        sddl_of(guard.psd, info)
    }
}

/// Replaces the DACL on `path` with the policy's protected directory DACL.
#[cfg(target_os = "windows")]
fn apply_dir_dacl(path: &Path, pol: &Policy) -> Result<()> {
    apply_sddl(path, &pol.dir_sddl(), None)
}

/// Sets the DACL of `path` to `sddl` (protected) and, when `owner` is set (an SDDL owner such
/// as `BA`), its owner too.
#[cfg(target_os = "windows")]
fn apply_sddl(path: &Path, sddl: &str, owner: Option<&str>) -> Result<()> {
    use windows::Win32::Security::Authorization::SetNamedSecurityInfoW;
    use windows::Win32::Security::{
        ACL, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner,
        PROTECTED_DACL_SECURITY_INFORMATION, PSID,
    };
    let full = match owner {
        Some(o) => format!("O:{o}{sddl}"),
        None => sddl.to_string(),
    };
    let sd = sd_from_sddl(&full)?;
    let w = U16CString::from_os_str(path.as_os_str()).map_err(|_| fs_err!("bad path"))?;
    unsafe {
        let mut present = BOOL(0);
        let mut defaulted = BOOL(0);
        let mut dacl: *mut ACL = std::ptr::null_mut();
        GetSecurityDescriptorDacl(sd.psd, &mut present, &mut dacl, &mut defaulted)
            .map_err(|e| fs_err!("GetSecurityDescriptorDacl failed: {e}"))?;
        let mut owner_sid = PSID::default();
        let mut info = DACL_SECURITY_INFORMATION.0 | PROTECTED_DACL_SECURITY_INFORMATION.0;
        if owner.is_some() {
            GetSecurityDescriptorOwner(sd.psd, &mut owner_sid, &mut defaulted)
                .map_err(|e| fs_err!("GetSecurityDescriptorOwner failed: {e}"))?;
            info |= OWNER_SECURITY_INFORMATION.0;
        }
        SetNamedSecurityInfoW(
            PCWSTR::from_raw(w.as_ptr()),
            SE_FILE_OBJECT,
            OBJECT_SECURITY_INFORMATION(info),
            owner_sid,
            PSID::default(),
            Some(dacl as *const ACL),
            None,
        )
        .ok()
        .map_err(|e| fs_err!("SetNamedSecurityInfoW failed on {}: {e}", path.display()))?;
    }
    Ok(())
}

/// Re-applies `privacy` to an existing directory tree. See the Unix version for the contract.
#[cfg(target_os = "windows")]
pub fn repair_private_tree(path: &Path, privacy: Privacy) -> Result<usize> {
    fn walk(p: &Path, pol: &Policy, n: &mut usize) -> Result<()> {
        let md = fs::symlink_metadata(p).with_context(|| format!("lstat {}", p.display()))?;
        if (md.file_attributes() & 0x400) != 0 {
            fs_bail!("refusing to operate on reparse point {}", p.display());
        }
        let cur = read_sddl(p)?;
        let owner = sddl_owner(&cur).unwrap_or("");
        let new_owner = (!pol.owners().contains(&owner)).then_some("BA");
        let sddl = if md.is_dir() {
            pol.dir_sddl()
        } else {
            pol.file_sddl()
        };
        apply_sddl(p, &sddl, new_owner)?;
        *n += 1;
        if md.is_dir() {
            for e in fs::read_dir(p).with_context(|| format!("read {}", p.display()))? {
                let e = e.with_context(|| format!("read {}", p.display()))?;
                walk(&e.path(), pol, n)?;
            }
        }
        Ok(())
    }
    let Ok(md) = fs::symlink_metadata(path) else {
        return Ok(0);
    };
    if (md.file_attributes() & 0x400) != 0 {
        fs_bail!("refusing to operate on reparse point {}", path.display());
    }
    if !md.is_dir() {
        fs_bail!("{} exists and is not a directory", path.display());
    }
    let pol = Policy::new(privacy)?;
    let s = read_sddl(path)?;
    let owner = sddl_owner(&s).unwrap_or("");
    if !pol.owners().contains(&owner) {
        fs_bail!(
            "insecure: {} is owned by {owner}, not {}; refusing to repair it",
            path.display(),
            pol.owners().join(", ")
        );
    }
    let mut n = 0;
    walk(path, &pol, &mut n)?;
    verify_secure_acl(path, &pol).with_context(|| format!("insecure ACL on {}", path.display()))?;
    Ok(n)
}

/// Owner field of an SDDL string such as `O:SYD:P(...)`.
#[cfg(target_os = "windows")]
fn sddl_owner(s: &str) -> Option<&str> {
    let rest = s.strip_prefix("O:")?;
    let end = rest
        .find("G:")
        .or_else(|| rest.find("D:"))
        .unwrap_or(rest.len());
    Some(&rest[..end])
}

/// Creates `path` (and parents) with the policy's protected DACL, or verifies (and for
/// [`Privacy::CurrentUser`] tightens) an existing directory.
#[cfg(target_os = "windows")]
pub fn ensure_private_dir_with(path: &Path, privacy: Privacy) -> Result<()> {
    let pol = Policy::new(privacy)?;
    ensure_dir_policy(path, &pol)
}

#[cfg(target_os = "windows")]
fn ensure_dir_policy(path: &Path, pol: &Policy) -> Result<()> {
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
        return verify_or_tighten(path, pol);
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
        ensure_dir_policy(parent, pol)?; // recurse upward first
    }
    // Protected, inheritable (OI|CI) DACL for the policy's trustees only.
    let sd = sd_from_sddl(&pol.dir_sddl())?;
    let sa = SECURITY_ATTRIBUTES {
        lpSecurityDescriptor: sd.psd.0,
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        bInheritHandle: BOOL(0),
    };
    let w = U16CString::from_os_str(path.as_os_str()).map_err(|_| fs_err!("bad path"))?;
    if let Err(e) = unsafe {
        CreateDirectoryW(
            PCWSTR::from_raw(w.as_ptr()),
            Some(&sa as *const SECURITY_ATTRIBUTES),
        )
    } {
        // If already exists (a racing creator), it is verified below; otherwise error
        if !path.exists() {
            fs_bail!("failed to create directory {}: {}", path.display(), e);
        }
    }
    // Always verify target ACL after creation (or if a racer created it)
    verify_secure_acl(path, pol).with_context(|| format!("insecure ACL on {}", path.display()))
}

#[cfg(target_os = "windows")]
fn verify_or_tighten(path: &Path, pol: &Policy) -> Result<()> {
    match verify_secure_acl(path, pol) {
        Ok(()) => Ok(()),
        Err(Error::InsecurePath(_))
            if pol.tightens()
                && read_sddl(path)
                    .ok()
                    .as_deref()
                    .and_then(sddl_owner)
                    .is_some_and(|o| pol.owners().contains(&o)) =>
        {
            apply_dir_dacl(path, pol)?;
            verify_secure_acl(path, pol)
                .with_context(|| format!("insecure ACL on {}", path.display()))
        }
        Err(e) => Err(e).with_context(|| format!("insecure ACL on {}", path.display())),
    }
}

/// Atomically replaces `dest` with `data` under `privacy`'s protected DACL.
#[cfg(target_os = "windows")]
pub fn atomic_write_private_with(dest: &Path, data: &[u8], privacy: Privacy) -> Result<()> {
    let pol = Policy::new(privacy)?;
    let parent = dest
        .parent()
        .ok_or_else(|| fs_err!("no parent for {}", dest.display()))?;
    ensure_dir_policy(parent, &pol)?;
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
    atomic_write_private_with_tmp(dest, &tmp_path, data, &pol.file_sddl())?;
    // Verify parent directory ACL after write (handles already-exist winner case too)
    verify_secure_acl(parent, &pol)
}

// Windows internal helper used by production and tests: perform atomic write using an explicit
// temp path within the same directory and the given file SDDL. Exclusive create and guarded
// cleanup are identical to production behavior. This function does not call verify_secure_acl.
#[cfg(target_os = "windows")]
pub(crate) fn atomic_write_private_with_tmp(
    dest: &Path,
    tmp_path: &Path,
    data: &[u8],
    file_sddl: &str,
) -> Result<()> {
    let to_w = |s: &OsStr| -> Vec<u16> { s.encode_wide().chain(std::iter::once(0)).collect() };
    let sd = sd_from_sddl(file_sddl)?;
    let sa = SECURITY_ATTRIBUTES {
        lpSecurityDescriptor: sd.psd.0,
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        bInheritHandle: BOOL(0),
    };
    let tmp_w = to_w(tmp_path.as_os_str());
    let dest_w = to_w(dest.as_os_str());
    unsafe {
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
        // Armed only after our exclusive create succeeded, so a collision never deletes a file.
        let mut tmp_guard = TempFileGuard::new(tmp_path.to_path_buf());
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
        MoveFileExW(
            PCWSTR::from_raw(tmp_w.as_ptr()),
            PCWSTR::from_raw(dest_w.as_ptr()),
            MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
        )
        .map_err(|e| fs_err!("rename {} -> {}: {}", tmp_path.display(), dest.display(), e))?;
        tmp_guard.disarm();
    }
    Ok(())
}

/// Checks that `path` has a protected DACL naming only the policy's trustees and an accepted owner.
#[cfg(target_os = "windows")]
pub(crate) fn verify_secure_acl(path: &Path, pol: &Policy) -> Result<()> {
    let s = read_sddl(path)?;
    if !s.contains("D:P") {
        fs_bail!("DACL not protected (requires D:P): {}", s);
    }
    let owner = sddl_owner(&s).unwrap_or("");
    if !pol.owners().contains(&owner) {
        fs_bail!(
            "Owner {} not allowed (allowed: {}): {}",
            owner,
            pol.owners().join(", "),
            s
        );
    }
    if let Some(d_start) = s.find("D:") {
        let trustees = pol.trustees();
        for seg in s[d_start + 2..].split('(').skip(1) {
            if let Some(end) = seg.find(')')
                && let Some(sid) = seg[..end].rsplit(';').next()
                && !trustees.contains(&sid.trim())
            {
                fs_bail!("unexpected SID in DACL: {}", sid.trim());
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

    fn test_sddl() -> String {
        super::Policy::new(Privacy::CurrentUser)
            .unwrap()
            .file_sddl()
    }

    #[test]
    fn current_user_dir_is_created_private_and_verifies() {
        let td = TestTempDir::new();
        let d = td.path().join("a").join("b");
        super::ensure_private_dir_with(&d, Privacy::CurrentUser).unwrap();
        let pol = super::Policy::new(Privacy::CurrentUser).unwrap();
        super::verify_secure_acl(&d, &pol).unwrap();
        let sd = super::read_sddl(&d).unwrap();
        assert!(
            !sd.contains(";;;WD)") && !sd.contains(";;;BU)") && !sd.contains(";;;AU)"),
            "{sd}"
        );
        super::atomic_write_private_with(&d.join("f"), b"x", Privacy::CurrentUser).unwrap();
        assert_eq!(fs::read(d.join("f")).unwrap(), b"x");
    }

    #[test]
    fn current_user_tightens_own_plain_dir() {
        let td = TestTempDir::new();
        let d = td.path().join("plain");
        fs::create_dir_all(&d).unwrap();
        // A plain directory inherits a broad DACL from %TEMP%; the owner may tighten it.
        super::ensure_private_dir_with(&d, Privacy::CurrentUser).unwrap();
        let pol = super::Policy::new(Privacy::CurrentUser).unwrap();
        super::verify_secure_acl(&d, &pol).unwrap();
    }

    #[test]
    fn sddl_text_has_no_trailing_nul() {
        let td = TestTempDir::new();
        let sd = super::read_sddl(td.path()).unwrap();
        assert!(!sd.contains('\0'));
    }

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
        let err = super::atomic_write_private_with_tmp(&dest, &collide, b"new-bytes", &test_sddl())
            .unwrap_err();
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
        super::atomic_write_private_with_tmp(&dest, &tmp, b"new", &test_sddl())
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
        let res = super::atomic_write_private_with_tmp(&dest_dir, &tmp, b"bytes", &test_sddl());
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

#[cfg(test)]
mod sid_tests {
    use super::*;

    #[test]
    fn sha1_matches_known_vectors() {
        let hex = |b: [u8; 20]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        assert_eq!(hex(sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        assert_eq!(
            hex(sha1(&[b'a'; 1000])),
            "291e9a6c66994949b57ba5e650361e98fc36b1ba"
        );
    }

    #[test]
    fn service_sid_matches_windows() {
        // Well-known: NT SERVICE\TrustedInstaller.
        assert_eq!(
            service_sid("TrustedInstaller"),
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        );
        assert_eq!(
            service_sid("trustedinstaller"),
            service_sid("TrustedInstaller")
        );
    }
}
