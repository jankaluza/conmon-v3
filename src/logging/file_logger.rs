use chrono::{Datelike, Local, Timelike};

use crate::{
    error::{ConmonError, ConmonResult},
    logging::plugin::{LogPlugin, LogPluginCfg},
};

use getrandom::fill;
use nix::errno::Errno;
use nix::fcntl::{FcntlArg, OFlag, fcntl, open, openat, readlink, renameat};
use nix::libc;
use nix::sys::stat::{Mode, SFlag, fstat, fstatat, stat};
use nix::unistd::{UnlinkatFlags, geteuid, getuid, unlinkat};

use std::{
    cmp::min,
    ffi::{OsStr, OsString},
    fs::File,
    io::Write,
    os::fd::{AsFd, AsRawFd, OwnedFd, RawFd},
    os::unix::ffi::{OsStrExt, OsStringExt},
    path::{Component, Path, PathBuf},
};

use log::warn;

const TSBUFLEN: usize = 44;
/// Retries for unpredictable temporary log basenames on `EEXIST`.
const MAX_TEMP_NAME_ATTEMPTS: u32 = 8;

/// Validated, pinned directory fd used for all log sibling operations.
struct PinnedLogParent {
    fd: OwnedFd,
}

/// Temporary log file created in the pinned parent during rotation or reopen.
struct TempLogSibling {
    file: Option<File>,
    parent: PinnedLogParent,
    temp_basename: Option<OsString>,
    log_basename: OsString,
}

impl TempLogSibling {
    fn into_log_file(mut self) -> File {
        debug_assert!(
            self.temp_basename.is_none(),
            "temporary log sibling was not installed before extracting its file"
        );
        self.file.take().expect("temporary log file handle missing")
    }
}

impl Drop for TempLogSibling {
    fn drop(&mut self) {
        drop(self.file.take());
        // Unlink the directory entry if needed.
        if let Some(temp_basename) = self.temp_basename.take() {
            unlink_temp_basename(&self.parent.fd, &temp_basename);
        }
    }
}

/// A simple file-based logging plugin.
///
/// Writes all log data to the configured file path.
pub struct FileLogger {
    file: File,
    stdout_has_partial: bool,
    stderr_has_partial: bool,
    no_sync: bool,
    max_size: u64,
    global_max_size: u64,
    bytes_written: u64,
    total_bytes_written: u64,
    path: PathBuf,
    max_files: i32,
    allowlist_dirs: Option<Vec<PathBuf>>,
    opt_rotate: bool,
}

fn log_parent_and_basename(path: &Path) -> ConmonResult<(&Path, &OsStr)> {
    let base = path
        .file_name()
        .filter(|b| !b.is_empty())
        .ok_or_else(|| ConmonError::new("Log path has no basename", 1))?;
    // Basename-only paths such as `container.log` use the current directory.
    let parent = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    Ok((parent, base))
}

/// Build a sibling basename from raw `OsStr` bytes plus a suffix such as `.1`.
fn sibling_basename(base: &OsStr, suffix: &[u8]) -> OsString {
    let mut bytes = base.as_bytes().to_vec();
    bytes.extend_from_slice(suffix);
    OsString::from_vec(bytes)
}

fn dot_number_suffix(n: i32) -> Vec<u8> {
    let mut suffix = vec![b'.'];
    suffix.extend_from_slice(n.to_string().as_bytes());
    suffix
}

/// Resolve the path currently referenced by `fd` via `/proc/self/fd`.
fn fd_path(fd: &impl AsFd) -> ConmonResult<PathBuf> {
    let raw = fd.as_fd().as_raw_fd();
    let proc_fd = format!("/proc/self/fd/{raw}");
    let link = readlink(proc_fd.as_str())
        .map_err(|e| ConmonError::new(format!("Failed to read /proc/self/fd/{raw}: {e}"), 1))?;
    const DELETED_SUFFIX: &[u8] = b" (deleted)";
    let bytes = link.as_os_str().as_bytes();
    if bytes.len() >= DELETED_SUFFIX.len() && bytes.ends_with(DELETED_SUFFIX) {
        return Err(ConmonError::new(
            "File descriptor refers to an unlinked inode",
            1,
        ));
    }
    Ok(PathBuf::from(link))
}

fn is_path_in_allowlist(allowlist_dirs: &Option<Vec<PathBuf>>, canonical_path: &Path) -> bool {
    let Some(dirs) = allowlist_dirs else {
        return true; // no allowlist configured
    };
    if dirs.is_empty() {
        return true; // treat empty allowlist like no allowlist
    }

    for dir in dirs {
        // Skip empty
        if dir.as_os_str().is_empty() {
            continue;
        }
        let allowed_canon = match std::fs::canonicalize(dir) {
            Ok(p) => p,
            Err(_) => {
                // mirror C: warn and continue
                warn!("Invalid allowlist directory");
                continue;
            }
        };
        // Component-wise prefix check (safer than string prefix).
        if canonical_path.starts_with(&allowed_canon) {
            return true;
        }
    }
    false
}

fn open_path_at_nofollow(path: &Path) -> ConmonResult<OwnedFd> {
    // Walk one component at a time without following symlinks.
    let start = if path.is_absolute() { "/" } else { "." };
    let mut current = open(start, OFlag::O_PATH | OFlag::O_CLOEXEC, Mode::empty()).map_err(|e| {
        ConmonError::new(format!("Failed to open log file: {e}"), 1)
    })?;

    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                return Err(ConmonError::new("Log path contains traversal patterns", 1));
            }
            Component::Normal(name) => {
                current = openat(
                    &current,
                    name,
                    OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|e| ConmonError::new(format!("Failed to open log file: {e}"), 1))?;
            }
            Component::Prefix(_) => {
                return Err(ConmonError::new("Unsupported path prefix", 1));
            }
        }
    }

    Ok(current)
}

/// Confirm the pinned fd still refers to an allowed, owned directory.
fn validate_pinned_parent(
    parent_fd: &OwnedFd,
    allowlist_dirs: &Option<Vec<PathBuf>>,
) -> ConmonResult<()> {
    let pst = fstat(parent_fd)
        .map_err(|e| ConmonError::new(format!("Failed to stat parent directory: {e}"), 1))?;
    // Parent directory checks
    let kind = SFlag::from_bits_truncate(pst.st_mode);
    if !kind.contains(SFlag::S_IFDIR) {
        return Err(ConmonError::new("Log parent is not a directory", 1));
    }
    // Not world-writable
    if (pst.st_mode & libc::S_IWOTH) != 0 {
        return Err(ConmonError::new("Parent directory is world-writable", 1));
    }

    let uid = getuid().as_raw();
    let euid = geteuid().as_raw();
    let owner = pst.st_uid;
    // Ownership check: accept root, real uid, effective uid
    if owner != 0 && owner != uid && owner != euid {
        return Err(ConmonError::new(
            format!("Parent directory owned by unexpected UID {owner}"),
            1,
        ));
    }

    let canon_path = fd_path(parent_fd)?;
    let path_stat = stat(&canon_path)
        .map_err(|e| ConmonError::new(format!("Failed to stat pinned directory path: {e}"), 1))?;
    if path_stat.st_dev != pst.st_dev || path_stat.st_ino != pst.st_ino {
        return Err(ConmonError::new(
            "Pinned parent directory path does not match descriptor",
            1,
        ));
    }

    // Allowlist is checked once here; basename cannot escape this directory.
    if allowlist_dirs.is_some() && !is_path_in_allowlist(allowlist_dirs, &canon_path) {
        return Err(ConmonError::new("Parent directory not in allowlist", 1));
    }

    Ok(())
}

/// Open and validate the log path's parent directory.
fn open_log_parent(
    path: &Path,
    allowlist_dirs: &Option<Vec<PathBuf>>,
) -> ConmonResult<PinnedLogParent> {
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() {
        return Err(ConmonError::new("Empty log path", 1));
    }
    if bytes.len() >= libc::PATH_MAX as usize {
        return Err(ConmonError::new("Log path too long", 1));
    }

    let (parent_dir, _) = log_parent_and_basename(path)?;
    let fd = open_path_at_nofollow(parent_dir)?;
    validate_pinned_parent(&fd, allowlist_dirs)?;
    Ok(PinnedLogParent { fd })
}

/// Open was done with `O_NONBLOCK`; restore blocking I/O after validation.
fn clear_nonblock_flag(fd: &impl AsFd) -> ConmonResult<()> {
    let flags = fcntl(fd.as_fd(), FcntlArg::F_GETFL)
        .map_err(|e| ConmonError::new(format!("Failed to read log file flags: {e}"), 1))?;
    let mut oflags = OFlag::from_bits_truncate(flags);
    oflags.remove(OFlag::O_NONBLOCK);
    fcntl(fd.as_fd(), FcntlArg::F_SETFL(oflags))
        .map_err(|e| ConmonError::new(format!("Failed to clear O_NONBLOCK on log file: {e}"), 1))?;
    Ok(())
}

/// Return device/inode for an opened regular file.
fn regular_file_identity(fd: &impl AsFd) -> ConmonResult<(libc::dev_t, libc::ino_t)> {
    let st = fstat(fd.as_fd())
        .map_err(|e| ConmonError::new(format!("Failed to stat opened log file: {e}"), 1))?;
    let kind = SFlag::from_bits_truncate(st.st_mode);
    if !kind.contains(SFlag::S_IFREG) {
        return Err(ConmonError::new("Log path is not a regular file", 1));
    }
    Ok((st.st_dev, st.st_ino))
}

/// Ensure a directory entry still refers to the same inode as an opened fd.
fn verify_dir_entry_matches_fd(
    parent_fd: &OwnedFd,
    basename: &OsStr,
    fd: &impl AsFd,
) -> ConmonResult<()> {
    let (fd_dev, fd_ino) = regular_file_identity(fd)?;
    let entry_st = fstatat(
        parent_fd,
        basename,
        nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
    )
    .map_err(|e| ConmonError::new(format!("Failed to stat log directory entry: {e}"), 1))?;
    let kind = SFlag::from_bits_truncate(entry_st.st_mode);
    if !kind.contains(SFlag::S_IFREG) {
        return Err(ConmonError::new(
            "Log directory entry is not a regular file",
            1,
        ));
    }
    if fd_dev != entry_st.st_dev || fd_ino != entry_st.st_ino {
        return Err(ConmonError::new(
            "Directory entry does not match opened log file",
            1,
        ));
    }
    Ok(())
}

/// Open or create the log file relative to a pinned parent.
fn open_log_file(parent: &PinnedLogParent, basename: &OsStr, append: bool) -> ConmonResult<File> {
    // Inspect the basename through the pinned parent before opening it.
    let expected_file = match fstatat(
        &parent.fd,
        basename,
        nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
    ) {
        Ok(st) => {
            let kind = SFlag::from_bits_truncate(st.st_mode);
            if kind.contains(SFlag::S_IFLNK) {
                return Err(ConmonError::new("Log path is a symbolic link", 1));
            }
            if !kind.contains(SFlag::S_IFREG) {
                return Err(ConmonError::new("Log path is not a regular file", 1));
            }
            Some((st.st_dev, st.st_ino))
        }
        Err(Errno::ENOENT) => None,
        Err(e) => {
            return Err(ConmonError::new(
                format!("Failed to inspect log path: {e}"),
                1,
            ));
        }
    };

    let create_exclusive = expected_file.is_none();
    let mut flags = OFlag::O_WRONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC;
    if create_exclusive {
        flags |= OFlag::O_CREAT | OFlag::O_EXCL;
    } else if !append {
        flags |= OFlag::O_TRUNC;
    }
    if append {
        flags |= OFlag::O_APPEND;
    }

    let fd = openat(&parent.fd, basename, flags, Mode::from_bits_truncate(0o640))
        .map_err(|e| ConmonError::new(format!("Failed to open log file: {e}"), 1))?;

    let actual_file = regular_file_identity(&fd)?;
    // Reject TOCTOU swaps between the pre-open stat and the opened fd.
    if let Some(expected_file) = expected_file {
        if actual_file != expected_file {
            return Err(ConmonError::new("Log file changed during open", 1));
        }
    }
    clear_nonblock_flag(&fd)?;
    Ok(File::from(fd))
}

/// Generate a 128-bit unpredictable basename for a temporary log sibling.
fn unpredictable_temp_basename() -> ConmonResult<OsString> {
    let mut rnd = [0u8; 16];
    fill(&mut rnd)
        .map_err(|e| ConmonError::new(format!("Failed to generate random name: {e}"), 1))?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = b".conmon-log-".to_vec();
    for byte in rnd {
        name.push(HEX[(byte >> 4) as usize]);
        name.push(HEX[(byte & 0x0f) as usize]);
    }
    Ok(OsString::from_vec(name))
}

fn unlink_temp_basename(parent_fd: &OwnedFd, temp_basename: &OsStr) {
    // Best-effort cleanup; callers rely on RAII for error paths.
    match unlinkat(parent_fd, temp_basename, UnlinkatFlags::NoRemoveDir) {
        Ok(()) => {}
        Err(Errno::ENOENT) => {}
        Err(e) => warn!("Failed to remove temporary log file: {e}"),
    }
}

/// Create an exclusive temporary log file in the pinned parent directory.
fn create_temp_log(
    parent: PinnedLogParent,
    log_basename: OsString,
) -> ConmonResult<TempLogSibling> {
    for _ in 0..MAX_TEMP_NAME_ATTEMPTS {
        let temp_basename = unpredictable_temp_basename()?;
        let fd = match openat(
            &parent.fd,
            temp_basename.as_os_str(),
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o640),
        ) {
            Ok(fd) => fd,
            Err(Errno::EEXIST) => continue, // retry with a new random name
            Err(e) => {
                return Err(ConmonError::new(
                    format!("Failed to create temporary log file: {e}"),
                    1,
                ));
            }
        };

        if let Err(e) = verify_dir_entry_matches_fd(&parent.fd, temp_basename.as_os_str(), &fd) {
            drop(fd);
            unlink_temp_basename(&parent.fd, temp_basename.as_os_str());
            return Err(e);
        }

        return Ok(TempLogSibling {
            file: Some(File::from(fd)),
            parent,
            temp_basename: Some(temp_basename),
            log_basename,
        });
    }

    Err(ConmonError::new(
        "Failed to allocate unique temporary log name",
        1,
    ))
}

/// Rename two siblings within the same pinned parent directory.
fn renameat_sibling(parent_fd: &OwnedFd, from: &OsStr, to: &OsStr) -> ConmonResult<()> {
    renameat(parent_fd, from, parent_fd, to)
        .map_err(|e| ConmonError::new(format!("Failed to rename log sibling: {e}"), 1))
}

/// Move the active log to `.1`, install the temporary file, and restore on failure.
fn install_rotated_log(sibling: &mut TempLogSibling, backup_basename: &OsStr) -> ConmonResult<()> {
    let temp_basename = sibling
        .temp_basename
        .as_ref()
        .expect("temporary log basename missing")
        .as_os_str();
    // Re-verify immediately before changing the active log.
    verify_dir_entry_matches_fd(
        &sibling.parent.fd,
        temp_basename,
        sibling
            .file
            .as_ref()
            .expect("temporary log file handle missing"),
    )?;

    // Rename current log to .1
    renameat_sibling(
        &sibling.parent.fd,
        sibling.log_basename.as_os_str(),
        backup_basename,
    )
    .map_err(|e| ConmonError::new(format!("Failed to rotate log file: {e}"), 1))?;

    // Move new file into place
    if let Err(e) = renameat_sibling(
        &sibling.parent.fd,
        temp_basename,
        sibling.log_basename.as_os_str(),
    ) {
        warn!("Failed to move new log file into place: {e}");
        // Try to restore original file
        if let Err(e2) = renameat_sibling(
            &sibling.parent.fd,
            backup_basename,
            sibling.log_basename.as_os_str(),
        ) {
            warn!("CRITICAL: Failed to restore original log file: {e2}");
            warn!("Original log data may be in backup file");
        }
        return Err(ConmonError::new("Rotation failed", 1));
    }

    sibling.temp_basename = None; // disarm RAII cleanup after successful install
    Ok(())
}

/// Atomically replace the active log with a temporary sibling.
fn install_reopened_log(sibling: &mut TempLogSibling) -> ConmonResult<()> {
    let temp_basename = sibling
        .temp_basename
        .as_ref()
        .expect("temporary log basename missing")
        .as_os_str();
    // Re-verify immediately before changing the active log.
    verify_dir_entry_matches_fd(
        &sibling.parent.fd,
        temp_basename,
        sibling
            .file
            .as_ref()
            .expect("temporary log file handle missing"),
    )?;

    renameat_sibling(
        &sibling.parent.fd,
        temp_basename,
        sibling.log_basename.as_os_str(),
    )
    .map_err(|e| ConmonError::new(format!("Failed to move new log file into place: {e}"), 1))?;

    sibling.temp_basename = None; // disarm RAII cleanup after successful install
    Ok(())
}

/// Shift numbered backups through the pinned parent fd.
fn shift_backup_files(
    parent: &PinnedLogParent,
    log_base: &OsStr,
    max_files: i32,
) -> ConmonResult<()> {
    // Bounds checking
    if max_files <= 0 {
        return Err(ConmonError::new(
            format!("Invalid log_max_files value: {max_files}"),
            1,
        ));
    }

    let loop_start = if max_files > 1 { max_files } else { 2 };
    let mut had_errors = false;

    // Shift: .N-1 -> .N, ...
    for i in (2..=loop_start).rev() {
        let from = sibling_basename(log_base, &dot_number_suffix(i - 1));
        let to = sibling_basename(log_base, &dot_number_suffix(i));

        match renameat(&parent.fd, from.as_os_str(), &parent.fd, to.as_os_str()) {
            Ok(()) => {}
            Err(Errno::ENOENT) => {} // Ignore ENOENT
            Err(e) => {
                warn!("Failed to shift backup file {from:?} to {to:?}: {e}");
                had_errors = true;
            }
        }
    }

    if had_errors {
        warn!("Backup file shifting completed with some errors");
    }

    Ok(())
}

impl FileLogger {
    pub fn new(cfg: &LogPluginCfg) -> ConmonResult<Self> {
        if !cfg.log_labels.is_empty() {
            return Err(ConmonError::new("k8s-file doesn't support --log-label", 1));
        }
        if cfg.log_tag.is_some() {
            return Err(ConmonError::new("k8s-file doesn't support --log-tag", 1));
        }

        let parent = open_log_parent(&cfg.path, &cfg.allowlist_dirs)?;
        let (_, basename) = log_parent_and_basename(&cfg.path)?;
        // Secure open via pinned parent instead of pathname-based `OpenOptions`.
        let file = open_log_file(&parent, basename, true)?;
        let metadata = file.metadata()?;

        Ok(Self {
            file,
            stdout_has_partial: false,
            stderr_has_partial: false,
            no_sync: cfg.no_sync,
            max_size: cfg.max_size as u64,
            global_max_size: cfg.global_max_size as u64,
            bytes_written: metadata.len(),
            total_bytes_written: metadata.len(),
            path: cfg.path.clone(),
            max_files: cfg.max_files,
            allowlist_dirs: cfg.allowlist_dirs.clone(),
            opt_rotate: cfg.rotate,
        })
    }

    fn get_line_len(line_len: &mut isize, buf: &[u8], buflen: isize) -> bool {
        let mut partial = false;
        let len = buflen as usize;

        if let Some(pos) = buf[..len].iter().position(|&c| c == b'\n') {
            *line_len = (pos + 1) as isize;
        } else {
            *line_len = len as isize;
            partial = true;
        }
        partial
    }

    fn set_k8s_timestamp(buf: &mut [u8], pipename: &str) {
        let now = Local::now();
        let offset = now.offset().local_minus_utc();
        let off_sign = if offset < 0 { '-' } else { '+' };
        let off_abs = offset.abs();
        let hours = off_abs / 3600;
        let mins = (off_abs % 3600) / 60;

        // "YYYY-MM-DDTHH:MM:SS.NNNNNNNNN+01:00 stdout "
        let nsec = now.timestamp_subsec_nanos();
        let s = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:09}{}{:02}:{:02} {} ",
            now.year(),
            now.month(),
            now.day(),
            now.hour(),
            now.minute(),
            now.second(),
            nsec,
            off_sign,
            hours,
            mins,
            pipename
        );

        let bytes = s.as_bytes();
        let n = min(buf.len().saturating_sub(1), bytes.len());
        buf[..n].copy_from_slice(&bytes[..n]);
        if !buf.is_empty() {
            buf[buf.len() - 1] = 0;
        }
    }

    /// Rotates and replaces `self.file` with a new file handle.
    fn rotate(&mut self) -> ConmonResult<()> {
        // Derive basenames once and reuse the same pinned parent for the whole operation.
        let (_, log_base) = log_parent_and_basename(&self.path)?;
        let log_basename = sibling_basename(log_base, b"");
        let parent = open_log_parent(&self.path, &self.allowlist_dirs)?;

        if self.opt_rotate {
            if self.file.as_raw_fd() < 0 {
                return Err(ConmonError::new(
                    "Cannot rotate: invalid file descriptor",
                    1,
                ));
            }

            let fd = self.file.as_raw_fd();
            // Lock old fd.
            if !self.lock_fd_write(fd) {
                // Locked by other process => skip rotation.
                return Ok(());
            }

            let rotation_result: ConmonResult<TempLogSibling> = (|| {
                // Validate active log still matches its directory entry.
                verify_dir_entry_matches_fd(&parent.fd, log_basename.as_os_str(), &self.file)?;
                let backup_basename = sibling_basename(log_base, b".1");
                // Create new temporary log file with restrictive permissions.
                let mut sibling = create_temp_log(parent, log_basename)?;
                // Shift backups and rotate.
                shift_backup_files(&sibling.parent, log_base, self.max_files)?;
                install_rotated_log(&mut sibling, backup_basename.as_os_str())?;
                Ok(sibling)
            })();

            // Always unlock once; replacement happens only after success below.
            // Unlock and close the old file; drop the old File afterwards.
            self.unlock_fd(fd);
            // Replace file handle
            self.file = rotation_result?.into_log_file();
            self.bytes_written = 0;
        } else {
            // Reopen without rotation: truncate the existing log atomically.
            let mut sibling = create_temp_log(parent, log_basename)?;
            install_reopened_log(&mut sibling)?;
            self.file = sibling.into_log_file();
            self.bytes_written = 0;
        }

        Ok(())
    }

    fn lock_fd_write(&self, fd: RawFd) -> bool {
        let mut lock = libc::flock {
            l_type: libc::F_WRLCK as i16,
            l_whence: libc::SEEK_SET as i16,
            l_start: 0,
            l_len: 0,
            l_pid: 0,
        };
        unsafe { libc::fcntl(fd, libc::F_SETLK, &mut lock) != -1 }
    }

    fn unlock_fd(&self, fd: RawFd) {
        let mut unlock = libc::flock {
            l_type: libc::F_UNLCK as i16,
            l_whence: libc::SEEK_SET as i16,
            l_start: 0,
            l_len: 0,
            l_pid: 0,
        };
        unsafe {
            let _ = libc::fcntl(fd, libc::F_SETLK, &mut unlock);
        }
    }

    /// Rotates a log when configured so and next record would push us over `self.max_size`.
    fn rotate_if_needed(&mut self, bytes_to_be_written: u64) -> ConmonResult<()> {
        if self.max_size > 0
            && self.bytes_written.saturating_add(bytes_to_be_written) >= self.max_size
        {
            self.rotate()?;
        }
        Ok(())
    }
}

impl Drop for FileLogger {
    fn drop(&mut self) {
        if !self.no_sync {
            let _ = self.file.sync_all();
        }
    }
}

impl LogPlugin for FileLogger {
    fn reopen(&mut self) -> ConmonResult<()> {
        self.rotate()
    }

    fn write(&mut self, is_stdout: bool, data: &[u8]) -> ConmonResult<()> {
        // Track if we previously wrote a partial line for each stream.
        let has_partial = if is_stdout {
            self.stdout_has_partial
        } else {
            self.stderr_has_partial
        };

        let pipename = if is_stdout { "stdout" } else { "stderr" };

        let mut buf = data;
        let mut buflen = data.len() as isize;

        // Helper to map I/O errors into ConmonError.
        let map_err = |e: std::io::Error, msg: &str| ConmonError::new(format!("{msg}: {e}"), 1);

        // If we get an empty buffer and we had a partial line before, emit terminating "F\n".
        if buflen == 0 && has_partial {
            let mut tsbuf = [0u8; TSBUFLEN];
            Self::set_k8s_timestamp(&mut tsbuf, pipename);
            let ts_len = tsbuf.iter().position(|&b| b == 0).unwrap_or(tsbuf.len());

            // bytes: timestamp + "F\n"
            let bytes_to_be_written = ts_len as u64 + 2;
            if self.global_max_size > 0
                && self.total_bytes_written.saturating_add(bytes_to_be_written)
                    >= self.global_max_size
            {
                return Ok(());
            }
            self.rotate_if_needed(bytes_to_be_written)?;

            self.file
                .write_all(&tsbuf[..ts_len])
                .map_err(|e| map_err(e, "failed to write timestamp"))?;
            self.file
                .write_all(b"F\n")
                .map_err(|e| map_err(e, "failed to write terminating F-sequence"))?;
            self.file
                .flush()
                .map_err(|e| map_err(e, "failed to flush log file"))?;

            self.bytes_written = self.bytes_written.saturating_add(bytes_to_be_written);
            self.total_bytes_written = self.total_bytes_written.saturating_add(bytes_to_be_written);

            if is_stdout {
                self.stdout_has_partial = false;
            } else {
                self.stderr_has_partial = false;
            };
            return Ok(());
        }

        while buflen > 0 {
            let mut line_len: isize = 0;
            let partial = Self::get_line_len(&mut line_len, buf, buflen);

            let mut tsbuf = [0u8; TSBUFLEN];
            Self::set_k8s_timestamp(&mut tsbuf, pipename);
            let ts_len = tsbuf.iter().position(|&b| b == 0).unwrap_or(tsbuf.len());

            // timestamp + ("P " or "F ") + line + maybe extra "\n"
            let mut bytes_to_be_written: u64 = ts_len as u64 + 2 + (line_len as u64);
            if partial {
                bytes_to_be_written = bytes_to_be_written.saturating_add(1);
            }

            // Enforce global max before writing.
            if self.global_max_size > 0
                && self.total_bytes_written.saturating_add(bytes_to_be_written)
                    >= self.global_max_size
            {
                break;
            }

            // Rotate if needed before writing this record.
            self.rotate_if_needed(bytes_to_be_written)?;

            // timestamp + stream
            self.file
                .write_all(&tsbuf[..ts_len])
                .map_err(|e| map_err(e, "failed to write timestamp"))?;

            // partial ("P ") vs full ("F ") marker
            if partial {
                self.file
                    .write_all(b"P ")
                    .map_err(|e| map_err(e, "failed to write partial log tag"))?;
            } else {
                self.file
                    .write_all(b"F ")
                    .map_err(|e| map_err(e, "failed to write end log tag"))?;
            }

            // actual log bytes
            let line_slice_len = line_len as usize;
            self.file
                .write_all(&buf[..line_slice_len])
                .map_err(|e| map_err(e, "failed to write log line"))?;

            // If there was no newline in this chunk, add one
            if partial {
                self.file
                    .write_all(b"\n")
                    .map_err(|e| map_err(e, "failed to write newline for partial log"))?;
            }

            self.bytes_written = self.bytes_written.saturating_add(bytes_to_be_written);
            self.total_bytes_written = self.total_bytes_written.saturating_add(bytes_to_be_written);

            if is_stdout {
                self.stdout_has_partial = partial;
            } else {
                self.stderr_has_partial = partial;
            };

            // Advance buffer
            buf = &buf[line_slice_len..];
            buflen -= line_len;
        }

        self.file
            .flush()
            .map_err(|e| map_err(e, "failed to flush log file"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::plugin::LogPlugin;
    use nix::fcntl::AtFlags;
    use nix::sys::stat::Mode;
    use nix::unistd::mkfifo;
    use std::fs;
    use std::os::fd::FromRawFd;
    use std::os::unix::fs::symlink;
    use std::sync::{Mutex, OnceLock};

    fn base_cfg(path: PathBuf) -> LogPluginCfg {
        LogPluginCfg {
            path,
            no_sync: true,
            ..Default::default()
        }
    }

    fn dir_entry_exists(parent: &PinnedLogParent, basename: &OsStr) -> bool {
        fstatat(&parent.fd, basename, AtFlags::AT_SYMLINK_NOFOLLOW).is_ok()
    }

    /// Restore the process cwd when dropped so parallel tests do not leave a deleted directory as cwd.
    struct RestoreCwd(PathBuf);

    impl RestoreCwd {
        fn change_to(path: &Path) -> Self {
            let previous = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
            std::env::set_current_dir(path).unwrap();
            Self(previous)
        }
    }

    impl Drop for RestoreCwd {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.0);
        }
    }

    #[test]
    fn new_reports_v2_error_for_missing_log_parent() {
        let err = match FileLogger::new(&base_cfg(PathBuf::from("/not/a/path"))) {
            Err(e) => e,
            Ok(_) => panic!("expected missing log parent to be rejected"),
        };
        assert!(
            err.to_string().contains("Failed to open log file"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn open_log_parent_treats_basename_only_path_as_dot_parent() {
        let dir = tempfile::tempdir().unwrap();
        let _cwd = RestoreCwd::change_to(dir.path());
        let parent = open_log_parent(Path::new("container.log"), &None).unwrap();
        assert_eq!(
            fd_path(&parent.fd).unwrap(),
            dir.path().canonicalize().unwrap()
        );
    }

    #[test]
    fn open_path_at_nofollow_opens_absolute_parent() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("abs");
        fs::create_dir(&sub).unwrap();
        let parent = open_log_parent(&sub.join("log"), &None).unwrap();
        assert_eq!(fd_path(&parent.fd).unwrap(), sub.canonicalize().unwrap());
    }

    #[test]
    fn open_path_at_nofollow_opens_relative_parent() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("rel");
        fs::create_dir(&sub).unwrap();
        let _cwd = RestoreCwd::change_to(dir.path());
        let parent = open_log_parent(Path::new("rel/log"), &None).unwrap();
        assert_eq!(fd_path(&parent.fd).unwrap(), sub.canonicalize().unwrap());
    }

    #[test]
    fn installed_temp_sibling_clears_basename_before_into_log_file() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("install.log");
        fs::write(&log, b"x").unwrap();
        let parent = open_log_parent(&log, &None).unwrap();
        let log_basename = sibling_basename(OsStr::new("install.log"), b"");
        let mut sibling = create_temp_log(parent, log_basename).unwrap();
        install_reopened_log(&mut sibling).unwrap();
        assert!(sibling.temp_basename.is_none());
        drop(sibling.into_log_file());
    }

    #[test]
    fn new_rejects_symlink_log_basename() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.log");
        fs::write(&target, b"").unwrap();
        let link = dir.path().join("link.log");
        symlink(&target, &link).unwrap();

        let err = match FileLogger::new(&base_cfg(link)) {
            Err(e) => e,
            Ok(_) => panic!("expected symlink log path to be rejected"),
        };
        assert!(err.to_string().contains("symbolic link"), "{err}");
    }

    #[test]
    fn new_rejects_symlink_parent_component() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::create_dir(&real).unwrap();
        let link = dir.path().join("link");
        symlink(&real, &link).unwrap();
        let log = link.join("container.log");

        let err = match FileLogger::new(&base_cfg(log)) {
            Err(e) => e,
            Ok(_) => panic!("expected symlink parent to be rejected"),
        };
        assert!(err.to_string().contains("not a directory"), "{err}");
    }

    #[test]
    fn new_rejects_existing_file_outside_allowlist() {
        let dir = tempfile::tempdir().unwrap();
        let allowed = dir.path().join("allowed");
        fs::create_dir(&allowed).unwrap();
        let outside = dir.path().join("outside.log");
        fs::write(&outside, b"existing").unwrap();

        let cfg = LogPluginCfg {
            path: outside,
            allowlist_dirs: Some(vec![allowed]),
            no_sync: true,
            ..Default::default()
        };

        let err = match FileLogger::new(&cfg) {
            Err(e) => e,
            Ok(_) => panic!("expected log path outside allowlist to be rejected"),
        };
        assert!(err.to_string().contains("allowlist"), "{err}");
    }

    #[test]
    fn new_rejects_fifo_log_path() {
        let dir = tempfile::tempdir().unwrap();
        let fifo = dir.path().join("log.fifo");
        mkfifo(&fifo, Mode::from_bits_truncate(0o644)).unwrap();

        let err = match FileLogger::new(&base_cfg(fifo)) {
            Err(e) => e,
            Ok(_) => panic!("expected fifo log path to be rejected"),
        };
        assert!(err.to_string().contains("regular file"), "{err}");
    }

    #[test]
    fn new_creates_log_with_append_semantics() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("append.log");
        {
            let mut logger = FileLogger::new(&base_cfg(log.clone())).unwrap();
            logger.write(true, b"first\n").unwrap();
        }
        let size_after_first = fs::metadata(&log).unwrap().len();
        assert!(size_after_first > 0);

        {
            let mut logger = FileLogger::new(&base_cfg(log.clone())).unwrap();
            assert_eq!(logger.file.metadata().unwrap().len(), size_after_first);
            logger.write(true, b"second\n").unwrap();
        }

        let contents = fs::read(log).unwrap();
        assert!(contents.windows(5).any(|w| w == b"first"));
        assert!(contents.windows(6).any(|w| w == b"second"));
    }

    #[test]
    fn new_accepts_non_utf8_parent_path() {
        let dir = tempfile::tempdir().unwrap();
        let parent_dir = dir
            .path()
            .join(std::ffi::OsStr::from_bytes(b"parent_\xFF\xFE"));
        fs::create_dir(&parent_dir).unwrap();
        let log = parent_dir.join("test.log");

        FileLogger::new(&base_cfg(log.clone())).unwrap();
        assert!(log.is_file());
    }

    #[test]
    fn non_utf8_log_basename_rotates_with_raw_byte_backup() {
        let dir = tempfile::tempdir().unwrap();
        let log_base = OsString::from_vec(b"log_\xFF\xFE".to_vec());
        let log = dir.path().join(&log_base);
        let expected_backup = sibling_basename(log_base.as_os_str(), b".1");
        fs::write(&log, b"seed").unwrap();

        let cfg = LogPluginCfg {
            path: log.clone(),
            no_sync: true,
            rotate: true,
            max_size: 1,
            max_files: 2,
            ..Default::default()
        };
        let mut logger = FileLogger::new(&cfg).unwrap();
        logger.write(true, b"0123456789\n").unwrap();

        assert_eq!(expected_backup.as_bytes(), b"log_\xFF\xFE.1");
        assert!(dir.path().join(&expected_backup).is_file());
    }

    #[test]
    fn rotation_succeeds_and_preserves_backup() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("rotate.log");
        let cfg = LogPluginCfg {
            path: log.clone(),
            no_sync: true,
            rotate: true,
            max_size: 1,
            max_files: 2,
            ..Default::default()
        };
        let mut logger = FileLogger::new(&cfg).unwrap();
        logger.write(true, b"0123456789\n").unwrap();

        assert!(dir.path().join("rotate.log.1").exists());
        assert!(fs::metadata(&log).unwrap().len() > 0);
    }

    #[test]
    fn reopen_without_rotation_replaces_log_contents() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("reopen.log");
        fs::write(&log, b"old").unwrap();
        let cfg = LogPluginCfg {
            path: log.clone(),
            no_sync: true,
            rotate: false,
            ..Default::default()
        };
        let mut logger = FileLogger::new(&cfg).unwrap();
        logger.reopen().unwrap();
        logger.write(true, b"new\n").unwrap();
        drop(logger);

        let contents = fs::read(log).unwrap();
        assert!(!contents.windows(3).any(|w| w == b"old"));
        assert!(contents.windows(3).any(|w| w == b"new"));
    }

    #[test]
    fn temp_log_cleanup_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("cleanup.log");
        let parent = open_log_parent(&log, &None).unwrap();
        let log_basename = sibling_basename(OsStr::new("cleanup.log"), b"");
        let parent_fd = unsafe { OwnedFd::from_raw_fd(libc::dup(parent.fd.as_raw_fd())) };
        let temp = create_temp_log(parent, log_basename).unwrap();
        let temp_name = temp.temp_basename.clone().expect("temp basename");
        let check_parent = || PinnedLogParent {
            fd: unsafe { OwnedFd::from_raw_fd(libc::dup(parent_fd.as_raw_fd())) },
        };
        assert!(dir_entry_exists(&check_parent(), temp_name.as_os_str()));
        drop(temp);
        assert!(!dir_entry_exists(&check_parent(), temp_name.as_os_str()));
    }

    #[cfg(test)]
    fn open_exclusive_temp(
        parent: &PinnedLogParent,
        temp_basename: &OsStr,
    ) -> Result<OwnedFd, Errno> {
        openat(
            &parent.fd,
            temp_basename,
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o640),
        )
    }

    #[cfg(test)]
    fn create_temp_log_with_basename_sequence(
        parent: PinnedLogParent,
        log_basename: OsString,
        names: impl IntoIterator<Item = OsString>,
    ) -> ConmonResult<TempLogSibling> {
        for temp_basename in names {
            let fd = match open_exclusive_temp(&parent, temp_basename.as_os_str()) {
                Ok(fd) => fd,
                Err(Errno::EEXIST) => continue,
                Err(e) => {
                    return Err(ConmonError::new(
                        format!("Failed to create temporary log file: {e}"),
                        1,
                    ));
                }
            };

            verify_dir_entry_matches_fd(&parent.fd, temp_basename.as_os_str(), &fd)?;

            return Ok(TempLogSibling {
                file: Some(File::from(fd)),
                parent,
                temp_basename: Some(temp_basename),
                log_basename,
            });
        }

        Err(ConmonError::new(
            "Failed to allocate unique temporary log name",
            1,
        ))
    }

    #[test]
    fn exclusive_temp_create_reports_eexist_on_collision() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("exclusive.log");
        let parent = open_log_parent(&log, &None).unwrap();
        let name = unpredictable_temp_basename().unwrap();

        open_exclusive_temp(&parent, name.as_os_str()).unwrap();
        assert_eq!(
            open_exclusive_temp(&parent, name.as_os_str()).unwrap_err(),
            Errno::EEXIST
        );
    }

    #[test]
    fn create_temp_log_retries_eexist_collision() {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let _guard = LOCK.get_or_init(|| Mutex::new(())).lock().unwrap();

        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("collision.log");
        let parent = open_log_parent(&log, &None).unwrap();
        let log_basename = sibling_basename(OsStr::new("collision.log"), b"");

        let first = unpredictable_temp_basename().unwrap();
        open_exclusive_temp(&parent, first.as_os_str()).unwrap();
        let second = unpredictable_temp_basename().unwrap();

        let temp = create_temp_log_with_basename_sequence(
            PinnedLogParent {
                fd: unsafe { OwnedFd::from_raw_fd(libc::dup(parent.fd.as_raw_fd())) },
            },
            log_basename,
            [first.clone(), second],
        )
        .unwrap();

        assert_ne!(temp.temp_basename.as_ref().expect("temp basename"), &first);
        assert!(dir_entry_exists(
            &parent,
            temp.temp_basename.as_ref().unwrap().as_os_str(),
        ));
    }

    #[test]
    fn rotation_restores_original_log_on_install_failure() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("restore.log");
        fs::write(&log, b"original").unwrap();

        let parent = open_log_parent(&log, &None).unwrap();
        let log_basename = sibling_basename(OsStr::new("restore.log"), b"");
        let backup_basename = sibling_basename(OsStr::new("restore.log"), b".1");
        let sibling = create_temp_log(parent, log_basename).unwrap();

        renameat_sibling(
            &sibling.parent.fd,
            sibling.log_basename.as_os_str(),
            backup_basename.as_os_str(),
        )
        .unwrap();
        let temp_basename = sibling.temp_basename.as_ref().expect("temp basename");
        unlink_temp_basename(&sibling.parent.fd, temp_basename.as_os_str());

        let install_err = renameat_sibling(
            &sibling.parent.fd,
            temp_basename.as_os_str(),
            sibling.log_basename.as_os_str(),
        )
        .unwrap_err();
        assert!(install_err.to_string().contains("rename"), "{install_err}");

        renameat_sibling(
            &sibling.parent.fd,
            backup_basename.as_os_str(),
            sibling.log_basename.as_os_str(),
        )
        .unwrap();
        assert_eq!(fs::read(&log).unwrap(), b"original");
        assert!(!dir.path().join("restore.log.1").exists());
    }
}
