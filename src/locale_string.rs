//! Locale-dependent string conversion helpers.
//!
//! conmon-v2 relies on GLib's `g_option_context_parse` after `setlocale(LC_ALL, "")`.
//! For `G_OPTION_ARG_STRING` options (including `--log-tag`), GLib converts argv bytes
//! from the process locale encoding to UTF-8. When `LANG=C` (ASCII) and the tag contains
//! UTF-8 non-ASCII bytes, that conversion fails with:
//! `Invalid byte sequence in conversion input`.
//!
//! Rust/`clap` accept UTF-8 independently of locale, so `--log-tag` must be checked
//! explicitly (for any log driver) to preserve Podman / conmon-v2 compatibility.

use crate::error::{ConmonError, ConmonResult};
use nix::libc::{self, c_char, size_t};
use std::cell::Cell;
use std::ffi::CStr;
use std::sync::{Mutex, MutexGuard};

/// Error text matching conmon-v2 / GLib option parsing (Podman e2e asserts this substring).
pub const LOCALE_CONVERSION_ERROR: &str =
    "option parsing failed: Invalid byte sequence in conversion input";

/// Serializes locale env + `setlocale` mutations (process-global, not thread-safe).
static LOCALE_LOCK: Mutex<()> = Mutex::new(());

thread_local! {
    /// True while this thread holds [`LOCALE_LOCK`] (supports re-entrant validate calls).
    static LOCALE_LOCK_HELD: Cell<bool> = const { Cell::new(false) };
}

/// Guard that releases the locale lock and clears the thread-local held flag.
pub struct LocaleLockGuard {
    _guard: Option<MutexGuard<'static, ()>>,
}

impl Drop for LocaleLockGuard {
    fn drop(&mut self) {
        if self._guard.is_some() {
            LOCALE_LOCK_HELD.with(|h| h.set(false));
        }
    }
}

/// Lock for tests (and production validation) that mutate or read locale state.
///
/// Re-entrant on the same thread: nested calls return a no-op guard.
pub fn lock_locale_env() -> LocaleLockGuard {
    if LOCALE_LOCK_HELD.with(|h| h.get()) {
        return LocaleLockGuard { _guard: None };
    }
    let guard = LOCALE_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    LOCALE_LOCK_HELD.with(|h| h.set(true));
    LocaleLockGuard {
        _guard: Some(guard),
    }
}

fn is_utf8_codeset(codeset: &[u8]) -> bool {
    codeset.eq_ignore_ascii_case(b"UTF-8") || codeset.eq_ignore_ascii_case(b"UTF8")
}

/// Apply the environment locale, matching conmon-v2's `setlocale(LC_ALL, "")`.
///
/// Returns `true` if the locale was applied. On failure (invalid `LANG`/`LC_*`),
/// falls back to `"C"` so behavior matches a fresh conmon process (default C)
/// rather than whatever locale a prior caller left installed.
fn apply_environment_locale() {
    // SAFETY: empty string loads locale from the environment; `"C"` is always valid.
    unsafe {
        if libc::setlocale(libc::LC_ALL, c"".as_ptr()).is_null() {
            let _ = libc::setlocale(libc::LC_ALL, c"C".as_ptr());
        }
    }
}

/// Current codeset after `apply_environment_locale`, or `None` if unavailable.
fn current_codeset() -> Option<&'static [u8]> {
    // SAFETY: `nl_langinfo` returns a pointer into libc locale storage valid until
    // the next locale change. Callers hold `LOCALE_LOCK` for the conversion duration.
    unsafe {
        let ptr = libc::nl_langinfo(libc::CODESET);
        if ptr.is_null() {
            return None;
        }
        Some(CStr::from_ptr(ptr).to_bytes())
    }
}

/// Convert `input` from the process locale encoding to UTF-8 via `iconv`.
///
/// Returns `Err` on illegal sequences, incomplete input, or iconv setup failure.
fn iconv_locale_to_utf8(input: &[u8], fromcode: &[u8]) -> Result<Vec<u8>, ()> {
    let mut from = Vec::with_capacity(fromcode.len() + 1);
    from.extend_from_slice(fromcode);
    from.push(0);

    // SAFETY: `from` is NUL-terminated; `tocode` is a static C string.
    let cd = unsafe { libc::iconv_open(c"UTF-8".as_ptr(), from.as_ptr() as *const c_char) };
    if cd == (-1_isize as libc::iconv_t) {
        return Err(());
    }

    let mut in_buf = input.to_vec();
    // UTF-8 is at most 4 bytes per input byte for typical single-byte locales.
    let mut out_buf = vec![0u8; input.len().saturating_mul(4).max(16)];

    let mut inleft: size_t = in_buf.len();
    let mut outleft: size_t = out_buf.len();
    let mut inptr = in_buf.as_mut_ptr() as *mut c_char;
    let mut outptr = out_buf.as_mut_ptr() as *mut c_char;

    // SAFETY: buffers are valid, sizes match; iconv updates pointers/remaining counts.
    let n = unsafe { libc::iconv(cd, &mut inptr, &mut inleft, &mut outptr, &mut outleft) };
    // SAFETY: close the descriptor opened above.
    let _ = unsafe { libc::iconv_close(cd) };

    if n == (-1_isize as size_t) || inleft != 0 {
        return Err(());
    }

    let written = out_buf.len() - outleft;
    out_buf.truncate(written);
    Ok(out_buf)
}

/// Validate that `bytes` are a valid locale-encoded string convertible to UTF-8.
///
/// Caller must hold [`lock_locale_env`]. Mirrors GLib's `G_OPTION_ARG_STRING`
/// conversion under the process locale (after applying `LANG`/`LC_*`).
fn validate_locale_convertible_bytes_locked(bytes: &[u8]) -> ConmonResult<()> {
    apply_environment_locale();

    let Some(codeset) = current_codeset() else {
        return Err(ConmonError::new(LOCALE_CONVERSION_ERROR, 1));
    };

    // Fast path: UTF-8 locale — accept only well-formed UTF-8 (already true for `&str`).
    if is_utf8_codeset(codeset) {
        return match std::str::from_utf8(bytes) {
            Ok(_) => Ok(()),
            Err(_) => Err(ConmonError::new(LOCALE_CONVERSION_ERROR, 1)),
        };
    }

    match iconv_locale_to_utf8(bytes, codeset) {
        Ok(_) => Ok(()),
        Err(()) => Err(ConmonError::new(LOCALE_CONVERSION_ERROR, 1)),
    }
}

/// Validate a `--log-tag` value under the process locale (GLib `G_OPTION_ARG_STRING` semantics).
pub fn validate_log_tag(tag: &str) -> ConmonResult<()> {
    let _guard = lock_locale_env();
    validate_locale_convertible_bytes_locked(tag.as_bytes())
}

/// Test helper: holds the locale lock and temporarily sets `LANG` / clears `LC_*`.
///
/// Restores the previous environment (and re-applies locale) on drop. Use this
/// from any test that mutates locale-related env vars.
#[cfg(test)]
pub struct LocaleEnvGuard {
    _lock: LocaleLockGuard,
    old_lang: Option<String>,
    old_lc_all: Option<String>,
    old_lc_ctype: Option<String>,
}

#[cfg(test)]
impl LocaleEnvGuard {
    /// Set `LANG` to `lang` (or unset it when `None`), clear `LC_ALL`/`LC_CTYPE`.
    pub fn set(lang: Option<&str>) -> Self {
        use std::env;

        let lock = lock_locale_env();
        let old_lang = env::var("LANG").ok();
        let old_lc_all = env::var("LC_ALL").ok();
        let old_lc_ctype = env::var("LC_CTYPE").ok();

        match lang {
            Some(v) => unsafe {
                env::set_var("LANG", v);
                env::set_var("LC_ALL", "");
                env::remove_var("LC_CTYPE");
            },
            None => unsafe {
                env::remove_var("LANG");
                env::set_var("LC_ALL", "");
                env::remove_var("LC_CTYPE");
            },
        }

        Self {
            _lock: lock,
            old_lang,
            old_lc_all,
            old_lc_ctype,
        }
    }

    /// Like [`Self::set`], but picks an installed UTF-8 locale.
    ///
    /// Prefers `C.UTF-8` / `C.utf8` (common in minimal images), then other
    /// well-known names, then the first UTF-8 entry from `locale -a`.
    pub fn set_utf8() -> Self {
        let name = available_utf8_locale();
        Self::set(Some(&name))
    }
}

/// Return an installed UTF-8 locale name suitable for tests.
#[cfg(test)]
pub fn available_utf8_locale() -> String {
    use std::ffi::CString;
    use std::process::Command;

    const CANDIDATES: &[&str] = &["C.UTF-8", "C.utf8", "en_US.UTF-8", "en_US.utf8"];

    let _lock = lock_locale_env();

    let try_name = |name: &str| -> bool {
        let Ok(cname) = CString::new(name) else {
            return false;
        };
        // SAFETY: probe `setlocale`, then restore the previous locale string.
        unsafe {
            let prev_ptr = libc::setlocale(libc::LC_ALL, std::ptr::null());
            let prev = if prev_ptr.is_null() {
                None
            } else {
                Some(std::ffi::CStr::from_ptr(prev_ptr).to_owned())
            };
            let ok = !libc::setlocale(libc::LC_ALL, cname.as_ptr()).is_null()
                && current_codeset().is_some_and(is_utf8_codeset);
            if let Some(ref p) = prev {
                let _ = libc::setlocale(libc::LC_ALL, p.as_ptr());
            } else {
                let _ = libc::setlocale(libc::LC_ALL, c"C".as_ptr());
            }
            ok
        }
    };

    for name in CANDIDATES {
        if try_name(name) {
            return (*name).to_string();
        }
    }

    if let Ok(out) = Command::new("locale").arg("-a").output() {
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let name = line.trim();
            if name.is_empty() {
                continue;
            }
            let lower = name.to_ascii_lowercase();
            if !(lower.contains("utf8") || lower.contains("utf-8")) {
                continue;
            }
            if try_name(name) {
                return name.to_string();
            }
        }
    }

    panic!(
        "no UTF-8 locale available for tests; install e.g. C.UTF-8 (or set LANG to a UTF-8 locale)"
    );
}

#[cfg(test)]
impl Drop for LocaleEnvGuard {
    fn drop(&mut self) {
        use std::env;

        unsafe {
            match &self.old_lang {
                Some(v) => env::set_var("LANG", v),
                None => env::remove_var("LANG"),
            }
            match &self.old_lc_all {
                Some(v) => env::set_var("LC_ALL", v),
                None => env::remove_var("LC_ALL"),
            }
            match &self.old_lc_ctype {
                Some(v) => env::set_var("LC_CTYPE", v),
                None => env::remove_var("LC_CTYPE"),
            }
        }
        apply_environment_locale();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_tag_succeeds_without_lang() {
        let _env = LocaleEnvGuard::set(None);
        validate_log_tag("ascii-tag").expect("ASCII tag must be accepted");
    }

    #[test]
    fn ascii_tag_succeeds_with_c_locale() {
        let _env = LocaleEnvGuard::set(Some("C"));
        validate_log_tag("podman").expect("ASCII under C must succeed");
    }

    #[test]
    fn non_ascii_tag_fails_with_c_locale() {
        let _env = LocaleEnvGuard::set(Some("C"));
        let err = validate_log_tag("äöüß").expect_err("must fail under C");
        assert_eq!(err.code, 1);
        assert_eq!(err.msg, LOCALE_CONVERSION_ERROR);
    }

    #[test]
    fn non_ascii_tag_succeeds_with_utf8_locale() {
        let _env = LocaleEnvGuard::set_utf8();
        validate_log_tag("äöüß").expect("UTF-8 locale must accept non-ASCII");
    }

    #[test]
    fn non_ascii_tag_fails_with_invalid_locale() {
        let _env = LocaleEnvGuard::set(Some("not-a-real-locale"));
        let err = validate_log_tag("äöüß").expect_err("invalid locale must fail cleanly");
        assert_eq!(err.code, 1);
        assert_eq!(err.msg, LOCALE_CONVERSION_ERROR);
    }
}
