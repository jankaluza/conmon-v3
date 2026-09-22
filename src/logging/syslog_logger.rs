use crate::{
    error::{ConmonError, ConmonResult},
    logging::plugin::{LogPlugin, LogPluginCfg},
};
use nix::libc::{self, LOG_ERR, LOG_INFO, LOG_NDELAY, LOG_PID, LOG_USER};
use std::ffi::CString;

const STDIO_BUF_SIZE: usize = 8192;

/// Logging plugin that writes container stdout/stderr lines to syslog.
pub struct SyslogLogger {
    /// Buffer for partial (not ending with newline) stdout log messages.
    stdout_buf: [u8; STDIO_BUF_SIZE],

    /// Length of valid data in `stdout_buf`.
    stdout_buf_len: usize,

    /// Buffer for partial (not ending with newline) stderr log messages.
    stderr_buf: [u8; STDIO_BUF_SIZE],

    /// Length of valid data in `stderr_buf`.
    stderr_buf_len: usize,

    /// Ident string passed to `openlog`; must outlive syslog usage.
    _ident: CString,
}

impl SyslogLogger {
    pub fn new(cfg: &LogPluginCfg) -> ConmonResult<Self> {
        if !cfg.log_labels.is_empty() {
            return Err(ConmonError::new("syslog doesn't support --log-label", 1));
        }

        let ident = Self::syslog_ident(cfg)?;
        // SAFETY: `ident` remains owned by this struct for the logger lifetime.
        // LOG_PID includes the PID; LOG_NDELAY connects immediately.
        unsafe {
            libc::openlog(ident.as_ptr(), LOG_PID | LOG_NDELAY, LOG_USER);
        }

        Ok(Self {
            stdout_buf: [0; STDIO_BUF_SIZE],
            stdout_buf_len: 0,
            stderr_buf: [0; STDIO_BUF_SIZE],
            stderr_buf_len: 0,
            _ident: ident,
        })
    }

    /// Choose the syslog identity: `--log-tag`, container name, short cuuid, or `"conmon"`.
    fn syslog_ident(cfg: &LogPluginCfg) -> ConmonResult<CString> {
        let raw = if let Some(ref tag) = cfg.log_tag {
            tag.as_str()
        } else if let Some(ref name) = cfg.name {
            name.as_str()
        } else if let Some(ref cuuid) = cfg.cuuid {
            Self::truncate_cuuid(cuuid)
        } else {
            "conmon"
        };
        CString::new(raw).map_err(|_| {
            ConmonError::new(
                format!("syslog identity contains interior NUL byte: {raw:?}"),
                1,
            )
        })
    }

    /// Parses a leading `<N>` syslog/journal priority prefix (`N` in 0..=7).
    fn parse_priority_prefix(buf: &[u8], priority: &mut i32, message_start: &mut usize) -> bool {
        if buf.len() < 3 {
            return false;
        }
        if buf[0] != b'<' || buf[2] != b'>' || !(b'0'..=b'7').contains(&buf[1]) {
            return false;
        }
        *priority = (buf[1] - b'0') as i32;
        *message_start = 3;
        true
    }

    /// Returns whether the line is partial (no newline) and sets `line_len`.
    fn get_line_len(line_len: &mut isize, buf: &[u8], buflen: isize) -> bool {
        let len = buflen as usize;
        if let Some(pos) = buf[..len].iter().position(|&c| c == b'\n') {
            *line_len = (pos + 1) as isize;
            false
        } else {
            *line_len = len as isize;
            true
        }
    }

    fn truncate_cuuid(s: &str) -> &str {
        if s.len() <= 12 {
            return s;
        }
        match s.char_indices().nth(12) {
            Some((idx, _)) => &s[..idx],
            None => s,
        }
    }

    /// Build a NUL-free C string from message bytes (trailing newline stripped).
    fn message_cstring(parts: &[&[u8]]) -> CString {
        let mut message = Vec::new();
        for part in parts {
            for &b in *part {
                message.push(if b == 0 { b'?' } else { b });
            }
        }
        while message.last() == Some(&b'\n') {
            message.pop();
        }
        // `message` has no NUL bytes, so this cannot fail.
        CString::new(message).unwrap_or_else(|_| CString::new("").unwrap())
    }

    fn emit(priority: i32, message: &CString) {
        // SAFETY: format string is a literal; message is a valid C string.
        // Never pass user data as the format string (printf-style API).
        unsafe {
            libc::syslog(priority, c"%s".as_ptr(), message.as_ptr());
        }
    }
}

impl Drop for SyslogLogger {
    fn drop(&mut self) {
        // SAFETY: pairs with openlog in `new`.
        unsafe {
            libc::closelog();
        }
    }
}

impl LogPlugin for SyslogLogger {
    fn reopen(&mut self) -> ConmonResult<()> {
        Ok(())
    }

    fn write(&mut self, is_stdout: bool, data: &[u8]) -> ConmonResult<()> {
        let (partial_buf, partial_buf_len) = if is_stdout {
            (&mut self.stdout_buf[..], &mut self.stdout_buf_len)
        } else {
            (&mut self.stderr_buf[..], &mut self.stderr_buf_len)
        };

        let default_priority = if is_stdout { LOG_INFO } else { LOG_ERR };

        let mut buf = data;
        let mut buflen = buf.len() as isize;

        while buflen > 0 || *partial_buf_len > 0 {
            let mut line_len: isize = 0;
            let partial = buflen == 0 || Self::get_line_len(&mut line_len, buf, buflen);

            // Buffer partial lines until we see a newline (or the buffer fills).
            if buflen > 0 && partial {
                let needed = line_len as usize;
                if *partial_buf_len + needed < STDIO_BUF_SIZE {
                    partial_buf[*partial_buf_len..*partial_buf_len + needed]
                        .copy_from_slice(&buf[..needed]);
                    *partial_buf_len += needed;
                    return Ok(());
                }
            }

            let mut parsed_priority = default_priority;
            let mut message_start_idx = 0usize;
            let mut actual_message_len = line_len;

            if *partial_buf_len == 0 && line_len > 0 && buflen > 0 {
                let to_parse = &buf[..line_len as usize];
                if Self::parse_priority_prefix(
                    to_parse,
                    &mut parsed_priority,
                    &mut message_start_idx,
                ) {
                    actual_message_len = line_len - message_start_idx as isize;
                } else {
                    message_start_idx = 0;
                }
            }

            let partial_part = &partial_buf[..*partial_buf_len];
            let input_part = if buflen > 0 {
                &buf[message_start_idx..message_start_idx + actual_message_len as usize]
            } else {
                &[][..]
            };
            let message = Self::message_cstring(&[partial_part, input_part]);
            Self::emit(parsed_priority, &message);

            if buflen > 0 {
                buf = &buf[line_len as usize..];
                buflen -= line_len;
            }
            *partial_buf_len = 0;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::plugin::initialize_log_plugin;

    fn cfg() -> LogPluginCfg {
        LogPluginCfg {
            cid: Some("0123456789abcdef".into()),
            cuuid: Some("0123456789abcdef0123456789abcdef".into()),
            name: Some("testctr".into()),
            ..Default::default()
        }
    }

    #[test]
    fn syslog_logger_new_rejects_labels() {
        let mut c = cfg();
        c.log_labels = vec!["FOO=bar".into()];
        match SyslogLogger::new(&c) {
            Ok(_) => panic!("labels must be rejected"),
            Err(err) => assert!(err.msg.contains("doesn't support --log-label")),
        }
    }

    #[test]
    fn syslog_logger_uses_log_tag_as_ident() {
        let mut c = cfg();
        c.log_tag = Some("mytag".into());
        let logger = SyslogLogger::new(&c).expect("create");
        assert_eq!(logger._ident.to_bytes(), b"mytag");
    }

    #[test]
    fn syslog_logger_write_and_reopen() -> ConmonResult<()> {
        let mut plugin = initialize_log_plugin("syslog", &cfg())?;
        plugin.write(true, b"hello\n")?;
        plugin.write(false, b"<3>error line\n")?;
        plugin.write(true, b"partial")?;
        plugin.write(true, b" line\n")?;
        plugin.reopen()?;
        // Drain any remaining partial buffers (mirrors main shutdown).
        plugin.write(true, b"")?;
        Ok(())
    }

    #[test]
    fn parse_priority_prefix_accepts_0_to_7() {
        let mut pri = 6;
        let mut start = 0;
        assert!(SyslogLogger::parse_priority_prefix(
            b"<3>msg\n",
            &mut pri,
            &mut start
        ));
        assert_eq!(pri, 3);
        assert_eq!(start, 3);
        assert!(!SyslogLogger::parse_priority_prefix(
            b"msg\n", &mut pri, &mut start
        ));
        assert!(!SyslogLogger::parse_priority_prefix(
            b"<9>x", &mut pri, &mut start
        ));
    }
}
