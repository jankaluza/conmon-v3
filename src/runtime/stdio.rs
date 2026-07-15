use crate::{
    error::{ConmonError, ConmonResult},
    logging::plugin::LogPlugin,
    unix_socket::{RemoteSocket, Socket, SocketType, UnixSocket},
};

use nix::{
    cmsg_space,
    errno::Errno,
    fcntl::OFlag,
    libc::{SHUT_RD, shutdown},
    poll::{PollFd, PollFlags, poll},
    sys::socket::{ControlMessageOwned, MsgFlags, SockaddrStorage, recvmsg},
    sys::wait::{Id, WaitPidFlag, WaitStatus, waitid},
    unistd::{Pid, pipe2, read},
};

use std::{
    io::{self, IoSliceMut},
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
    path::PathBuf,
    time::{Duration, Instant},
};

use log::{debug, info};

/// Maximum time to wait for the runtime to connect on `--console-socket` and send the pty fd.
const CONSOLE_SOCKET_WAIT_TIMEOUT: Duration = Duration::from_secs(60);
const CONSOLE_SOCKET_POLL_INTERVAL: Duration = Duration::from_millis(500);
/// Max SCM_RIGHTS descriptors accepted in one `recvmsg`.
const MAX_SCM_RIGHTS_FDS: usize = 4;

/// Creates new pipe and return read/write fds.
///
/// # Returns
///
/// * (read_fd, write_wf)
///
/// # Errors
///
/// * [`ConmonError`] on any error.
pub fn create_pipe() -> ConmonResult<(OwnedFd, OwnedFd)> {
    let (rfd, wfd) = pipe2(OFlag::O_CLOEXEC).map_err(|e| {
        ConmonError::new(
            format!(
                "Failed to create pipe: {}",
                io::Error::from_raw_os_error(e as i32)
            ),
            1,
        )
    })?;

    Ok((rfd, wfd))
}

/// Reads data from fd and stores them in the buffer.
/// # Returns
///
/// * Number of bytes read.
///
/// # Arguments
///
/// * `fd` - The file descriptor to read the data from.
/// * `buf` - The buffer to write the data into.
///
/// # Errors
///
/// * [`ConmonError`] on any error.
pub fn read_pipe(fd: &OwnedFd, buf: &mut [u8]) -> ConmonResult<usize> {
    loop {
        match read(fd, buf) {
            Ok(n) => return Ok(n),
            Err(Errno::EINTR) | Err(Errno::EAGAIN) => continue,
            Err(e) => {
                return Err(ConmonError::new(
                    format!("read() failed while reading pipe: {e}"),
                    1,
                ));
            }
        }
    }
}

/// Result of the `recv_data_and_fds` function.
struct RecvResult {
    n: usize,
    /// Owned SCM_RIGHTS descriptors (at most [`MAX_SCM_RIGHTS_FDS`]).
    fds: Vec<OwnedFd>,
}

/// Receives data and SCM_RIGHTS file descriptors. Every received FD is wrapped
/// in [`OwnedFd`] immediately so unused extras cannot leak.
fn recv_data_and_fds(fd: RawFd, buf: &mut [u8]) -> nix::Result<RecvResult> {
    let mut iov = [IoSliceMut::new(buf)];
    let mut cmsgspace = cmsg_space!([RawFd; MAX_SCM_RIGHTS_FDS]);

    let msg = recvmsg::<SockaddrStorage>(fd, &mut iov, Some(&mut cmsgspace), MsgFlags::empty())?;

    let mut fds = Vec::new();
    if let Some(ControlMessageOwned::ScmRights(rights)) = msg.cmsgs()?.next() {
        fds.extend(rights.into_iter().map(|raw| {
            // SAFETY: `raw` is an FD newly received via SCM_RIGHTS from
            // `recvmsg`. We take ownership exactly once here; unused FDs
            // are closed when their `OwnedFd` is dropped.
            unsafe { OwnedFd::from_raw_fd(raw) }
        }));
    }
    Ok(RecvResult { n: msg.bytes, fds })
}

/// Accepts the console-socket connection and returns the terminal FD sent over it.
///
/// Polls with a timeout and watches for runtime exit via non-reaping `waitid`.
/// On runtime exit, one final non-blocking attempt drains an already-queued
/// connection or FD before failing.
pub fn receive_console_fd(
    console_socket: UnixSocket,
    runtime_pid: Option<Pid>,
) -> ConmonResult<RemoteSocket> {
    receive_console_fd_with_timeout(console_socket, runtime_pid, CONSOLE_SOCKET_WAIT_TIMEOUT)
}

fn receive_console_fd_with_timeout(
    console_socket: UnixSocket,
    runtime_pid: Option<Pid>,
    timeout: Duration,
) -> ConmonResult<RemoteSocket> {
    let listen_fd = console_socket.fd().ok_or_else(|| {
        ConmonError::new(
            "Cannot receive console socket file descriptor without console socket.",
            1,
        )
    })?;
    let deadline = Instant::now() + timeout;

    let remote = wait_until_console_ready(
        deadline,
        runtime_pid,
        "Timed out waiting for runtime to connect on console socket",
        |wait| {
            if poll_fd(listen_fd.as_fd(), wait)? {
                console_socket.accept()
            } else {
                Ok(None)
            }
        },
    )?;

    wait_until_console_ready(
        deadline,
        runtime_pid,
        "Timed out waiting for console fd over console socket",
        |wait| {
            if poll_fd(remote.fd.as_fd(), wait)? {
                try_receive_console_fd(remote.fd.as_fd())
            } else {
                Ok(None)
            }
        },
    )
}

/// Shared wait loop for accept and FD receive. On runtime exit, tries once more
/// with a zero timeout before failing (queued connection/FD race).
fn wait_until_console_ready(
    deadline: Instant,
    runtime_pid: Option<Pid>,
    timeout_msg: &str,
    mut try_progress: impl FnMut(Duration) -> ConmonResult<Option<RemoteSocket>>,
) -> ConmonResult<RemoteSocket> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ConmonError::new(timeout_msg, 1));
        }
        let wait = remaining.min(CONSOLE_SOCKET_POLL_INTERVAL);

        if let Some(value) = try_progress(wait)? {
            return Ok(value);
        }

        if let Some(status) = runtime_exit_status(runtime_pid)? {
            if let Some(value) = try_progress(Duration::ZERO)? {
                return Ok(value);
            }
            return Err(ConmonError::new(
                format!("Runtime process exited with status {status} before sending console fd"),
                1,
            ));
        }
    }
}

fn try_receive_console_fd(fd: BorrowedFd<'_>) -> ConmonResult<Option<RemoteSocket>> {
    let mut buf = [0u8; 1];
    match recv_data_and_fds(fd.as_raw_fd(), &mut buf) {
        Ok(res) if res.n > 0 => {
            let mut fds = res.fds.into_iter();
            let Some(owned_fd) = fds.next() else {
                return Err(ConmonError::new(
                    "No file descriptor received using console socket.",
                    1,
                ));
            };
            drop(fds); // close any extra SCM_RIGHTS descriptors
            debug!("Received console fd {}", owned_fd.as_raw_fd());
            Ok(Some(RemoteSocket::new(SocketType::Terminal, owned_fd)))
        }
        Ok(_) => Err(ConmonError::new(
            "Console socket closed before file descriptor was received.",
            1,
        )),
        #[allow(unreachable_patterns)]
        Err(Errno::EAGAIN) | Err(Errno::EWOULDBLOCK) => Ok(None),
        Err(e) => Err(ConmonError::new(
            format!("Error receiving file descriptor using console socket: {e}"),
            1,
        )),
    }
}

/// Non-reaping runtime exit check (`waitid` + `WNOWAIT`).
fn runtime_exit_status(runtime_pid: Option<Pid>) -> ConmonResult<Option<i32>> {
    let Some(pid) = runtime_pid else {
        return Ok(None);
    };
    let flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT | WaitPidFlag::WNOHANG;
    loop {
        match waitid(Id::Pid(pid), flags) {
            Ok(WaitStatus::Exited(_, status)) => return Ok(Some(status)),
            Ok(WaitStatus::Signaled(_, sig, _)) => return Ok(Some(128 + sig as i32)),
            Ok(_) => return Ok(None),
            Err(Errno::EINTR) => continue,
            Err(Errno::ECHILD) => {
                return Err(ConmonError::new(
                    format!(
                        "waitid({pid}): unexpected ECHILD; runtime should remain waitable until session cleanup"
                    ),
                    1,
                ));
            }
            Err(e) => {
                return Err(ConmonError::new(format!("waitid({pid}) failed: {e}"), 1));
            }
        }
    }
}

/// Single `poll()`. `EINTR` returns `Ok(false)` so the caller recomputes remaining time.
fn poll_fd(fd: BorrowedFd<'_>, timeout: Duration) -> ConmonResult<bool> {
    let timeout_ms = timeout.as_millis().min(u16::MAX as u128) as u16;
    let mut pollfds = [PollFd::new(fd, PollFlags::POLLIN)];
    match poll(&mut pollfds, timeout_ms) {
        Ok(0) => Ok(false),
        Ok(_) => Ok(pollfds[0].revents().is_some_and(|r| {
            r.intersects(
                PollFlags::POLLIN | PollFlags::POLLHUP | PollFlags::POLLERR | PollFlags::POLLNVAL,
            )
        })),
        Err(Errno::EINTR) => Ok(false),
        Err(e) => Err(ConmonError::new(
            format!(
                "poll() failed while waiting for console socket: {}",
                io::Error::from_raw_os_error(e as i32)
            ),
            1,
        )),
    }
}

/// Remove a console/terminal peer FD from forward lists before its `OwnedFd` is dropped.
fn remove_forward_fd(console_fds: &mut Vec<RawFd>, terminal_fds: &mut Vec<RawFd>, socket: &Socket) {
    let Socket::Remote(remote) = socket else {
        return;
    };

    let fds = match remote.socket_type {
        SocketType::Console => console_fds,
        SocketType::Terminal => terminal_fds,
        _ => return,
    };

    let fd = remote.fd.as_raw_fd();
    fds.retain(|&candidate| candidate != fd);
}

/// Handle a peer that reached read-side EOF without dropping the socket.
///
/// Attach clients often EOF the read side immediately (no stdin) while still
/// expecting stdout/stderr writes, so Console FDs stay in `console_fds`.
/// Terminal peers stop receiving forwarded stdin.
fn on_peer_read_eof(
    terminal_fds: &mut Vec<RawFd>,
    socket: &Socket,
    stdin_attached: bool,
    leave_stdin_open: bool,
    workerfd_stdin: &mut Option<OwnedFd>,
) {
    let Socket::Remote(remote) = socket else {
        return;
    };

    match remote.socket_type {
        SocketType::Console if stdin_attached && !leave_stdin_open => {
            workerfd_stdin.take();
        }
        SocketType::Terminal => {
            terminal_fds.retain(|&candidate| candidate != remote.fd.as_raw_fd());
        }
        _ => {}
    }
}

/// Handles incomming data on fds and forwards them to right destination.
/// This function blocks until the container is running.
/// # Arguments
///
/// * `log_plugin` - plugin to which the container logs are forwarded into.
/// * `mainfd_stdout` - fd from which the container's stdout is read from.
/// * `mainfd_stderr` - fd from which the container's stderr is read from.
/// * `workerfd_stdin` - fd into which the container's stdin is written.
/// * `attach_socket` - socket for `attach` connections.
/// * `terminal_socket` - terminal socket create by runtime in case of `--terminal`.
/// * `ctl_fifo` - Remote socket for `ctl` fifo.
/// * `winsz_fifo` - Remote socket for `winsz` fifo.
/// * `leave_stdin_open` - Whether to keep stdin open attach client disconnects.
/// * `idle_callback` - function executed periodically during the event-loop.
#[allow(clippy::too_many_arguments)]
pub fn handle_stdio<F>(
    log_plugin: &mut dyn LogPlugin,
    mut mainfd_stdout: Option<OwnedFd>,
    mainfd_stderr: OwnedFd,
    mut workerfd_stdin: Option<OwnedFd>,
    attach_socket: Option<UnixSocket>,
    terminal_socket: Option<RemoteSocket>,
    ctl_fifo: Option<RemoteSocket>,
    winsz_fifo: Option<RemoteSocket>,
    oom_socket: Option<RemoteSocket>,
    notify_socket: Option<RemoteSocket>,
    notify_host_path: Option<PathBuf>,
    stdin_attached: bool,
    leave_stdin_open: bool,
    signal_fd: i32,
    mut idle_callback: F,
) -> ConmonResult<()>
where
    F: FnMut(bool) -> ConmonResult<bool>,
{
    debug!("Starting event loop");
    let mut sockets: Vec<Socket> = Vec::new();
    let mut new_sockets: Vec<RemoteSocket> = Vec::new();
    let mut fds: Vec<PollFd> = vec![];

    // Helpers containing fds for console, terminal and stdout, so we can easily
    // forward data to them.
    let mut console_fds = Vec::new();
    let mut terminal_fds = Vec::new();
    let mut stdout_fd: i32 = -1;

    // Optional attach socket.
    // WARN: The attach socket must be in `fds` before the stdout and stderr,
    // otherwise the stdout/stderr read is handled before the attach accept
    // callback and some data from stdout/stderr can be lost.
    if let Some(attach) = attach_socket {
        if let Some(fd) = attach.fd() {
            let borrowed = unsafe { BorrowedFd::borrow_raw(fd.as_raw_fd()) };
            fds.push(PollFd::new(borrowed, PollFlags::POLLIN));
        }
        sockets.push(Socket::Unix(attach));
    }

    // Container's stdout.
    if let Some(stdout) = mainfd_stdout.take() {
        stdout_fd = stdout.as_raw_fd();
        let borrowed = unsafe { BorrowedFd::borrow_raw(stdout.as_raw_fd()) };
        fds.push(PollFd::new(borrowed, PollFlags::POLLIN));
        sockets.push(Socket::Remote(RemoteSocket::new(
            SocketType::Stdout,
            stdout,
        )));
    }

    // Container's stderr.
    let borrowed = unsafe { BorrowedFd::borrow_raw(mainfd_stderr.as_raw_fd()) };
    fds.push(PollFd::new(borrowed, PollFlags::POLLIN));
    sockets.push(Socket::Remote(RemoteSocket::new(
        SocketType::Stderr,
        mainfd_stderr,
    )));

    // Optional terminal socket.
    if let Some(terminal) = terminal_socket {
        stdout_fd = terminal.fd.as_raw_fd();
        terminal_fds.push(terminal.fd.as_raw_fd());
        let borrowed = unsafe { BorrowedFd::borrow_raw(terminal.fd.as_raw_fd()) };
        fds.push(PollFd::new(borrowed, PollFlags::POLLIN));
        sockets.push(Socket::Remote(terminal));
    }

    // Optional ctl fifo.
    if let Some(ctl) = ctl_fifo {
        let borrowed = unsafe { BorrowedFd::borrow_raw(ctl.fd.as_raw_fd()) };
        fds.push(PollFd::new(borrowed, PollFlags::POLLIN));
        sockets.push(Socket::Remote(ctl));
    }

    // Optional winsz fifo.
    if let Some(winsz) = winsz_fifo {
        let borrowed = unsafe { BorrowedFd::borrow_raw(winsz.fd.as_raw_fd()) };
        fds.push(PollFd::new(borrowed, PollFlags::POLLIN));
        sockets.push(Socket::Remote(winsz));
    }

    // Optional OOM socket.
    if let Some(oom) = oom_socket {
        let borrowed = unsafe { BorrowedFd::borrow_raw(oom.fd.as_raw_fd()) };
        fds.push(PollFd::new(borrowed, PollFlags::POLLIN));
        sockets.push(Socket::Remote(oom));
    }

    // Optional systemd notify socket.
    if let Some(notify) = notify_socket {
        let borrowed = unsafe { BorrowedFd::borrow_raw(notify.fd.as_raw_fd()) };
        fds.push(PollFd::new(borrowed, PollFlags::POLLIN));
        sockets.push(Socket::Remote(notify));
    }

    // Signal fd to recieve UNIX signals.
    if signal_fd > 0 {
        info!("SignalFD: {}", signal_fd);
        let borrowed = unsafe { BorrowedFd::borrow_raw(signal_fd) };
        fds.push(PollFd::new(borrowed, PollFlags::POLLIN));
        sockets.push(Socket::Invalid());
    }

    // Main loop.
    // Iterates as long as we have some RemoteSocket to read from or
    // as long as `idle_callback` returns `true`.
    while sockets.iter().any(|s| matches!(s, Socket::Remote(_))) {
        // Run poll to get informed about new fd events.
        let n = poll(&mut fds, 10_u16).map_err(|e| {
            ConmonError::new(
                format!(
                    "handle_stdio poll() failed: {}",
                    io::Error::from_raw_os_error(e as i32)
                ),
                1,
            )
        })?;

        // We have no fd to read from, so execute the idle function.
        if n == 0 {
            let keep_running = idle_callback(false)?;
            if !keep_running {
                info!("idle_callback stopped the event loop.");
                return Ok(());
            }
            continue;
        }

        // We will mutate fds/remote_sockets, so iterate by index.
        let mut i = 0;
        while i < fds.len() {
            // The poll fd.
            let pfd = &fds[i];
            // If `false`, we close the socket completely.
            let mut keep_socket = true;
            // if `false`, we close the read side of the socket.
            let mut continue_reading = true;

            if let Some(revents) = pfd.revents() {
                if revents.contains(PollFlags::POLLIN) {
                    // If the POLLIN comes from the signal fd, run the idle_callback to handle
                    // the received signal.
                    if pfd.as_fd().as_raw_fd() == signal_fd {
                        if !idle_callback(true)? {
                            info!("idle_callback stopped the event loop after signal.");
                            return Ok(());
                        }
                        i += 1;
                        continue;
                    }

                    // Handle the received data.
                    continue_reading = sockets[i].handle_data(
                        log_plugin,
                        &mut new_sockets,
                        workerfd_stdin.as_ref(),
                        &console_fds,
                        &terminal_fds,
                        stdout_fd,
                        &notify_host_path,
                    )?;

                    // Add new sockets to `sockets` and `fds`.
                    // This happens when `attach` accepts new connection in the `handle_data`.
                    if !new_sockets.is_empty() {
                        while !new_sockets.is_empty() {
                            let new_socket = new_sockets.pop();
                            info!("Adding {:?} into poll fds", new_socket);
                            if let Some(n_s) = new_socket {
                                if n_s.socket_type == SocketType::Console {
                                    console_fds.push(n_s.fd.as_raw_fd());
                                }
                                let borrowed =
                                    unsafe { BorrowedFd::borrow_raw(n_s.fd.as_raw_fd()) };
                                fds.push(PollFd::new(borrowed, PollFlags::POLLIN));
                                sockets.push(Socket::Remote(n_s));
                            }
                        }
                        new_sockets.clear();
                    }
                } else if revents.contains(PollFlags::POLLHUP) {
                    // On HUP, close the socket.
                    debug!("HUP on {:?}", pfd);
                    keep_socket = false;
                }
            }

            if !continue_reading {
                // Close the read part of the socket.
                debug!("Shutdown {:?}", fds[i].as_fd().as_raw_fd());
                unsafe { shutdown(fds[i].as_fd().as_raw_fd(), SHUT_RD) };

                // Remove it from fds we call poll for.
                fds[i].set_events(PollFlags::empty());

                on_peer_read_eof(
                    &mut terminal_fds,
                    &sockets[i],
                    stdin_attached,
                    leave_stdin_open,
                    &mut workerfd_stdin,
                );
            }

            if keep_socket {
                // Go to next socket in case we want to keep this one.
                i += 1;
            } else {
                // Remove the fd completely. Dropping the socket closes the OwnedFd,
                // so clear it from forward lists first to avoid later writev/write
                // to a recycled FD number.
                remove_forward_fd(&mut console_fds, &mut terminal_fds, &sockets[i]);
                let socket = sockets.swap_remove(i);
                info!("Removing socket {:?}", socket);
                fds.swap_remove(i);

                // Do NOT increment the `i`, since it now points to swapped fd.
            }
        }
    }

    // All remote sockets closed; probe for a container that exited while I/O drained.
    let keep_running = idle_callback(false)?;
    if !keep_running {
        info!("idle_callback stopped the event loop after sockets closed.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unix_socket::{SocketType, UnixSocket};
    use nix::sys::socket::{
        AddressFamily, ControlMessage, SockFlag, SockType, sendmsg, socketpair,
    };
    use nix::sys::stat::Mode;
    use nix::sys::wait::{Id, WaitPidFlag, WaitStatus, waitid};
    use std::io::IoSlice;
    use std::os::unix::net::UnixStream;
    use std::process::Command;
    use std::thread;
    use std::time::Duration;
    use tempfile::tempdir;

    fn test_console_socket() -> ConmonResult<(tempfile::TempDir, UnixSocket)> {
        let tmp = tempdir().map_err(|e| ConmonError::new(e.to_string(), 1))?;
        let mut s = UnixSocket::new(
            SocketType::Terminal,
            false,
            tmp.path().to_path_buf(),
            None,
            None,
        );
        s.bind(
            Some(tmp.path().join("console.sock")),
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC,
            Mode::from_bits_truncate(0o700),
        )?;
        s.listen()?;
        Ok((tmp, s))
    }

    fn send_fds(count: usize, payload: &[u8]) -> ConmonResult<(OwnedFd, Vec<(OwnedFd, OwnedFd)>)> {
        let (sender, receiver) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )?;
        let mut keepalive = Vec::new();
        let mut fds = Vec::new();
        for _ in 0..count {
            let (r, w) = pipe2(OFlag::O_CLOEXEC)?;
            fds.push(r.as_raw_fd());
            keepalive.push((r, w));
        }
        sendmsg::<()>(
            sender.as_raw_fd(),
            &[IoSlice::new(payload)],
            &[ControlMessage::ScmRights(&fds)],
            MsgFlags::empty(),
            None,
        )?;
        Ok((receiver, keepalive))
    }

    fn wait_exited_nowait(pid: Pid) {
        let flags = WaitPidFlag::WEXITED | WaitPidFlag::WNOWAIT | WaitPidFlag::WNOHANG;
        loop {
            match waitid(Id::Pid(pid), flags).unwrap() {
                WaitStatus::Exited(_, _) | WaitStatus::Signaled(_, _, _) => return,
                _ => thread::sleep(Duration::from_millis(10)),
            }
        }
    }

    #[test]
    fn recv_data() -> ConmonResult<()> {
        let (receiver, _k) = send_fds(1, b"foo")?;
        let mut buf = [0u8; 16];
        let res = recv_data_and_fds(receiver.as_raw_fd(), &mut buf)?;
        assert_eq!(res.n, 3);
        assert_eq!(&buf[..3], b"foo");
        assert_eq!(res.fds.len(), 1);
        Ok(())
    }

    #[test]
    fn recv_data_too_many_scm_rights() -> ConmonResult<()> {
        let (receiver, _k) = send_fds(MAX_SCM_RIGHTS_FDS + 1, b"foo")?;
        let mut buf = [0u8; 16];
        assert_eq!(
            recv_data_and_fds(receiver.as_raw_fd(), &mut buf).err(),
            Some(Errno::ENOBUFS)
        );
        Ok(())
    }

    #[test]
    fn receive_console_fd_times_out_without_connection() -> ConmonResult<()> {
        let (_tmp, sock) = test_console_socket()?;
        let err =
            receive_console_fd_with_timeout(sock, None, Duration::from_millis(200)).unwrap_err();
        assert!(err.msg.contains("Timed out waiting for runtime to connect"));
        Ok(())
    }

    #[test]
    fn receive_console_fd_gets_passed_fd() -> ConmonResult<()> {
        let (_tmp, sock) = test_console_socket()?;
        let path = sock.path().unwrap().clone();
        let peer = thread::spawn(move || {
            let client = UnixStream::connect(path).unwrap();
            let (r, w) = pipe2(OFlag::O_CLOEXEC).unwrap();
            drop(w);
            sendmsg::<()>(
                client.as_raw_fd(),
                &[IoSlice::new(b"x")],
                &[ControlMessage::ScmRights(&[r.as_raw_fd()])],
                MsgFlags::empty(),
                None,
            )
            .unwrap();
        });
        let terminal = receive_console_fd_with_timeout(sock, None, Duration::from_secs(5))?;
        assert_eq!(terminal.socket_type, SocketType::Terminal);
        peer.join().unwrap();
        Ok(())
    }

    #[test]
    fn runtime_exit_status_does_not_reap_child() {
        let mut child = Command::new("sh").args(["-c", "exit 42"]).spawn().unwrap();
        let pid = Pid::from_raw(child.id() as i32);
        wait_exited_nowait(pid);
        assert_eq!(runtime_exit_status(Some(pid)).unwrap(), Some(42));
        assert_eq!(child.wait().unwrap().code(), Some(42));
    }

    #[test]
    fn receive_console_fd_fails_when_runtime_exits() -> ConmonResult<()> {
        let (_tmp, sock) = test_console_socket()?;
        let mut child = Command::new("sh").args(["-c", "exit 42"]).spawn().unwrap();
        let pid = Pid::from_raw(child.id() as i32);
        let err =
            receive_console_fd_with_timeout(sock, Some(pid), Duration::from_secs(5)).unwrap_err();
        let _ = child.wait();
        assert!(err.msg.contains("Runtime process exited with status 42"));
        Ok(())
    }

    #[test]
    fn accept_propagates_errors() -> ConmonResult<()> {
        let tmp = tempdir().map_err(|e| ConmonError::new(e.to_string(), 1))?;
        let mut sock = UnixSocket::new(
            SocketType::Terminal,
            false,
            tmp.path().to_path_buf(),
            None,
            None,
        );
        sock.bind(
            Some(tmp.path().join("nolisten.sock")),
            SockType::Stream,
            SockFlag::SOCK_CLOEXEC,
            Mode::from_bits_truncate(0o700),
        )?;
        let err = sock.accept().unwrap_err();
        assert!(err.msg.contains("Failed to accept client connection"));
        Ok(())
    }

    #[test]
    fn read_eof_keeps_attach_fd_in_console_fds() -> ConmonResult<()> {
        let (attach_r, _attach_w) = pipe2(OFlag::O_CLOEXEC)?;
        let attach_fd = attach_r.as_raw_fd();
        let (stdin_r, stdin_w) = pipe2(OFlag::O_CLOEXEC)?;
        drop(stdin_r);
        let sockets = [Socket::Remote(RemoteSocket::new(
            SocketType::Console,
            attach_r,
        ))];
        let console_fds = [attach_fd];
        let mut terminal_fds = Vec::new();
        let mut workerfd_stdin = Some(stdin_w);

        on_peer_read_eof(
            &mut terminal_fds,
            &sockets[0],
            true,
            false,
            &mut workerfd_stdin,
        );

        assert!(
            console_fds.contains(&attach_fd),
            "attach FD must remain in console_fds after read-side EOF"
        );
        assert!(
            workerfd_stdin.is_none(),
            "container stdin is closed when the attach client EOFs"
        );
        Ok(())
    }

    #[test]
    fn read_eof_stops_forwarding_to_terminal() -> ConmonResult<()> {
        let (term_r, _term_w) = pipe2(OFlag::O_CLOEXEC)?;
        let term_fd = term_r.as_raw_fd();
        let sockets = [Socket::Remote(RemoteSocket::new(
            SocketType::Terminal,
            term_r,
        ))];
        let mut terminal_fds = vec![term_fd];
        let mut workerfd_stdin = None;

        on_peer_read_eof(
            &mut terminal_fds,
            &sockets[0],
            false,
            false,
            &mut workerfd_stdin,
        );

        assert!(
            !terminal_fds.contains(&term_fd),
            "terminal FD must be removed from terminal_fds after read-side EOF"
        );
        Ok(())
    }

    #[test]
    fn socket_removal_clears_forward_fd_before_owned_fd_drop() -> ConmonResult<()> {
        // Mirrors the event-loop removal path: remove_forward_fd, then swap_remove/drop.
        let (attach_r, _attach_w) = pipe2(OFlag::O_CLOEXEC)?;
        let stale_fd = attach_r.as_raw_fd();
        let mut sockets = vec![Socket::Remote(RemoteSocket::new(
            SocketType::Console,
            attach_r,
        ))];
        let mut console_fds = vec![stale_fd];
        let mut terminal_fds = Vec::new();

        remove_forward_fd(&mut console_fds, &mut terminal_fds, &sockets[0]);
        let removed = sockets.swap_remove(0);
        drop(removed);

        assert!(
            !console_fds.contains(&stale_fd),
            "stale attach FD must be cleared before OwnedFd drop"
        );

        let (new_r, _new_w) = pipe2(OFlag::O_CLOEXEC)?;
        let reused = new_r.as_raw_fd();
        if reused == stale_fd {
            assert!(
                !console_fds.contains(&reused),
                "recycled FD number must not remain in console_fds"
            );
        }
        Ok(())
    }
}
