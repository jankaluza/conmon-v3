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
    unistd::{pipe2, read},
};

use std::{
    io::{self, IoSliceMut},
    os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
    path::PathBuf,
};

use log::{debug, info};

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
pub struct RecvResult {
    /// The number of bytes read.
    n: usize,

    /// The file descriptors received.
    fds: Vec<RawFd>,
}

/// Receives data and file descriptors from existing file descriptor.
///
/// The file descriptors must be sent using the ScmRights Control message.
///
/// # Returns
///
/// * The `RecvResult` with number of bytes read and file descriptors received.
///
/// # Arguments
///
/// * `fd` - The file descriptor to read the data and fds from.
/// * `buf` - The buffer to write the data into.
///
/// # Errors
///
/// * [`ConmonError`] on any error.
fn recv_data_and_fds(fd: RawFd, buf: &mut [u8]) -> nix::Result<RecvResult> {
    let mut iov = [IoSliceMut::new(buf)];
    let mut cmsgspace = cmsg_space!([RawFd; 4]);

    let msg = recvmsg::<SockaddrStorage>(fd, &mut iov, Some(&mut cmsgspace), MsgFlags::empty())?;

    let mut fds = Vec::new();
    let rights = msg.cmsgs()?.next();
    if let Some(ControlMessageOwned::ScmRights(rights)) = rights {
        fds.extend(rights);
    }
    Ok(RecvResult { n: msg.bytes, fds })
}

/// Accepts the console_socket connection and returns the fd sent over it.
///
/// This function blocks until the fd is received.
///
/// # Returns
///
/// * The `RemoteSocket` based on the file descriptor received over `console_socket`.
///
/// # Arguments
///
/// * `console_socket` - The `UnixSocket` to receive the console file-descriptor from.
///
/// # Errors
///
/// * [`ConmonError`] on any error.
pub fn receive_console_fd(console_socket: UnixSocket) -> ConmonResult<RemoteSocket> {
    // Block on accept until we have some connection.
    let remote = console_socket.accept()?;
    if let Some(r) = remote {
        // We actually do not care about the data received. We care only about fd.
        let mut buf = [0u8; 8192];
        match recv_data_and_fds(r.fd.as_raw_fd(), &mut buf) {
            Ok(res) => {
                let n = res.n;
                if n > 0 {
                    let received_fd = res.fds.first();
                    if let Some(rfd) = received_fd {
                        debug!("Received console fd {}", rfd);
                        let owned_fd = unsafe { OwnedFd::from_raw_fd(*rfd) };
                        let ret = RemoteSocket::new(SocketType::Terminal, owned_fd);
                        return Ok(ret);
                    }
                } else {
                    return Err(ConmonError::new(
                        "No file descriptor received using console socket.",
                        1,
                    ));
                }
            }
            Err(e) => {
                return Err(ConmonError::new(
                    format!(
                        "Error receiving file descriptor using console socket: {}",
                        e
                    ),
                    1,
                ));
            }
        }
    }
    Err(ConmonError::new(
        "Cannot receive console socket file descriptor without console socket.",
        1,
    ))
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
            // If `false`, we close the socket completely.
            let mut keep_socket = true;
            // if `false`, we close the read side of the socket.
            let mut continue_reading = true;

            let revents = fds[i].revents();
            let polled_fd = fds[i].as_fd().as_raw_fd();
            if let Some(revents) = revents {
                if revents.contains(PollFlags::POLLIN) {
                    // If the POLLIN comes from the signal fd, run the idle_callback to handle
                    // the received signal.
                    if polled_fd == signal_fd {
                        idle_callback(true)?;
                        i += 1;
                        continue;
                    }

                    // Handle the received data.
                    continue_reading = sockets[i].handle_data(
                        log_plugin,
                        &mut new_sockets,
                        workerfd_stdin.as_ref(),
                        &mut console_fds,
                        &mut terminal_fds,
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
                    // Hangup with nothing readable: nothing left to drain.
                    continue_reading = false;
                }
                // Drain readable SEQPACKET data before removing on hangup.
                if revents.contains(PollFlags::POLLHUP) && !continue_reading {
                    debug!("HUP on fd {}", polled_fd);
                    keep_socket = false;
                }
            }

            if !continue_reading {
                // Close the read part of the socket.
                debug!("Shutdown {:?}", fds[i].as_fd().as_raw_fd());
                unsafe { shutdown(fds[i].as_fd().as_raw_fd(), SHUT_RD) };

                // Remove it from fds we call poll for.
                fds[i].set_events(PollFlags::empty());

                // Stop forwarding container output/input to this closed peer.
                remove_forward_fd(&mut console_fds, &mut terminal_fds, &sockets[i]);

                if let Socket::Remote(r) = &sockets[i] {
                    if r.socket_type == SocketType::Console && stdin_attached {
                        // We closed the Console socket attached to container's stdin.
                        // This normally means we also close the container's stdin, unless
                        // the called instructed us no to do it using the `--leave-stdin-open`.
                        if !leave_stdin_open {
                            // This closes the socket, since it moves out of scope.
                            workerfd_stdin.take();
                        }
                    }
                }
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
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::none_logger::NoneLogger;
    use crate::logging::plugin::LogPluginCfg;
    use nix::poll::PollTimeout;
    use nix::sys::socket::{
        AddressFamily, ControlMessage, SockFlag, SockType, sendmsg, socketpair,
    };
    use nix::unistd::write;
    use std::io::IoSlice;
    use std::sync::mpsc;

    fn poll_wait() -> PollTimeout {
        PollTimeout::from(500u16)
    }

    fn send_fds(count: usize, payload: &[u8]) -> ConmonResult<(OwnedFd, Vec<(OwnedFd, OwnedFd)>)> {
        let (sender, receiver) = socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )?;

        let mut keepalive = Vec::new();
        let mut fds_to_send: Vec<RawFd> = Vec::new();
        for _ in 0..count {
            let (r, w) = pipe2(OFlag::O_CLOEXEC)?;
            fds_to_send.push(r.as_raw_fd());
            keepalive.push((r, w));
        }

        let iov = [IoSlice::new(payload)];
        let cmsg = ControlMessage::ScmRights(&fds_to_send);
        sendmsg::<()>(sender.as_raw_fd(), &iov, &[cmsg], MsgFlags::empty(), None)?;

        Ok((receiver, keepalive))
    }

    /// One `handle_stdio` wake for a single remote socket.
    fn process_one_poll_wake(
        sockets: &mut [Socket],
        log_plugin: &mut dyn LogPlugin,
    ) -> ConmonResult<(PollFlags, bool, bool)> {
        let Socket::Remote(r) = &sockets[0] else {
            unreachable!();
        };
        let mut pfd = [PollFd::new(r.fd.as_fd(), PollFlags::POLLIN)];
        let n = poll(&mut pfd, poll_wait())?;
        assert_ne!(n, 0, "expected poll to report activity");
        let revents = pfd[0].revents().unwrap_or(PollFlags::empty());

        let mut continue_reading = true;
        let mut new_sockets = Vec::new();
        let mut console_fds = Vec::new();
        let mut terminal_fds = Vec::new();
        if revents.contains(PollFlags::POLLIN) {
            continue_reading = sockets[0].handle_data(
                log_plugin,
                &mut new_sockets,
                None,
                &mut console_fds,
                &mut terminal_fds,
                -1,
                &None,
            )?;
        } else if revents.contains(PollFlags::POLLHUP) {
            continue_reading = false;
        }
        let remove = revents.contains(PollFlags::POLLHUP) && !continue_reading;
        Ok((revents, continue_reading, remove))
    }

    #[test]
    fn recv_data() -> ConmonResult<()> {
        let payload = b"foo";
        let (receiver, _keepalive) = send_fds(1, payload)?;

        let mut buf = [0u8; 16];
        let res = recv_data_and_fds(receiver.as_raw_fd(), &mut buf)?;
        assert_eq!(res.n, payload.len());
        assert_eq!(&buf[..payload.len()], payload);
        assert_eq!(res.fds.len(), 1);
        Ok(())
    }

    /// `recv_data_and_fds` only expects at max 4 fds in the `SCM_RIGHTS` control message.
    #[test]
    fn recv_data_too_many_scm_rights() -> ConmonResult<()> {
        let (receiver, _keepalive) = send_fds(5, b"foo")?;

        let mut buf = [0u8; 16];
        let recv = recv_data_and_fds(receiver.as_raw_fd(), &mut buf);
        assert_eq!(recv.err(), Some(Errno::ENOBUFS));
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

    #[test]
    fn pollinhup_drains_queued_seqpacket_messages_before_removal() -> ConmonResult<()> {
        let (sender, receiver) = socketpair(
            AddressFamily::Unix,
            SockType::SeqPacket,
            None,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
        )?;
        let expected = [b"one".as_slice(), b"two".as_slice(), b"three".as_slice()];
        for msg in expected {
            assert_eq!(write(&sender, msg)?, msg.len());
        }
        drop(sender);

        let (tx, rx) = mpsc::channel();
        let mut remote = RemoteSocket::new(SocketType::Console, receiver);
        remote.set_handler(move |data| {
            let _ = tx.send(data.to_vec());
            true
        });
        let mut sockets = vec![Socket::Remote(remote)];
        let mut log_plugin = NoneLogger::new(&LogPluginCfg::default())?;

        let mut removed = false;
        for _ in 0..expected.len() + 2 {
            let (revents, continue_reading, remove) =
                process_one_poll_wake(&mut sockets, &mut log_plugin)?;
            if remove {
                assert!(revents.contains(PollFlags::POLLHUP) && !continue_reading);
                let got: Vec<Vec<u8>> = rx.try_iter().collect();
                assert_eq!(got, expected.map(|m| m.to_vec()));
                removed = true;
                break;
            }
            assert!(continue_reading);
        }
        assert!(removed);
        Ok(())
    }
}
