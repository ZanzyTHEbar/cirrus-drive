use std::io::{self, IoSliceMut};
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::os::unix::{net::UnixStream, process::CommandExt};
use std::path::Path;
use std::process::Command;

use rustix::event::{PollFd, PollFlags, poll};
use rustix::io::{FdFlags, fcntl_setfd, retry_on_intr};
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, recvmsg};

/// Mount via the installed FUSE 3 helper, receiving only the connection FD.
pub(crate) fn mount(path: &Path, source: &str, read_only: bool) -> io::Result<OwnedFd> {
    let (receive, send) = UnixStream::pair()?;
    let fd = send.as_raw_fd();
    let options = format!(
        "nodev,nosuid,noexec,fsname={source},subtype=cirrus-drive{}",
        if read_only { ",ro" } else { "" }
    );
    let mut helper = Command::new("fusermount3");
    helper.args(["-o", &options, "--"]).arg(path);
    helper.env("_FUSE_COMMFD", fd.to_string());
    // SAFETY: send stays open until output returns. Only the child's fd table
    // is changed, using the async-signal-safe fcntl syscall before exec.
    unsafe {
        helper.pre_exec(move || {
            fcntl_setfd(BorrowedFd::borrow_raw(fd), FdFlags::empty())?;
            Ok(())
        });
    }
    // The helper sends one byte plus one FD, which fits in the socket buffer
    // before it exits; output drains its stdout and stderr while waiting.
    let output = helper.output()?;
    drop(send);
    check_helper(output)?;
    let mut bytes = [0];
    let mut space = [std::mem::MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
    let mut control = RecvAncillaryBuffer::new(&mut space);
    let message = retry_on_intr(|| {
        recvmsg(
            &receive,
            &mut [IoSliceMut::new(&mut bytes)],
            &mut control,
            RecvFlags::CMSG_CLOEXEC,
        )
    })?;
    if message.bytes == 1
        && !message.flags.contains(ReturnFlags::CTRUNC)
        && let Some(RecvAncillaryMessage::ScmRights(mut fds)) = control.drain().next()
        && fds.len() == 1
        && let Some(fd) = fds.next()
    {
        return Ok(fd);
    }
    Err(io::Error::other(
        "fusermount3 did not send a FUSE descriptor",
    ))
}

pub(crate) fn disconnected(fd: &OwnedFd) -> io::Result<bool> {
    let mut fds = [PollFd::new(fd, PollFlags::empty())];
    retry_on_intr(|| poll(&mut fds, Some(&rustix::event::Timespec::default())))?;
    match fds[0].revents() {
        flags if flags.is_empty() => Ok(false),
        // Linux fuse_dev_poll returns POLLERR when this connection ends.
        PollFlags::ERR => Ok(true),
        _ => Err(io::Error::other("unexpected FUSE device poll result")),
    }
}

pub(crate) fn unmount(path: &Path) -> io::Result<()> {
    check_helper(
        Command::new("fusermount3")
            .args(["-u", "--"])
            .arg(path)
            .output()?,
    )
}

fn check_helper(output: std::process::Output) -> io::Result<()> {
    if output.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "fusermount3 failed ({}): {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )))
    }
}
