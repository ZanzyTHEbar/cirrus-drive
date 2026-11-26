//! Release-owned scheduling policy, with no account or filesystem service.

#[path = "../worker_wire.rs"]
mod worker_wire;

use std::io;
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

use worker_wire::{Decision, MAX_SPACES, Message};

fn main() -> io::Result<()> {
    // SAFETY: this single-threaded binary takes ownership of the inherited
    // protocol endpoint once and never accesses stdin through std::io.
    let channel = UnixStream::from(unsafe { OwnedFd::from_raw_fd(0) });
    let hello = Message::receive(&channel, None)?;
    if hello.kind != Decision::Hello || hello.sequence != 0 || hello.value != 0 {
        return Err(io::Error::other("expected resident hello"));
    }
    hello.send(&channel)?;
    let mut sequence = 0;
    loop {
        let request = Message::receive(&channel, None)?;
        if request.kind != Decision::Choose
            || request.generation != hello.generation
            || request.sequence <= sequence
            || !(1..=MAX_SPACES as u8).contains(&request.value)
        {
            return Err(io::Error::other("invalid resident scheduling request"));
        }
        sequence = request.sequence;
        // The resident orders the current fair cohort round-robin. A release
        // may choose a different eligible index; it cannot bypass the cohort.
        Message {
            value: 0,
            ..request
        }
        .send(&channel)?;
    }
}
