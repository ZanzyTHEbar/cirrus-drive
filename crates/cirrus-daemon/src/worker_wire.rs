//! Fixed-size Linux policy channel. Indices refer only to the current fair cohort.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Instant;

pub(crate) const PROTOCOL: u8 = 1;
pub(crate) const MAX_SPACES: usize = 64;
const SIZE: usize = 19;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Decision {
    Hello,
    Choose,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Message {
    pub(crate) kind: Decision,
    pub(crate) generation: u64,
    pub(crate) sequence: u64,
    pub(crate) value: u8,
}

impl Message {
    pub(crate) fn send(self, mut channel: &UnixStream) -> io::Result<()> {
        let mut bytes = [0; SIZE];
        bytes[0] = PROTOCOL;
        bytes[1] = match self.kind {
            Decision::Hello => 0,
            Decision::Choose => 1,
        };
        bytes[2..10].copy_from_slice(&self.generation.to_le_bytes());
        bytes[10..18].copy_from_slice(&self.sequence.to_le_bytes());
        bytes[18] = self.value;
        channel.write_all(&bytes)
    }

    pub(crate) fn receive(mut channel: &UnixStream, deadline: Option<Instant>) -> io::Result<Self> {
        let mut bytes = [0; SIZE];
        if let Some(deadline) = deadline {
            let mut unread = &mut bytes[..];
            while !unread.is_empty() {
                let remaining = deadline.saturating_duration_since(Instant::now());
                if remaining.is_zero() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "policy reply timed out",
                    ));
                }
                channel.set_read_timeout(Some(remaining))?;
                match channel.read(unread) {
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "policy channel closed",
                        ));
                    }
                    Ok(count) => unread = &mut unread[count..],
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) => return Err(error),
                }
            }
        } else {
            channel.read_exact(&mut bytes)?;
        }
        if bytes[0] != PROTOCOL {
            return Err(io::Error::other("invalid policy frame or protocol"));
        }
        let kind = match bytes[1] {
            0 => Decision::Hello,
            1 => Decision::Choose,
            _ => return Err(io::Error::other("unknown policy decision")),
        };
        Ok(Self {
            kind,
            generation: u64::from_le_bytes(
                bytes[2..10].try_into().expect("fixed generation field"),
            ),
            sequence: u64::from_le_bytes(bytes[10..18].try_into().expect("fixed sequence field")),
            value: bytes[18],
        })
    }
}
