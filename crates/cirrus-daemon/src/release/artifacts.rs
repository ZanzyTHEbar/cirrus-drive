//! Signed user release sets and the atomic, durable launcher selection.

use std::fs::File;
use std::io::{self, Read, Seek, Write};
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Component, Path};

use cirrus_api::CredentialPolicy;
use cirrus_client::wire::proc_fd_path;
use cirrus_fuse::ReadProgram;
use ring::{digest, rand, signature};
use rustix::fs::{self, FileType, MemfdFlags, Mode, OFlags, ResolveFlags, SealFlags};
use serde::{Deserialize, Serialize};

use crate::worker_wire::PROTOCOL;

// Clients can use the current account/public wire, and workers use only the
// policy ABI below. Neither ABI grants a release access to persisted formats.
const PUBLIC_PROTOCOL: u8 = 3;
const MANIFEST_LIMIT: u64 = 8192;
const ARTIFACT_LIMIT: u64 = 1024 * 1024 * 1024;
const SELECTED: &str = "selection.json";

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Selection {
    pub(super) current: Option<String>,
    pub(super) previous: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    format: u8,
    release: String,
    target_os: String,
    target_arch: String,
    public_protocol: u8,
    worker_protocol: u8,
    worker_role: String,
    store_access: String,
    pub(super) credential_policy: Option<CredentialPolicy>,
    pub(super) artifacts: Artifacts,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Artifacts {
    pub(super) resident: String,
    pub(super) worker: String,
    cli: String,
    ui: String,
    pub(super) read_engine: Option<String>,
}

pub(super) struct Store {
    root: OwnedFd,
    key: [u8; 32],
    pub(super) identity: String,
}

pub(super) struct Set {
    dir: OwnedFd,
    pub(super) manifest: Manifest,
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id.as_bytes()[0].is_ascii_alphanumeric()
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

fn valid_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn inspect(fd: &OwnedFd, kind: FileType) -> io::Result<()> {
    let stat = fs::fstat(fd)?;
    if FileType::from_raw_mode(stat.st_mode) != kind
        || stat.st_uid != rustix::process::geteuid().as_raw()
        || stat.st_mode & 0o7077 != 0
        || (kind == FileType::RegularFile && stat.st_nlink != 1)
    {
        return Err(io::Error::other("unsafe user release directory or file"));
    }
    Ok(())
}

fn child(dir: &OwnedFd, name: &str, kind: FileType) -> io::Result<OwnedFd> {
    let mut flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK;
    if kind == FileType::Directory {
        flags |= OFlags::DIRECTORY;
    }
    let fd = fs::openat2(
        dir,
        name,
        flags,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS,
    )?;
    inspect(&fd, kind)?;
    Ok(fd)
}

fn small_file(dir: &OwnedFd, name: &str, limit: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::from(child(dir, name, FileType::RegularFile)?)
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::Error::other("release metadata exceeds limit"));
    }
    Ok(bytes)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256(input: &mut File, mut copy: impl Write) -> io::Result<String> {
    let mut input = input.take(ARTIFACT_LIMIT + 1);
    let mut context = digest::Context::new(&digest::SHA256);
    let mut block = [0; 64 * 1024];
    loop {
        let count = input.read(&mut block)?;
        if count == 0 {
            return Ok(hex(context.finish().as_ref()));
        }
        if input.limit() == 0 {
            return Err(io::Error::other("release artifact exceeds limit"));
        }
        context.update(&block[..count]);
        copy.write_all(&block[..count])?;
    }
}

pub(super) fn resident_hash() -> io::Result<String> {
    // The live executable inode survives an install/unlink at its old path.
    sha256(&mut File::open("/proc/self/exe")?, io::sink())
}

impl Store {
    pub(super) fn open(path: &Path) -> io::Result<Self> {
        if !path.is_absolute() || path.components().any(|part| part == Component::ParentDir) {
            return Err(io::Error::other(
                "release root must be an absolute non-symlink path",
            ));
        }
        let root = fs::openat2(
            fs::CWD,
            path,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
            ResolveFlags::NO_SYMLINKS,
        )?;
        inspect(&root, FileType::Directory)?;
        let key = small_file(&root, "trust.ed25519", 32)?
            .try_into()
            .map_err(|_| io::Error::other("invalid installed Ed25519 key"))?;
        let stat = fs::fstat(&root)?;
        let identity = format!("{}:{}", stat.st_dev, stat.st_ino);
        Ok(Self {
            root,
            key,
            identity,
        })
    }

    pub(super) fn lock_resident(&self) -> io::Result<()> {
        fs::flock(&self.root, fs::FlockOperation::NonBlockingLockExclusive).map_err(|error| {
            io::Error::other(format!(
                "another resident may own this release install: {error}"
            ))
        })
    }

    pub(super) fn sync_selection(&self) -> io::Result<()> {
        Ok(fs::fsync(&self.root)?)
    }

    pub(super) fn selection(&self) -> io::Result<Selection> {
        let bytes = match small_file(&self.root, SELECTED, 512) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Selection::default());
            }
            Err(error) => return Err(error),
        };
        let selection: Selection = serde_json::from_slice(&bytes)?;
        if selection.current.as_deref().is_none_or(|id| !valid_id(id))
            || selection
                .previous
                .as_deref()
                .is_some_and(|id| !valid_id(id))
            || selection.current == selection.previous
        {
            return Err(io::Error::other("invalid durable release selection"));
        }
        Ok(selection)
    }

    // Makes the selection visible. The caller publishes the matching serving
    // generation before syncing the directory and recording durability.
    pub(super) fn select(&self, selection: &Selection) -> io::Result<()> {
        let nonce = rand::generate::<[u8; 16]>(&rand::SystemRandom::new())
            .map_err(|_| io::Error::other("cannot name durable release selection"))?;
        let name = format!(".selection-{}", hex(&nonce.expose()));
        let mut file = File::from(fs::openat(
            &self.root,
            name.as_str(),
            OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::RUSR | Mode::WUSR,
        )?);
        let result = (|| -> io::Result<()> {
            serde_json::to_writer(&mut file, selection)?;
            file.sync_all()?;
            fs::renameat(&self.root, name.as_str(), &self.root, SELECTED)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::unlinkat(&self.root, name.as_str(), fs::AtFlags::empty());
        }
        result
    }

    pub(super) fn set(&self, id: &str) -> io::Result<Set> {
        if !valid_id(id) {
            return Err(io::Error::other("invalid release ID"));
        }
        let releases = child(&self.root, "releases", FileType::Directory)?;
        let dir = child(&releases, id, FileType::Directory)?;
        let bytes = small_file(&dir, "manifest.json", MANIFEST_LIMIT)?;
        let sig = small_file(&dir, "manifest.sig", 64)?;
        signature::UnparsedPublicKey::new(&signature::ED25519, self.key)
            .verify(&bytes, &sig)
            .map_err(|_| io::Error::other("release manifest signature is not trusted"))?;
        let manifest: Manifest = serde_json::from_slice(&bytes)?;
        if !matches!(
            (manifest.format, &manifest.artifacts.read_engine),
            (1, None) | (2, Some(_))
        ) || manifest.release != id
            || manifest.target_os != std::env::consts::OS
            || manifest.target_arch != std::env::consts::ARCH
            || manifest.public_protocol != PUBLIC_PROTOCOL
            || manifest.worker_protocol != PROTOCOL
            || manifest.worker_role != "eligible-space-policy"
            || manifest.store_access != "none"
        {
            return Err(io::Error::other(
                "release target, roles or protocols are incompatible",
            ));
        }
        Ok(Set { dir, manifest })
    }
}

impl Set {
    pub(super) fn read_program(&self) -> io::Result<ReadProgram> {
        let Some(hash) = &self.manifest.artifacts.read_engine else {
            return Ok(ReadProgram::default());
        };
        let bytes = small_file(&self.dir, "cirrus-read-engine.json", 1024)?;
        if !valid_hash(hash) || hex(digest::digest(&digest::SHA256, &bytes).as_ref()) != *hash {
            return Err(io::Error::other(
                "mounted read-engine artifact does not match the signed set",
            ));
        }
        ReadProgram::negotiate(&bytes)
    }

    fn verify(&self, name: &str, hash: &str, copy: impl Write) -> io::Result<File> {
        let mut file = File::from(child(&self.dir, name, FileType::RegularFile)?);
        let stat = fs::fstat(file.as_fd())?;
        if stat.st_mode & 0o777 != 0o500 || !valid_hash(hash) {
            return Err(io::Error::other(format!("unsafe release artifact: {name}")));
        }
        let machine = match std::env::consts::ARCH {
            "x86_64" => 62,
            "aarch64" => 183,
            _ => {
                return Err(io::Error::other(
                    "no native release ABI for this architecture",
                ));
            }
        };
        let mut header = [0; 20];
        file.read_exact(&mut header)?;
        if &header[..7] != b"\x7fELF\x02\x01\x01"
            || !matches!(u16::from_le_bytes([header[16], header[17]]), 2 | 3)
            || u16::from_le_bytes([header[18], header[19]]) != machine
        {
            return Err(io::Error::other(format!(
                "release artifact is not a native executable: {name}"
            )));
        }
        file.rewind()?;
        if sha256(&mut file, copy)? != hash {
            return Err(io::Error::other(format!(
                "release artifact does not match signed set: {name}"
            )));
        }
        file.rewind()?;
        Ok(file)
    }

    pub(super) fn worker(&self) -> io::Result<File> {
        let a = &self.manifest.artifacts;
        self.verify("cirrus-drive-service", &a.resident, io::sink())?;
        self.verify("cirrus-daemon", &a.cli, io::sink())?;
        self.verify("cirrus-ui", &a.ui, io::sink())?;
        // Execute exactly the hash-checked worker bytes, never reopen its
        // staging path or allow in-place modification after verification.
        let flags = MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING;
        let fd = fs::memfd_create("cirrus-control-worker", flags | MemfdFlags::EXEC).or_else(
            |error| {
                if error == rustix::io::Errno::INVAL {
                    // Older kernels have executable memfds but did not accept
                    // the explicit flag. A policy denial is never bypassed.
                    fs::memfd_create("cirrus-control-worker", flags)
                } else {
                    Err(error)
                }
            },
        )?;
        let sealed = File::from(fd);
        self.verify("cirrus-control-worker", &a.worker, &sealed)?;
        fs::fchmod(&sealed, Mode::RUSR | Mode::XUSR)?;
        fs::fcntl_add_seals(
            &sealed,
            SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL,
        )?;
        Ok(sealed)
    }

    pub(super) fn launch(&self, role: &str, args: &[std::ffi::OsString]) -> io::Result<()> {
        use std::os::unix::process::CommandExt;
        let (name, hash) = match role {
            "cli" => ("cirrus-daemon", &self.manifest.artifacts.cli),
            "ui" => ("cirrus-ui", &self.manifest.artifacts.ui),
            _ => return Err(io::Error::other("invalid client role")),
        };
        let file = self.verify(name, hash, io::sink())?;
        // The version directory is immutable to the release manager and only
        // accessible to the install UID. This pins the verified inode.
        Err(std::process::Command::new(proc_fd_path(&file, "")?)
            .arg0(name)
            .env("CIRRUS_RUNNING_RELEASE", &self.manifest.release)
            .args(args)
            .exec())
    }
}
