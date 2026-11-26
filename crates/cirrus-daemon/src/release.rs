//! Resident-owned release selection and generation fencing.

mod artifacts;

use std::ffi::OsString;
use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, TryLockError};
use std::thread;
use std::time::{Duration, Instant};

use cirrus_api::{
    CredentialPolicy, CredentialPolicyRequest, ReleaseRequest, ReleaseStatus, RunningReadEngine,
    RunningWorker,
};
use cirrus_client::wire::proc_fd_path;
use cirrus_fuse::ReadEngines;
use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::io::retry_on_intr;
use rustix::process::{Pid, PidfdFlags, pidfd_open};

use crate::worker_wire::{Decision, MAX_SPACES, Message};
use artifacts::{Selection, Store};

const HELLO_TIMEOUT: Duration = Duration::from_secs(2);
const DECISION_TIMEOUT: Duration = Duration::from_millis(500);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(30);
const WORKER_EXITED: &str = "worker exited; automatic transfers paused; inspect or roll back";
const SELECTION_PENDING: &str = "activation visible; release selection durability is pending";

struct ServingWorker {
    identity: RunningWorker,
    pidfd: OwnedFd,
}

impl ServingWorker {
    fn alive(&self) -> bool {
        let mut fds = [PollFd::new(&self.pidfd, PollFlags::IN)];
        // A pidfd observes this exact process even after its Child was reaped.
        // A zero-timeout poll never waits for IPC or requires the child lock.
        retry_on_intr(|| poll(&mut fds, Some(&Timespec::default()))) == Ok(0)
    }
}

struct Worker {
    serving: Arc<ServingWorker>,
    process: Child,
    channel: UnixStream,
    sequence: u64,
}

impl Worker {
    fn start(
        executable: File,
        release: String,
        sha256: String,
        generation: u64,
    ) -> io::Result<Self> {
        let (channel, endpoint) = UnixStream::pair()?;
        channel.set_write_timeout(Some(DECISION_TIMEOUT))?;
        let mut command = Command::new(proc_fd_path(&executable, "")?);
        command
            .arg0("cirrus-control-worker")
            .env_clear()
            .current_dir("/")
            .stdin(Stdio::from(OwnedFd::from(endpoint)))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: only async-signal-safe Linux syscalls run after fork.
        // Mark *every* other inherited FD CLOEXEC, even where a dependency
        // forgot to. Until exec the signed worker has not begun running.
        unsafe {
            command.pre_exec(|| {
                if libc::prctl(
                    libc::PR_SET_NO_NEW_PRIVS,
                    1 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                ) < 0
                    || libc::syscall(
                        libc::SYS_close_range,
                        3 as libc::c_ulong,
                        u32::MAX as libc::c_ulong,
                        libc::CLOSE_RANGE_CLOEXEC as libc::c_ulong,
                    ) < 0
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut process = command.spawn()?;
        let pid = Pid::from_child(&process);
        let pidfd = match pidfd_open(pid, PidfdFlags::empty()) {
            Ok(fd) => fd,
            Err(error) => {
                let _ = process.kill();
                let _ = process.wait();
                return Err(error.into());
            }
        };
        let mut worker = Self {
            serving: Arc::new(ServingWorker {
                identity: RunningWorker {
                    release,
                    sha256,
                    pid: process.id(),
                    generation,
                },
                pidfd,
            }),
            process,
            channel,
            sequence: 0,
        };
        let hello = Message {
            kind: Decision::Hello,
            generation,
            sequence: 0,
            value: 0,
        };
        if worker.exchange(hello, HELLO_TIMEOUT)? != 0 {
            return Err(io::Error::other("worker rejected resident handshake"));
        }
        // A negotiated worker must also answer one harmless policy probe.
        worker.choose(1)?;
        Ok(worker)
    }

    fn exchange(&self, request: Message, timeout: Duration) -> io::Result<u8> {
        let deadline = Instant::now() + timeout;
        request.send(&self.channel)?;
        let response = Message::receive(&self.channel, Some(deadline))?;
        if response.kind != request.kind
            || response.generation != request.generation
            || response.sequence != request.sequence
        {
            return Err(io::Error::other("stale or mismatched worker response"));
        }
        Ok(response.value)
    }

    fn choose(&mut self, count: usize) -> io::Result<usize> {
        if !(1..=MAX_SPACES).contains(&count) {
            return Err(io::Error::other("invalid resident Space cohort"));
        }
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or_else(|| io::Error::other("policy sequence exhausted"))?;
        let index = self.exchange(
            Message {
                kind: Decision::Choose,
                generation: self.serving.identity.generation,
                sequence: self.sequence,
                value: count as u8,
            },
            DECISION_TIMEOUT,
        )? as usize;
        if index >= count || !self.alive()? {
            return Err(io::Error::other(
                "worker did not propose a current eligible Space",
            ));
        }
        Ok(index)
    }

    fn alive(&mut self) -> io::Result<bool> {
        Ok(self.process.try_wait()?.is_none())
    }
}

impl Drop for Worker {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

#[derive(Default)]
struct State {
    selection: Selection,
    worker: Option<Arc<ServingWorker>>,
    note: Option<String>,
    selection_note: Option<String>,
    generation: u64,
    update_pending: bool,
    read_engine: RunningReadEngine,
}

impl State {
    fn live_worker(&self) -> Option<&RunningWorker> {
        self.worker
            .as_ref()
            .filter(|worker| worker.alive())
            .map(|worker| &worker.identity)
    }
}

struct Managed {
    store: Store,
    resident_hash: String,
    state: Mutex<State>,
    worker: Mutex<Option<Worker>>,
    switch_requested: AtomicBool,
    turn: Mutex<()>,
}

pub(crate) struct Policy {
    managed: Option<Managed>,
    read_program: Arc<ReadEngines>,
}

pub(crate) struct Turn<'a> {
    managed: Option<&'a Managed>,
    _drain: Option<MutexGuard<'a, ()>>,
}

struct Switch<'a>(&'a AtomicBool);

impl Drop for Switch<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl Policy {
    pub(crate) fn open(root: Option<&Path>) -> io::Result<Self> {
        let read_program = Arc::new(ReadEngines::default());
        let Some(root) = root else {
            return Ok(Self {
                managed: None,
                read_program,
            });
        };
        let store = Store::open(root)?;
        store.lock_resident()?;
        let mut state = State::default();
        let mut active = None;
        let resident_hash = artifacts::resident_hash()?;
        let result = (|| -> io::Result<()> {
            state.selection = store.selection()?;
            if let Some(current) = &state.selection.current {
                state.generation = 1;
                let set = store.set(current)?;
                state.update_pending = set.manifest.artifacts.resident != resident_hash;
                let program = set.read_program()?;
                let mut worker = Worker::start(
                    set.worker()?,
                    current.clone(),
                    set.manifest.artifacts.worker,
                    1,
                )?;
                if !worker.alive()? {
                    return Err(io::Error::other("selected worker exited"));
                }
                read_program.publish(1, program);
                state.read_engine = read_identity(current, set.manifest.artifacts.read_engine, 1);
                state.worker = Some(Arc::clone(&worker.serving));
                active = Some(worker);
            } else {
                state.note =
                    Some("no verified release selected; automatic transfers paused".into());
            }
            Ok(())
        })();
        if let Err(error) = result {
            state.note = Some(format!(
                "cannot start selected worker; automatic transfers paused: {error}"
            ));
        }
        Ok(Self {
            managed: Some(Managed {
                store,
                resident_hash,
                state: Mutex::new(state),
                worker: Mutex::new(active),
                switch_requested: AtomicBool::new(false),
                turn: Mutex::new(()),
            }),
            read_program,
        })
    }

    pub(crate) fn managed(&self) -> bool {
        self.managed.is_some()
    }

    pub(crate) fn turn(&self) -> Option<Turn<'_>> {
        if let Some(managed) = &self.managed {
            let drain = managed.turn.try_lock().ok()?;
            if managed.switch_requested.load(Ordering::Acquire) {
                return None;
            }
            Some(Turn {
                managed: Some(managed),
                _drain: Some(drain),
            })
        } else {
            Some(Turn {
                managed: None,
                _drain: None,
            })
        }
    }

    pub(crate) fn available(&self) -> bool {
        self.managed
            .as_ref()
            .is_none_or(|managed| managed.state().live_worker().is_some())
    }

    pub(crate) fn reap_exited(&self) {
        if let Some(managed) = &self.managed
            && let Ok(mut active) = managed.worker.try_lock()
            && active
                .as_mut()
                .is_some_and(|worker| matches!(worker.alive(), Ok(false)))
        {
            // Already reaped; published liveness remains readable via pidfd.
            drop(active.take());
        }
    }

    pub(crate) fn status(&self, automatic: bool) -> ReleaseStatus {
        let mut status = ReleaseStatus {
            managed: self.managed(),
            installation: None,
            resident_pid: std::process::id(),
            resident_version: env!("CARGO_PKG_VERSION").into(),
            resident_sha256: None,
            selected_release: None,
            previous_release: None,
            worker: None,
            draining_policy_turn: false,
            automatic_sync: automatic,
            resident_update_pending: false,
            note: None,
        };
        if let Some(managed) = &self.managed {
            let state = managed.state();
            status.installation = Some(managed.store.identity.clone());
            status.resident_sha256 = Some(managed.resident_hash.clone());
            status.selected_release = state.selection.current.clone();
            status.previous_release = state.selection.previous.clone();
            status.draining_policy_turn = managed.switch_requested.load(Ordering::Acquire);
            status.worker = state.live_worker().map(|id| RunningWorker {
                release: id.release.clone(),
                sha256: id.sha256.clone(),
                pid: id.pid,
                generation: id.generation,
            });
            status.automatic_sync &= status.worker.is_some();
            status.resident_update_pending = state.update_pending;
            let note = if state.worker.is_some() && status.worker.is_none() {
                Some(WORKER_EXITED)
            } else {
                state.note.as_deref()
            };
            status.note = match (note, state.selection_note.as_deref()) {
                (Some(note), Some(selection)) => Some(format!("{note}; {selection}")),
                (note, selection) => note.or(selection).map(str::to_owned),
            };
        }
        status
    }

    pub(crate) fn read_program(&self) -> Arc<ReadEngines> {
        Arc::clone(&self.read_program)
    }

    pub(crate) fn read_engine(&self) -> RunningReadEngine {
        let Some(managed) = &self.managed else {
            return RunningReadEngine::default();
        };
        let state = managed.state();
        let engine = &state.read_engine;
        RunningReadEngine {
            release: engine.release.clone(),
            sha256: engine.sha256.clone(),
            generation: engine.generation,
        }
    }

    pub(crate) fn authorize_credential_policy(
        &self,
        request: CredentialPolicyRequest,
    ) -> io::Result<CredentialPolicy> {
        let managed = self.managed.as_ref().ok_or_else(|| {
            io::Error::other("this resident does not own a signed user release install")
        })?;
        match request {
            CredentialPolicyRequest::Activate { release } => managed
                .store
                .set(&release)?
                .manifest
                .credential_policy
                .ok_or_else(|| {
                    io::Error::other("signed release does not specify a credential policy")
                }),
            CredentialPolicyRequest::Rollback => Ok(CredentialPolicy::StandardV1),
            CredentialPolicyRequest::Status => {
                Err(io::Error::other("expected a credential policy change"))
            }
        }
    }

    pub(crate) fn activate(&self, request: ReleaseRequest) -> io::Result<()> {
        let managed = self.managed.as_ref().ok_or_else(|| {
            io::Error::other(
                "this resident does not own a signed user release install; maintenance is required",
            )
        })?;
        let (id, generation, previous) = {
            let mut state = managed.state();
            let id = match request {
                ReleaseRequest::Activate { release } => release,
                ReleaseRequest::Rollback => state
                    .selection
                    .previous
                    .clone()
                    .ok_or_else(|| io::Error::other("no previous release is recorded"))?,
                ReleaseRequest::Status
                | ReleaseRequest::MountEngines
                | ReleaseRequest::CredentialPolicy(_) => {
                    return Err(io::Error::other("expected a release change"));
                }
            };
            if state.live_worker().is_some_and(|worker| worker.release == id) {
                let retry_sync = state.selection_note.is_some();
                drop(state);
                return if retry_sync {
                    managed.sync_selection()
                } else {
                    Ok(())
                };
            }
            state.generation = state
                .generation
                .checked_add(1)
                .filter(|generation| *generation <= ReadEngines::MAX_GENERATION)
                .ok_or_else(|| io::Error::other("policy generation exhausted"))?;
            let previous = if state.selection.current.as_ref() == Some(&id) {
                state.selection.previous.clone()
            } else {
                state.selection.current.clone()
            };
            (id, state.generation, previous)
        };
        // Authentication and negotiation grant the candidate no admission.
        // An invalid candidate cannot interrupt a currently serving worker.
        let set = managed.store.set(&id)?;
        let program = set.read_program()?;
        let engine = read_identity(&id, set.manifest.artifacts.read_engine.clone(), generation);
        let executable = set.worker()?;
        let update_pending = set.manifest.artifacts.resident != managed.resident_hash;
        let mut candidate = Worker::start(
            executable,
            id.clone(),
            set.manifest.artifacts.worker,
            generation,
        )?;

        managed.switch_requested.store(true, Ordering::Release);
        let switch = Switch(&managed.switch_requested);
        let deadline = Instant::now() + DRAIN_TIMEOUT;
        let _drain = loop {
            match managed.turn.try_lock() {
                Ok(guard) => break guard,
                Err(TryLockError::WouldBlock) if Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                _ => {
                    return Err(io::Error::other(
                        "admitted policy turn did not drain; selection unchanged",
                    ));
                }
            }
        };
        if !candidate.alive()? {
            return Err(io::Error::other(
                "candidate exited while waiting for the admitted turn",
            ));
        }
        let selection = Selection {
            current: Some(id),
            previous,
        };
        managed.store.select(&selection)?;
        let old = {
            let mut worker = managed.worker.lock().expect("release worker lock poisoned");
            let mut state = managed.state();
            // The rename is visible to launchers. Publish its generation now;
            // directory sync may take arbitrarily long or fail.
            state.selection = selection;
            state.update_pending = update_pending;
            state.note = None;
            state.selection_note = Some(SELECTION_PENDING.into());
            self.read_program.publish(generation, program);
            state.read_engine = engine;
            state.worker = Some(Arc::clone(&candidate.serving));
            let old = worker.replace(candidate);
            // Status must see the new generation and the end of draining together.
            // The turn guard still blocks admission through sync and retirement.
            drop(switch);
            old
        };
        let durable = managed.sync_selection();
        drop(old);
        // The same turn fence covers old response validation, final admission
        // and all resident effects. Nobody can consume a response from `old`.
        if managed.state().live_worker().is_none() {
            return Err(io::Error::other(
                "selected worker exited; automatic transfers paused",
            ));
        }
        durable
    }
}

fn read_identity(release: &str, sha256: Option<String>, generation: u64) -> RunningReadEngine {
    RunningReadEngine {
        release: sha256.as_ref().map(|_| release.to_owned()),
        sha256,
        generation,
    }
}

impl Managed {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("release state lock poisoned")
    }

    fn sync_selection(&self) -> io::Result<()> {
        let note = self.store.sync_selection().err().map(|error| {
            format!("activation visible, but release selection durability is unknown: {error}")
        });
        let result = note
            .as_ref()
            .map_or(Ok(()), |note| Err(io::Error::other(note.clone())));
        self.state().selection_note = note;
        result
    }
}

impl Turn<'_> {
    pub(crate) fn choose(&self, count: usize) -> Option<usize> {
        let Some(managed) = self.managed else {
            return (count != 0).then_some(0);
        };
        if count == 0 || managed.switch_requested.load(Ordering::Acquire) {
            return None;
        }
        let mut active = managed.worker.lock().expect("release worker lock poisoned");
        let worker = active.as_mut()?;
        if !worker.serving.alive() {
            return None;
        }
        match worker.choose(count) {
            Ok(index) => Some(index),
            Err(error) => {
                {
                    let mut state = managed.state();
                    state.worker = None;
                    state.note = Some(format!(
                        "worker protocol failed; automatic transfers paused: {error}"
                    ));
                }
                let failed = active.take();
                drop(active);
                drop(failed);
                None
            }
        }
    }

    pub(crate) fn still_selected(&self) -> bool {
        self.managed.is_none_or(|managed| {
            // The held turn fences generation replacement. Recheck liveness
            // after validating the Space, before the resident admits effects.
            managed.state().live_worker().is_some()
                && !managed.switch_requested.load(Ordering::Acquire)
        })
    }
}

pub(crate) fn launch_client(
    root: &Path,
    role: &str,
    bootstrap: &Path,
    args: &[OsString],
) -> io::Result<()> {
    let store = Store::open(root)?;
    let Some(id) = store.selection()?.current else {
        return Err(Command::new(bootstrap)
            .env_remove("CIRRUS_RUNNING_RELEASE")
            .args(args)
            .exec());
    };
    store.set(&id)?.launch(role, args)
}
