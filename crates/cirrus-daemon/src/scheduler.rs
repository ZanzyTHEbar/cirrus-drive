//! One account transfer owner, round-robin Space turns, foreground-first admission.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use cirrus_account::Accounts;

const POLL: Duration = Duration::from_secs(2);

struct Control {
    accounts: Arc<Accounts>,
    busy: Arc<AtomicBool>,
    pending: AtomicUsize,
    paused: AtomicBool,
    stopping: AtomicBool,
    admission: Mutex<()>,
    wake: Condvar,
    sleep: Mutex<()>,
}

pub(crate) struct Scheduler {
    control: Arc<Control>,
    thread: Option<JoinHandle<()>>,
}

pub(crate) struct Foreground {
    control: Arc<Control>,
    claimed: bool,
    _priority: cirrus_account::ForegroundPriority,
}

struct Background(Arc<Control>);
impl Drop for Background {
    fn drop(&mut self) {
        let _gate = self
            .0
            .admission
            .lock()
            .expect("account admission lock poisoned");
        self.0.busy.store(false, Ordering::Release);
        self.0.wake.notify_all();
    }
}

impl Foreground {
    pub(crate) fn wait(&mut self) -> io::Result<()> {
        while !self.claimed {
            if self.control.paused.load(Ordering::Acquire) {
                return Err(io::Error::other(
                    "shutdown waiting for account operation; retry stop",
                ));
            }
            {
                let _gate = self
                    .control
                    .admission
                    .lock()
                    .map_err(|_| io::Error::other("account admission unavailable"))?;
                self.claimed = self
                    .control
                    .busy
                    .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok();
            }
            if !self.claimed {
                thread::sleep(Duration::from_millis(20));
            }
        }
        Ok(())
    }
}

impl Drop for Foreground {
    fn drop(&mut self) {
        let _gate = self
            .control
            .admission
            .lock()
            .expect("account admission lock poisoned");
        if self.claimed {
            self.control.busy.store(false, Ordering::Release);
        }
        self.control.pending.fetch_sub(1, Ordering::AcqRel);
        self.control.wake.notify_all();
    }
}

impl Scheduler {
    pub(crate) fn start(
        accounts: Arc<Accounts>,
        busy: Arc<AtomicBool>,
        mounts: Arc<Mutex<Vec<cirrus_fuse::Mounted>>>,
        enabled: bool,
    ) -> io::Result<Self> {
        let control = Arc::new(Control {
            accounts,
            busy,
            pending: AtomicUsize::new(0),
            paused: AtomicBool::new(false),
            stopping: AtomicBool::new(false),
            admission: Mutex::new(()),
            wake: Condvar::new(),
            sleep: Mutex::new(()),
        });
        if !enabled {
            return Ok(Self {
                control,
                thread: None,
            });
        }
        // Existing fault scenarios deliberately inspect manual-sync boundaries.
        // This switch is absent from normal binaries and never reads real homes.
        #[cfg(feature = "fault-injection")]
        if std::env::var("CIRRUS_TEST_AUTO_SYNC").ok().as_deref() != Some("1") {
            return Ok(Self {
                control,
                thread: None,
            });
        }
        let worker = Arc::clone(&control);
        let thread = thread::Builder::new()
            .name("cirrus-sync".into())
            .spawn(move || {
                let mut after: Option<(String, String)> = None;
                let mut leader = None;
                let mut refreshed = Instant::now();
                let mut mount_after = 0;
                #[cfg(feature = "fault-injection")]
                let mut diagnostic_events = 0;
                loop {
                    let mut progressed = false;
                    if worker.stopping.load(Ordering::Acquire) {
                        break;
                    }
                    if !worker.paused.load(Ordering::Acquire)
                        && worker.pending.load(Ordering::Acquire) == 0
                        && let Ok(spaces) = worker.accounts.activated_spaces()
                    {
                        if !spaces.is_empty() && leader.is_none() {
                            leader = worker.accounts.acquire_scheduler().ok();
                        }
                        let next =
                            spaces
                                .iter()
                                .filter(|key| after.as_ref().is_none_or(|after| *key > after))
                                .chain(spaces.iter().filter(|key| {
                                    after.as_ref().is_some_and(|after| *key <= after)
                                }))
                                .find(|(instance, space)| {
                                    leader.is_some()
                                        && !worker.accounts.background_yield_requested()
                                        && !worker.stopping.load(Ordering::Acquire)
                                        && !worker.paused.load(Ordering::Acquire)
                                        && worker.pending.load(Ordering::Acquire) == 0
                                        && worker.accounts.sync_status(instance, space).is_ok_and(
                                            |status| {
                                                status.new_work
                                                    && !matches!(
                                                        status.phase,
                                                        cirrus_account::SyncPhase::Retry
                                                            | cirrus_account::SyncPhase::Attention
                                                    )
                                            },
                                        )
                                })
                                .cloned();
                        if let Some((instance, space)) = next {
                            after = Some((instance.clone(), space.clone()));
                            let admitted = {
                                let _gate = worker
                                    .admission
                                    .lock()
                                    .expect("account admission lock poisoned");
                                worker.pending.load(Ordering::Acquire) == 0
                                    && !worker.paused.load(Ordering::Acquire)
                                    && worker
                                        .busy
                                        .compare_exchange(
                                            false,
                                            true,
                                            Ordering::AcqRel,
                                            Ordering::Acquire,
                                        )
                                        .is_ok()
                            };
                            if admitted {
                                let permit = Background(Arc::clone(&worker));
                                #[cfg(feature = "fault-injection")]
                                if std::env::var_os("CIRRUS_TEST_AUTO_DIAGNOSTICS").is_some() && diagnostic_events < 1024 {
                                    diagnostic_events += 1;
                                    eprintln!("cirrus lab scheduler diagnostic: time_ms={} begin space={space}",std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis());
                                }
                                let result = worker
                                    .accounts
                                    .automatic_sync_turn(&instance, &space);
                                #[cfg(feature = "fault-injection")]
                                if std::env::var_os("CIRRUS_TEST_AUTO_DIAGNOSTICS").is_some() && diagnostic_events < 1024 {
                                    diagnostic_events += 1;
                                    eprintln!("cirrus lab scheduler diagnostic: time_ms={} end space={space} result={result:?}",std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis());
                                }
                                progressed = result.unwrap_or(false);
                                #[cfg(feature = "fault-injection")]
                                if std::env::var_os("CIRRUS_TEST_DIRTY_RANGE").is_some() {
                                    eprintln!("cirrus lab automatic turn: progressed={progressed}");
                                }
                                worker.accounts.invalidate_mount_metadata();
                                drop(permit);
                            }
                        }
                    }
                    // One cached/viewed directory from one mount, outside the
                    // mount-management lock. Refresh is process-local: the
                    // global transfer leader cannot see another daemon's mounts.
                    // Keep local foreground-first admission, but do not require
                    // the account-global mutation election for read-only DAV.
                    if refreshed.elapsed() >= POLL
                        && !worker.accounts.background_yield_requested()
                        && !worker.stopping.load(Ordering::Acquire)
                    {
                        refreshed = Instant::now();
                        let handle = mounts.try_lock().ok().and_then(|mounts| {
                            if mounts.is_empty() {
                                return None;
                            }
                            let index = mount_after % mounts.len();
                            mount_after = index + 1;
                            Some(mounts[index].namespace_refresh())
                        });
                        if let Some(handle) = handle {
                            let admitted = {
                                let _gate = worker
                                    .admission
                                    .lock()
                                    .expect("account admission lock poisoned");
                                worker.pending.load(Ordering::Acquire) == 0
                                    && !worker.paused.load(Ordering::Acquire)
                                    && worker
                                        .busy
                                        .compare_exchange(
                                            false,
                                            true,
                                            Ordering::AcqRel,
                                            Ordering::Acquire,
                                        )
                                        .is_ok()
                            };
                            if admitted {
                                let _permit = Background(Arc::clone(&worker));
                                if let Err(error) = handle.refresh_one() {
                                    eprintln!("mounted namespace refresh deferred: {error}");
                                }
                            }
                        }
                    }
                    // A useful bounded turn releases ownership, then immediately
                    // rechecks foreground admission and rotates to the next fair
                    // Space. No-progress, idle and backoff paths still sleep.
                    if progressed {
                        thread::yield_now();
                        continue;
                    }
                    #[cfg(feature = "fault-injection")]
                    if std::env::var_os("CIRRUS_TEST_AUTO_DIAGNOSTICS").is_some() && diagnostic_events < 1024 {
                        diagnostic_events += 1;
                        eprintln!("cirrus lab scheduler diagnostic: time_ms={} sleep busy={} pending={} paused={} foreground={}",std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_millis(),worker.busy.load(Ordering::Acquire),worker.pending.load(Ordering::Acquire),worker.paused.load(Ordering::Acquire),worker.accounts.background_yield_requested());
                    }
                    let sleep = worker.sleep.lock().expect("sync wake lock poisoned");
                    let _ = worker
                        .wake
                        .wait_timeout(sleep, POLL)
                        .expect("sync wake lock poisoned");
                }
            })?;
        Ok(Self {
            control,
            thread: Some(thread),
        })
    }

    pub(crate) fn foreground(&self) -> io::Result<Foreground> {
        let _gate = self
            .control
            .admission
            .lock()
            .map_err(|_| io::Error::other("account admission unavailable"))?;
        if self.control.paused.load(Ordering::Acquire) {
            return Err(io::Error::other(
                "shutdown waiting for account operation; retry stop",
            ));
        }
        // Preserve the existing refusal of competing foreground operations.
        if self.control.pending.load(Ordering::Acquire) != 0 {
            return Err(io::Error::other("another account operation is in progress"));
        }
        self.control.pending.fetch_add(1, Ordering::AcqRel);
        let priority = self.control.accounts.request_foreground();
        let claimed = self
            .control
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        Ok(Foreground {
            control: Arc::clone(&self.control),
            claimed,
            _priority: priority,
        })
    }

    pub(crate) fn enabled(&self) -> bool {
        self.thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished())
    }

    pub(crate) fn pause(&self) {
        let _gate = self
            .control
            .admission
            .lock()
            .expect("account admission lock poisoned");
        self.control.paused.store(true, Ordering::Release);
        self.control.accounts.pause_background(true);
        self.control.wake.notify_all();
    }

    pub(crate) fn quiescent(&self) -> bool {
        !self.control.busy.load(Ordering::Acquire)
            && self.control.pending.load(Ordering::Acquire) == 0
    }

    /// Only after transfer and foreground owners have quiesced may cancellation reset.
    pub(crate) fn resume(&self) {
        let _gate = self
            .control
            .admission
            .lock()
            .expect("account admission lock poisoned");
        if !self.control.busy.load(Ordering::Acquire)
            && self.control.pending.load(Ordering::Acquire) == 0
        {
            self.control.accounts.reset_cancel();
            self.control.accounts.pause_background(false);
            self.control.paused.store(false, Ordering::Release);
            self.control.wake.notify_all();
        }
    }

    pub(crate) fn join(&mut self) -> io::Result<()> {
        self.pause();
        self.control.stopping.store(true, Ordering::Release);
        self.control.wake.notify_all();
        if let Some(thread) = self.thread.take() {
            thread
                .join()
                .map_err(|_| io::Error::other("sync worker panicked"))?;
        }
        Ok(())
    }
}

impl Drop for Scheduler {
    fn drop(&mut self) {
        self.control.stopping.store(true, Ordering::Release);
        self.control.accounts.cancel();
        self.control.wake.notify_all();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
