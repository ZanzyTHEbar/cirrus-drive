//! Metadata-only mount warmup. The frontier belongs to the mount, not the inode cache.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::{
    AccountError, Accounts, DirectorySnapshot, MountBinding, ReadPermit, bound_space, dav, offline,
};

const RETRY_DELAY: Duration = Duration::from_secs(30);
const REFRESH_AGE: Duration = Duration::from_secs(5 * 60);
const MAINTENANCE_TURN: Duration = Duration::from_secs(2);
const BACKGROUND_DAV_TIMEOUT: Duration = Duration::from_secs(2);

/// An observation shared by the mounted browse path and its background walk.
pub struct MountBrowseFlight<'a> {
    accounts: &'a Accounts,
    key: (String, Vec<String>),
}

impl Drop for MountBrowseFlight<'_> {
    fn drop(&mut self) {
        if let Ok(mut flights) = self.accounts.mount_browse_flights.lock() {
            flights.remove(&self.key);
            self.accounts.mount_browse_ready.notify_all();
        }
    }
}

struct WalkPath {
    parent: Option<Arc<WalkPath>>,
    name: String,
    depth: usize,
}

#[derive(Clone)]
struct Target {
    path: Option<Arc<WalkPath>>,
    id: String,
}

impl Target {
    fn root() -> Self {
        Self {
            path: None,
            id: String::new(),
        }
    }

    fn components(&self) -> Vec<String> {
        let mut components = Vec::new();
        let mut path = self.path.as_deref();
        while let Some(part) = path {
            components.push(part.name.clone());
            path = part.parent.as_deref();
        }
        components.reverse();
        components
    }
}

/// A disposable metadata frontier for one mount, independent of its hot cache.
pub struct MountMetadataWalk {
    seed: Option<DirectorySnapshot>,
    pending: Vec<Target>,
    due: Instant,
    incomplete: bool,
    initial: bool,
    single: bool,
}

impl MountMetadataWalk {
    /// Starts a walk, reusing an already validated root observation if supplied.
    pub fn new(seed: Option<DirectorySnapshot>) -> Self {
        Self {
            seed,
            pending: vec![Target::root()],
            due: Instant::now(),
            incomplete: false,
            initial: true,
            single: false,
        }
    }

    /// Whether the scheduler should admit another batch.
    pub fn ready(&self) -> bool {
        Instant::now() >= self.due
    }

    fn discover(
        &mut self,
        target: &Target,
        snapshot: &DirectorySnapshot,
    ) -> Result<(), AccountError> {
        let depth = target.path.as_ref().map_or(1, |path| path.depth + 1);
        let first_child = self.pending.len();
        let mut after = 0;
        loop {
            let page = snapshot.page(after)?;
            if page.is_empty() {
                break;
            }
            for (cookie, child) in page {
                after = cookie;
                if !child.is_directory() || !dav::valid_remote_id(child.id()) {
                    continue;
                }
                if depth > dav::MAX_PATH_DEPTH {
                    self.incomplete = true;
                    continue;
                }
                self.pending.push(Target {
                    path: Some(Arc::new(WalkPath {
                        parent: target.path.clone(),
                        name: child.name().to_owned(),
                        depth,
                    })),
                    id: child.id().to_owned(),
                });
            }
        }
        // Depth-first expansion shares parent prefixes and doesn't build a second
        // complete tree in RAM. The next batch can visit independent siblings.
        self.pending[first_child..].reverse();
        Ok(())
    }

    fn next_turn(&mut self) {
        if self.pending.is_empty() {
            self.pending = vec![Target::root()];
            if self.incomplete {
                eprintln!("mounted metadata walk incomplete; retrying in background");
            }
            self.due = self.due.max(
                Instant::now()
                    + if self.incomplete {
                        RETRY_DELAY
                    } else {
                        REFRESH_AGE
                    },
            );
            self.incomplete = false;
            self.initial = false;
        } else if !self.initial {
            self.due = self.due.max(Instant::now() + MAINTENANCE_TURN);
        }
    }
}

impl Accounts {
    /// Joins a walk's in-flight observation before loading or fetching a cold path.
    ///
    /// # Errors
    /// Reports an unavailable or busy observation.
    pub fn reserve_mount_browse(
        &self,
        mount: &str,
        path: &[String],
    ) -> Result<MountBrowseFlight<'_>, AccountError> {
        self.claim_mount_browse(mount, path, BACKGROUND_DAV_TIMEOUT)?
            .ok_or_else(|| AccountError::retryable_read("mount browse observation is busy"))
    }

    fn claim_mount_browse(
        &self,
        mount: &str,
        path: &[String],
        wait: Duration,
    ) -> Result<Option<MountBrowseFlight<'_>>, AccountError> {
        let key = (mount.to_owned(), path.to_vec());
        let flights = self
            .mount_browse_flights
            .lock()
            .map_err(|_| AccountError::new("mount browse state is unavailable"))?;
        let mut flights = if wait.is_zero() {
            flights
        } else {
            self.mount_browse_ready
                .wait_timeout_while(flights, wait, |flights| flights.contains(&key))
                .map_err(|_| AccountError::new("mount browse state is unavailable"))?
                .0
        };
        Ok(flights.insert(key.clone()).then(|| MountBrowseFlight {
            accounts: self,
            key,
        }))
    }

    /// Loads a recent, identity-bound durable browse observation with the current overlay.
    ///
    /// # Errors
    /// Refuses changed storage or an invalid retained observation.
    pub fn load_mount_browse(
        &self,
        binding: &MountBinding,
        path: &[String],
        id: &str,
        etag: Option<&str>,
        epoch: &str,
    ) -> Result<Option<(DirectorySnapshot, Duration)>, AccountError> {
        self.check_cancelled()?;
        self.storage.validate(&binding.root)?;
        offline::load_mount_browse(binding, path, id, etag, epoch, REFRESH_AGE)
    }

    /// Fetches and persists one batch of independent directories with spare read permits.
    ///
    /// # Errors
    /// Reports failed admission, storage or incomplete DAV work; retries are paced.
    pub fn warm_mount_metadata(
        &self,
        binding: &MountBinding,
        mount: &str,
        alive: &AtomicBool,
        walk: &mut MountMetadataWalk,
    ) -> Result<bool, AccountError> {
        if binding.is_offline() || !walk.ready() {
            return Ok(false);
        }
        let available = || alive.load(Ordering::Acquire) && !self.background_yield_requested();
        if !available() {
            return Ok(false);
        }
        let generation = self.metadata_generation();
        let epoch = format!("{mount}:{generation}");
        let result = (|| {
            if let Some(seed) = walk.seed.take() {
                walk.pending.pop();
                walk.discover(&Target::root(), &seed)?;
                return Ok(true);
            }
            let session = self
                .read_session
                .lock()
                .map_err(|_| AccountError::new("account state is unavailable"))?
                .clone();
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| AccountError::new("system clock is invalid"))?
                .as_secs();
            let Some(session) = session.filter(|s| {
                s.base.as_str() == binding.instance()
                    && !s.account.refresh_in_progress
                    && s.account.expires_at > now.saturating_add(30)
            }) else {
                return Ok(false);
            };
            self.storage.validate(&session.root)?;
            let space = bound_space(&session, binding)?;
            offline::verify_identity_in(
                &session.root,
                &binding.instance,
                &binding.issuer,
                &binding.subject,
            )?;
            let mut active = self
                .reads_in_flight
                .lock()
                .map_err(|_| AccountError::new("read state is unavailable"))?;
            let mut count = 3usize.saturating_sub(*active).min(walk.pending.len());
            if walk.single {
                count = count.min(1);
            }
            if count == 0 {
                return Ok(false);
            }
            *active += count;
            drop(active);
            let _permits: Vec<_> = (0..count).map(|_| ReadPermit(self)).collect();
            let observation = offline::begin_snapshot_in(&session.root)?;
            let mut requests = Vec::with_capacity(count);
            let mut flights = Vec::with_capacity(count);
            for target in walk.pending.iter().rev().take(count) {
                let path = target.components();
                let Some(flight) = self.claim_mount_browse(mount, &path, Duration::ZERO)? else {
                    return Ok(false);
                };
                flights.push(flight);
                let mapped =
                    offline::tree_remote_path(&session.root, &binding.instance, space, &path);
                let eligible = matches!(mapped, Ok((ref remote, false)) if remote == &path)
                    && offline::mount_walk_parent_matches(
                        &observation,
                        binding,
                        &path,
                        &target.id,
                    )?;
                requests.push((target.clone(), path, eligible));
            }
            let results = std::thread::scope(|scope| {
                let mut workers = Vec::with_capacity(count);
                for (_, path, eligible) in &requests {
                    let session = &session;
                    workers.push(eligible.then(|| {
                        scope.spawn(move || {
                            dav::directory_snapshot_timed_in(
                                &session.root,
                                &session.base,
                                space,
                                path,
                                &session.account.access_token,
                                &session.client,
                                BACKGROUND_DAV_TIMEOUT,
                            )
                        })
                    }));
                }
                workers
                    .into_iter()
                    .map(|worker| {
                        worker.map(|worker| {
                            worker.join().unwrap_or_else(|_| {
                                Err(AccountError::new("background DAV worker panicked"))
                            })
                        })
                    })
                    .collect::<Vec<_>>()
            });
            if !available()
                || self.metadata_generation() != generation
                || self
                    .read_session
                    .lock()
                    .map_err(|_| AccountError::new("account state is unavailable"))?
                    .as_ref()
                    .is_none_or(|current| !Arc::ptr_eq(current, &session))
            {
                return Ok(false);
            }
            if results
                .iter()
                .flatten()
                .any(|result| result.as_ref().is_err_and(|error| error.unauthorized))
            {
                self.invalidate_read_session(&session)?;
                self.invalidate_mount_metadata();
                return Ok(false);
            }
            let mut records = Vec::with_capacity(count);
            let mut rejected = Vec::new();
            let mut failed = None;
            for ((target, path, _), result) in requests.iter().zip(results) {
                match result {
                    Some(Ok(entries))
                        if target.id.is_empty() || entries.matches_parent(&target.id)? =>
                    {
                        records.push((target, path, entries));
                    }
                    Some(Err(error)) => {
                        if error.is_directory_binding_lost() {
                            rejected.push(path.as_slice());
                        }
                        if error.can_retry_read() || error.is_staging_full() {
                            let delay = error.retry_after.unwrap_or_default().max(RETRY_DELAY);
                            let now = Instant::now();
                            walk.due = walk
                                .due
                                .max(now.checked_add(delay).unwrap_or(now + RETRY_DELAY));
                        }
                        walk.incomplete = true;
                        failed.get_or_insert(error);
                    }
                    Some(Ok(_)) => {
                        walk.incomplete = true;
                        rejected.push(path.as_slice());
                    }
                    None => walk.incomplete = true,
                }
            }
            let rows: Vec<_> = records
                .iter()
                .map(|(_, path, entries)| (path.as_slice(), entries))
                .collect();
            match offline::save_mount_browse_batch(
                observation,
                (&binding.instance, space),
                &rows,
                &rejected,
                &epoch,
                || available() && self.metadata_generation() == generation,
            ) {
                Ok(true) => {}
                Ok(false) => return Ok(false),
                Err(error) => {
                    // A full parallel budget may not fit the configured storage policy.
                    // Reattempt one at a time. If a single listing doesn't fit,
                    // defer that branch to the next pass rather than blocking siblings.
                    if walk.single && error.is_staging_full() {
                        walk.pending.pop();
                    }
                    walk.single = true;
                    return Err(error);
                }
            }
            walk.single = false;
            walk.pending.truncate(walk.pending.len() - count);
            for (target, _, entries) in records.iter().rev() {
                walk.discover(target, entries)?;
            }
            if let Some(error) = failed {
                return Err(error);
            }
            Ok(true)
        })();
        if result.is_err() {
            walk.incomplete = true;
            walk.due = walk.due.max(Instant::now() + RETRY_DELAY);
        }
        walk.next_turn();
        result
    }
}
