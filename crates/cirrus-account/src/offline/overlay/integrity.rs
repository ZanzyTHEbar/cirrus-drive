//! Bounded integrity admission for every retained original-byte dependency.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock};

use sha2::{Digest, Sha256};

use super::super::{MAX_STAGING_FILES, open_staged_in, verify_staged_metadata};
use super::{AccountError, BLOCK, Object, Overlay, invalid};
use crate::account_storage::{RootIdentity, StorageRoot};

impl Overlay {
    pub(crate) fn add_required_originals(
        &self,
        originals: &mut BTreeMap<String, Object>,
    ) -> Result<(), AccountError> {
        if self.base.is_none() || self.visible_end == 0 {
            return Ok(());
        }
        let available = self.local_objects()?;
        let mut offset = 0;
        while offset < self.visible_end {
            let index = self
                .extents
                .partition_point(|extent| extent.start + extent.length <= offset);
            let extent = self.extents.get(index);
            if let Some(extent) = extent.filter(|extent| extent.start <= offset) {
                offset = (extent.start + extent.length).min(self.visible_end);
            } else {
                let block = offset / BLOCK * BLOCK;
                let object = available.get(&block).ok_or_else(|| {
                    AccountError::new(
                        "protected original content is unavailable; remote mutation refused",
                    )
                })?;
                let identity = serde_json::to_string(object).map_err(|_| invalid())?;
                originals.entry(identity).or_insert_with(|| object.clone());
                if originals.len() > MAX_STAGING_FILES {
                    return Err(invalid());
                }
                offset = (block + BLOCK)
                    .min(self.visible_end)
                    .min(extent.map_or(self.visible_end, |extent| extent.start));
            }
        }
        Ok(())
    }
}

struct Witness {
    storage: StorageRoot,
    object: Object,
    metadata: std::fs::Metadata,
}

impl Witness {
    fn verify(storage: &StorageRoot, object: &Object) -> Result<Self, AccountError> {
        if object.size == 0 || object.size > BLOCK {
            return Err(invalid());
        }
        // Bind the checkpoint metadata to the descriptor whose bytes passed SHA-256.
        let (_, metadata) = object.verified_range(storage, 0, object.size as usize)?;
        Ok(Self {
            storage: storage.clone(),
            object: object.clone(),
            metadata,
        })
    }

    fn unchanged(&self) -> Result<(), AccountError> {
        // Check by name too: replacement/unlink must invalidate the witness.
        let (file, _) = open_staged_in(&self.storage, &self.object.name)?;
        verify_staged_metadata(&file, &self.metadata)
    }
}

enum Validation {
    Checking {
        _storage: StorageRoot,
        verified: Vec<Witness>,
    },
    Invalidated,
}

enum Preparation {
    Pending(StorageRoot),
    Verified(Witness),
}

// This cache is never durable. Restart must read and checksum the entire union
// again; metadata alone cannot bless an already consumed integrity prefix.
static VALIDATIONS: OnceLock<Mutex<BTreeMap<(RootIdentity, String), Arc<Mutex<Validation>>>>> =
    OnceLock::new();

// Progress has its own ephemeral witnesses: a persisted cursor is never a
// substitute for actual bytes after restart. Keep growing captures reusable
// without rehashing the entire prefix on every automatic preparation turn.
static PREPARATIONS: OnceLock<Mutex<BTreeMap<(RootIdentity, String), Arc<Mutex<Preparation>>>>> =
    OnceLock::new();

fn same_object(left: &Object, right: &Object) -> bool {
    left.name == right.name && left.size == right.size && left.blocks == right.blocks
}

pub(super) fn verify_preparation(
    storage: &StorageRoot,
    objects: &BTreeMap<u64, Object>,
    bounded: bool,
) -> Result<bool, AccountError> {
    if objects.len() > 4096 {
        return Err(invalid());
    }
    let registry = PREPARATIONS.get_or_init(Default::default);
    let mut bytes = 0;
    let mut checked = Vec::with_capacity(objects.len());
    for object in objects.values() {
        let key = (storage.identity(), object.name.clone());
        loop {
            let (entry, retired) = {
                let mut preparations = registry.lock().map_err(|_| invalid())?;
                let retired = if !preparations.contains_key(&key) && preparations.len() >= 4096 {
                    Some(std::mem::take(&mut *preparations))
                } else {
                    None
                };
                let entry = Arc::clone(preparations.entry(key.clone()).or_insert_with(|| {
                    Arc::new(Mutex::new(Preparation::Pending(storage.clone())))
                }));
                (entry, retired)
            };
            drop(retired);
            let mut preparation = entry.lock().map_err(|_| invalid())?;
            match &*preparation {
                Preparation::Verified(witness) => {
                    if !same_object(&witness.object, object) || witness.unchanged().is_err() {
                        // Never replace the proof inside an existing entry:
                        // snapshots of it must lose their registry authority.
                        let removed = {
                            let mut preparations = registry.lock().map_err(|_| invalid())?;
                            if preparations
                                .get(&key)
                                .is_some_and(|current| Arc::ptr_eq(current, &entry))
                            {
                                preparations.remove(&key)
                            } else {
                                None
                            }
                        };
                        drop(removed);
                        continue;
                    }
                }
                Preparation::Pending(storage) => {
                    if bounded && bytes + object.size > 1024 * 1024 {
                        return Ok(false);
                    }
                    let witness = Witness::verify(storage, object)?;
                    *preparation = Preparation::Verified(witness);
                    bytes += object.size;
                    crate::executor::mark_progress();
                }
            }
            drop(preparation);
            checked.push((key, entry));
            break;
        }
    }
    let preparations = registry.lock().map_err(|_| invalid())?;
    if checked.iter().any(|(key, entry)| {
        !preparations
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, entry))
    }) {
        return Err(invalid());
    }
    Ok(true)
}

/// Metadata-only checkpoint of the actual-byte proof, never a rehash while a
/// SQL transaction/State lease is held. Eviction/change refuses publication.
pub(super) fn preparation_unchanged(
    storage: &StorageRoot,
    objects: &BTreeMap<u64, Object>,
) -> Result<(), AccountError> {
    let registry = PREPARATIONS.get_or_init(Default::default);
    let entries = {
        let preparations = registry.lock().map_err(|_| invalid())?;
        objects
            .values()
            .map(|object| {
                let key = (storage.identity(), object.name.clone());
                let entry = Arc::clone(preparations.get(&key).ok_or_else(invalid)?);
                Ok((key, entry, object))
            })
            .collect::<Result<Vec<_>, AccountError>>()?
    };
    for (_, entry, object) in &entries {
        let preparation = entry.lock().map_err(|_| invalid())?;
        let Preparation::Verified(witness) = &*preparation else {
            return Err(invalid());
        };
        if !same_object(&witness.object, object) {
            return Err(invalid());
        }
        witness.unchanged()?;
    }
    let preparations = registry.lock().map_err(|_| invalid())?;
    if entries.iter().any(|(key, entry, _)| {
        !preparations
            .get(key)
            .is_some_and(|current| Arc::ptr_eq(current, entry))
    }) {
        return Err(invalid());
    }
    Ok(())
}

pub(crate) fn verify_protected_in(
    storage: &StorageRoot,
    names: &[String],
    originals: &BTreeMap<String, Object>,
    bounded: bool,
) -> Result<bool, AccountError> {
    if originals.is_empty() {
        return Ok(true);
    }
    let mut roots = names.to_vec();
    roots.sort_unstable();
    let mut digest = Sha256::new();
    for identity in roots.iter().chain(originals.keys()) {
        digest.update((identity.len() as u64).to_be_bytes());
        digest.update(identity.as_bytes());
    }
    let key = (storage.identity(), format!("{:x}", digest.finalize()));
    let registry = VALIDATIONS.get_or_init(Default::default);
    let (entry, retired) = {
        let mut validations = registry.lock().map_err(|_| invalid())?;
        // Eviction removes authority, even for a still-running owned pass.
        let retired = if !validations.contains_key(&key) && validations.len() >= 8 {
            Some(std::mem::take(&mut *validations))
        } else {
            None
        };
        let entry = Arc::clone(validations.entry(key.clone()).or_insert_with(|| {
            Arc::new(Mutex::new(Validation::Checking {
                _storage: storage.clone(),
                verified: Vec::new(),
            }))
        }));
        (entry, retired)
    };
    drop(retired);
    let mut pass = entry.lock().map_err(|_| invalid())?;
    let Validation::Checking { verified, .. } = &mut *pass else {
        return Err(invalid());
    };
    let result = (|| {
        let mut bytes = 0;
        for object in originals.values().skip(verified.len()) {
            if object.size == 0 || object.size > BLOCK {
                return Err(invalid());
            }
            if bounded && bytes + object.size > 1024 * 1024 {
                return Ok(false);
            }
            verified.push(Witness::verify(storage, object)?);
            bytes += object.size;
            crate::executor::mark_progress();
        }
        // Keep checked prefixes immutable within this process, including while
        // the active source hash advances. Recovery-only tails are not consumed
        // by a shortened PUT stream and therefore need this final admission.
        for witness in verified {
            witness.unchanged()?;
        }
        Ok(true)
    })();
    let (removed, current) = {
        let mut validations = registry.lock().map_err(|_| invalid())?;
        let current = validations
            .get(&key)
            .is_some_and(|current| Arc::ptr_eq(current, &entry));
        let removed = if current && result.is_err() {
            validations.remove(&key)
        } else {
            None
        };
        (removed, current)
    };
    drop(removed);
    if !current || result.is_err() {
        *pass = Validation::Invalidated;
    }
    if !current {
        return Err(invalid());
    }
    result
}
