//! Bounded integrity admission for every retained original-byte dependency.

use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

use sha2::{Digest, Sha256};

use super::super::{MAX_STAGING_FILES, open_staged, verify_staged_metadata};
use super::{AccountError, BLOCK, Object, Overlay, invalid};

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
    object: Object,
    metadata: std::fs::Metadata,
}

impl Witness {
    fn verify(object: &Object) -> Result<Self, AccountError> {
        if object.size == 0 || object.size > BLOCK {
            return Err(invalid());
        }
        let (file, metadata) = open_staged(&object.name)?;
        // Verify payload SHA-256, not just the reference or a reopened inode.
        object.range(0, object.size as usize)?;
        verify_staged_metadata(&file, &metadata)?;
        Ok(Self {
            object: object.clone(),
            metadata,
        })
    }

    fn unchanged(&self) -> Result<(), AccountError> {
        // Check by name too: replacement/unlink must invalidate the witness.
        let (file, _) = open_staged(&self.object.name)?;
        verify_staged_metadata(&file, &self.metadata)
    }
}

struct Validation {
    verified: Vec<Witness>,
}

// This cache is never durable. Restart must read and checksum the entire union
// again; metadata alone cannot bless an already consumed integrity prefix.
static VALIDATIONS: OnceLock<Mutex<BTreeMap<String, Validation>>> = OnceLock::new();

// Progress has its own ephemeral witnesses: a persisted cursor is never a
// substitute for actual bytes after restart. Keep growing captures reusable
// without rehashing the entire prefix on every automatic preparation turn.
static PREPARATIONS: OnceLock<Mutex<BTreeMap<String, Witness>>> = OnceLock::new();

fn same_object(left: &Object, right: &Object) -> bool {
    left.name == right.name && left.size == right.size && left.blocks == right.blocks
}

pub(super) fn verify_preparation(
    objects: &BTreeMap<u64, Object>,
    bounded: bool,
) -> Result<bool, AccountError> {
    if objects.len() > 4096 {
        return Err(invalid());
    }
    let mut preparations = PREPARATIONS
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| invalid())?;
    let mut bytes = 0;
    for object in objects.values() {
        if preparations.get(&object.name).is_some_and(|witness| {
            same_object(&witness.object, object) && witness.unchanged().is_ok()
        }) {
            continue;
        }
        preparations.remove(&object.name);
        if bounded && bytes + object.size > 1024 * 1024 {
            return Ok(false);
        }
        let witness = Witness::verify(object)?;
        // One metadata witness per immutable physical object, matching the
        // existing 4096-file staging bound; no per-root prefix duplication.
        if preparations.len() >= 4096 {
            preparations.clear();
        }
        preparations.insert(object.name.clone(), witness);
        bytes += object.size;
        crate::executor::mark_progress();
    }
    Ok(true)
}

/// Metadata-only checkpoint of the actual-byte proof, never a rehash while a
/// SQL transaction/State lease is held. Eviction/change refuses publication.
pub(super) fn preparation_unchanged(objects: &BTreeMap<u64, Object>) -> Result<(), AccountError> {
    let preparations = PREPARATIONS
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| invalid())?;
    for object in objects.values() {
        let witness = preparations
            .get(&object.name)
            .filter(|witness| same_object(&witness.object, object))
            .ok_or_else(invalid)?;
        witness.unchanged()?;
    }
    Ok(())
}

pub(crate) fn verify_protected(
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
    let key = format!("{:x}", digest.finalize());
    let mut validations = VALIDATIONS
        .get_or_init(Default::default)
        .lock()
        .map_err(|_| invalid())?;
    // Bound ephemeral metadata even if writers keep superseding snapshots.
    if !validations.contains_key(&key) && validations.len() >= 8 {
        validations.clear();
    }
    let pass = validations
        .entry(key.clone())
        .or_insert_with(|| Validation {
            verified: Vec::new(),
        });
    let result = (|| {
        let mut bytes = 0;
        for object in originals.values().skip(pass.verified.len()) {
            if object.size == 0 || object.size > BLOCK {
                return Err(invalid());
            }
            if bounded && bytes + object.size > 1024 * 1024 {
                return Ok(false);
            }
            pass.verified.push(Witness::verify(object)?);
            bytes += object.size;
            crate::executor::mark_progress();
        }
        // Keep checked prefixes immutable within this process, including while
        // the active source hash advances. Recovery-only tails are not consumed
        // by a shortened PUT stream and therefore need this final admission.
        for witness in &pass.verified {
            witness.unchanged()?;
        }
        Ok(true)
    })();
    if result.is_err() {
        validations.remove(&key);
    }
    result
}
