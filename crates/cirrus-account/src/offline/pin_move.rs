//! Bounded ownership planning for explicit offline remote-directory replacement.

use super::{AccountError, Connection, FileVersion, MAX_PIN_BYTES, PinTree, params};

struct Owner {
    root: Vec<String>,
    tree: PinTree,
    copy: String,
}

struct Active {
    root: Vec<String>,
    tree: PinTree,
    // Original owner and original path for each file; payloads stay in SQLite.
    files: Vec<(usize, Vec<String>)>,
}

#[derive(Default)]
struct PlanSize {
    entries: usize,
    payload: u64,
    metadata: usize,
}

fn bound_active(owner: &mut Active, size: &mut PlanSize) -> Result<(), AccountError> {
    if owner.tree.files.len() != owner.files.len() {
        return Err(refused());
    }
    let mut zipped = owner
        .tree
        .files
        .drain(..)
        .zip(owner.files.drain(..))
        .collect::<Vec<_>>();
    zipped.sort_by(|a, b| a.0.path.cmp(&b.0.path));
    for (file, origin) in zipped {
        owner.tree.files.push(file);
        owner.files.push(origin);
    }
    owner.tree.directories.sort();
    if owner.tree.directories.windows(2).any(|w| w[0].0 >= w[1].0)
        || owner.tree.files.windows(2).any(|w| w[0].path >= w[1].path)
    {
        return Err(refused());
    }
    size.entries = size
        .entries
        .checked_add(owner.tree.directories.len() + owner.tree.files.len())
        .filter(|n| *n <= 4097)
        .ok_or_else(refused)?;
    for file in &owner.tree.files {
        size.payload = size
            .payload
            .checked_add(file.size)
            .filter(|n| *n <= MAX_PIN_BYTES)
            .ok_or_else(refused)?;
    }
    size.metadata = size
        .metadata
        .checked_add(
            serde_json::to_vec(&owner.tree.directories)
                .map_err(|_| refused())?
                .len(),
        )
        .and_then(|n| n.checked_add(serde_json::to_vec(&owner.tree.files).ok()?.len()))
        .filter(|n| *n <= 16777216)
        .ok_or_else(refused)?;
    Ok(())
}

fn refused() -> AccountError {
    AccountError::new("rename would displace or split a pin")
}

fn valid_path(path: &[String]) -> bool {
    path.len() <= 128
        && path.iter().all(|part| {
            !part.is_empty()
                && part != "."
                && part != ".."
                && !part.contains('/')
                && !part.chars().any(char::is_control)
        })
}

fn subtree(tree: &PinTree, root: &[String]) -> PinTree {
    PinTree {
        is_dir: tree.directories.iter().any(|(p, _)| p == root),
        directories: tree
            .directories
            .iter()
            .filter(|(p, _)| p.starts_with(root))
            .cloned()
            .collect(),
        files: tree
            .files
            .iter()
            .filter(|f| f.path.starts_with(root))
            .cloned()
            .collect(),
    }
}

fn rebase(
    path: &[String],
    source: &[String],
    destination: &[String],
) -> Result<Vec<String>, AccountError> {
    let next = if path.starts_with(source) {
        [destination, &path[source.len()..]].concat()
    } else {
        path.to_vec()
    };
    if !valid_path(&next) {
        return Err(refused());
    }
    super::path_key(&next)?;
    Ok(next)
}

fn verified_tree(
    conn: &Connection,
    account: (&str, &str),
    root: &[String],
) -> Result<PinTree, AccountError> {
    let (instance, space) = account;
    let key = super::path_key(root)?;
    let is_dir: bool = conn
        .query_row(
            "SELECT is_dir FROM pins WHERE instance=?1 AND space=?2 AND root=?3",
            params![instance, space, key],
            |row| row.get(0),
        )
        .map_err(|_| refused())?;
    let (dirs, manifest): (String, String) = conn
        .query_row(
            "SELECT directories,manifest FROM pins WHERE instance=?1 AND space=?2 AND root=?3",
            params![instance, space, key],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| refused())?;
    let directories: Vec<(Vec<String>, String)> =
        serde_json::from_str(&dirs).map_err(|_| refused())?;
    let files: Vec<FileVersion> = serde_json::from_str(&manifest).map_err(|_| refused())?;
    if directories.len() + files.len() > 4097
        || directories.windows(2).any(|w| w[0].0 >= w[1].0)
        || files.windows(2).any(|w| w[0].path >= w[1].path)
        || (is_dir && directories.first().map(|(p, _)| p.as_slice()) != Some(root))
        || (!is_dir && (!directories.is_empty() || files.len() != 1 || files[0].path != root))
    {
        return Err(refused());
    }
    let has_parent = |path: &[String]| {
        path.split_last().is_some_and(|(_, parent)| {
            directories
                .binary_search_by(|(p, _)| p.as_slice().cmp(parent))
                .is_ok()
        })
    };
    for (path, id) in &directories {
        if !valid_path(path) || !path.starts_with(root)
            // Space-root pins use the existing empty-ID sentinel; it is not a
            // remote resource identity and never authorizes either MOVE side.
            || !(crate::dav::valid_remote_id(id) || (path.is_empty() && id.is_empty()))
            || (path != root && !has_parent(path))
        {
            return Err(refused());
        }
    }
    let count: usize = conn
        .query_row(
            "SELECT count(*) FROM files WHERE instance=?1 AND space=?2 AND root=?3",
            params![instance, space, key],
            |row| row.get(0),
        )
        .map_err(|_| refused())?;
    let orphans:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM chunks c WHERE c.instance=?1 AND c.space=?2 AND c.root=?3 AND NOT EXISTS(SELECT 1 FROM files f WHERE f.instance=c.instance AND f.space=c.space AND f.root=c.root AND f.path=c.path))",params![instance,space,key],|row|row.get(0)).map_err(|_|refused())?;
    if count != files.len() || orphans {
        return Err(refused());
    }
    let mut bytes = 0u64;
    for version in &files {
        if !valid_path(&version.path)
            || !version.path.starts_with(root)
            || version.instance != instance
            || version.space != space
            || !crate::dav::valid_remote_id(&version.id)
            || !crate::dav::strong_etag(&version.etag)
            || (is_dir
                && (!has_parent(&version.path)
                    || directories
                        .binary_search_by(|(p, _)| p.cmp(&version.path))
                        .is_ok()))
        {
            return Err(refused());
        }
        bytes = bytes
            .checked_add(version.size)
            .filter(|n| *n <= MAX_PIN_BYTES)
            .ok_or_else(refused)?;
        let stored:String=conn.query_row("SELECT CASE WHEN length(version)<=16777216 THEN version END FROM files WHERE instance=?1 AND space=?2 AND root=?3 AND path=?4 AND verified_complete=1",params![instance,space,key,super::path_key(&version.path)?],|row|row.get(0)).map_err(|_|refused())?;
        let stored: FileVersion = serde_json::from_str(&stored).map_err(|_| refused())?;
        if stored != *version {
            return Err(refused());
        }
        crate::recovery::verify_active_file(conn, instance, space, &key, version)?;
    }
    Ok(PinTree {
        is_dir,
        directories,
        files,
    })
}

// Visit the same authenticated, complete ID/ETag/generation-bound observations
// that the caller retains as immutable MOVE proofs later in this transaction.
// With no containing capture, only the source root comes from that proof alone:
// every descendant directory (including empty ones) needs explicit pin metadata,
// and every file needs an exact verified donor. Dirty overlays cannot fill gaps.
fn incoming_tree(
    conn: &Connection,
    binding: &crate::MountBinding,
    source: &[String],
    owners: &[Owner],
) -> Result<Active, AccountError> {
    // This is capture synthesis, not permission to create pinned coverage
    // from observations alone (even for an observed-empty source root).
    let covers_source =
        |owner: &Owner| owner.root.starts_with(source) || source.starts_with(&owner.root);
    if !owners.iter().any(covers_source) {
        return Err(refused());
    }
    let mut incoming = Active {
        root: source.to_vec(),
        tree: PinTree {
            is_dir: true,
            directories: Vec::new(),
            files: Vec::new(),
        },
        files: Vec::new(),
    };
    let mut size = PlanSize::default();
    super::visit_tree_proofs(conn, binding, source, None, |path, observation| {
        let (id, _) = observation.remote_parent()?;
        if path != source
            && !owners
                .iter()
                .filter(|owner| covers_source(owner))
                .any(|owner| {
                    owner
                        .tree
                        .directories
                        .binary_search_by(|(p, _)| p.as_slice().cmp(path))
                        .is_ok_and(|index| owner.tree.directories[index].1 == id)
                })
        {
            return Err(refused());
        }
        size.entries = size
            .entries
            .checked_add(1)
            .filter(|n| *n <= 4097)
            .ok_or_else(refused)?;
        size.metadata = size
            .metadata
            .checked_add(
                serde_json::to_vec(&(path, &id))
                    .map_err(|_| refused())?
                    .len(),
            )
            .filter(|n| *n <= 16777216)
            .ok_or_else(refused)?;
        incoming.tree.directories.push((path.to_vec(), id));
        let mut after = 0;
        loop {
            let page = observation.page(after)?;
            if page.is_empty() {
                break;
            }
            for (cookie, entry) in page {
                after = cookie;
                if entry.is_directory() {
                    continue;
                }
                let mut path = path.to_vec();
                path.push(entry.name().to_owned());
                let version = FileVersion {
                    instance: binding.instance.clone(),
                    space: binding.space.clone(),
                    path,
                    id: entry.id().to_owned(),
                    etag: entry
                        .etag()
                        .filter(|etag| crate::dav::strong_etag(etag))
                        .ok_or_else(refused)?
                        .to_owned(),
                    size: entry.size().ok_or_else(refused)?,
                    checksums: entry.checksums().to_vec(),
                };
                let mut donor = None;
                for (index, owner) in owners
                    .iter()
                    .enumerate()
                    .filter(|(_, owner)| covers_source(owner))
                {
                    if let Ok(file) = owner
                        .tree
                        .files
                        .binary_search_by(|file| file.path.cmp(&version.path))
                    {
                        if owner.tree.files[file] != version {
                            return Err(refused());
                        }
                        donor.get_or_insert(index);
                    }
                }
                let donor = donor.ok_or_else(refused)?;
                size.entries = size
                    .entries
                    .checked_add(1)
                    .filter(|n| *n <= 4097)
                    .ok_or_else(refused)?;
                size.payload = size
                    .payload
                    .checked_add(version.size)
                    .filter(|n| *n <= MAX_PIN_BYTES)
                    .ok_or_else(refused)?;
                size.metadata = size
                    .metadata
                    .checked_add(serde_json::to_vec(&version).map_err(|_| refused())?.len())
                    .filter(|n| *n <= 16777216)
                    .ok_or_else(refused)?;
                incoming.files.push((donor, version.path.clone()));
                incoming.tree.files.push(version);
            }
        }
        Ok(())
    })?;
    bound_active(&mut incoming, &mut PlanSize::default())?;
    Ok(incoming)
}

fn validate_local_additions(
    conn: &Connection,
    binding: &crate::MountBinding,
    source: &[String],
    incoming: &PinTree,
) -> Result<(), AccountError> {
    // Captured dirty bases were checked per owner. An uncaptured path is
    // allowed only as a separately owned, never-admitted local create, not as
    // a substitute donor for anything in the immutable remote proof above.
    let mut statement=conn.prepare("SELECT id,path FROM operation_journal WHERE instance=?1 AND space=?2 AND state IN ('pending','conflict','uncertain')").map_err(|_|refused())?;
    let rows = statement
        .query_map(params![binding.instance, binding.space], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|_| refused())?;
    for row in rows {
        let (id, encoded) = row.map_err(|_| refused())?;
        let path: Vec<String> = serde_json::from_str(&encoded).map_err(|_| refused())?;
        if path.starts_with(source)
            && incoming
                .files
                .binary_search_by(|file| file.path.cmp(&path))
                .is_err()
        {
            local_create(conn, binding, id, &path, None)?;
            let parents = super::load_operation_parents(conn, id, &path)?;
            super::validate_parent_dependencies(
                conn,
                &binding.instance,
                &binding.space,
                &path,
                &parents,
            )?;
            for (index, parent) in parents.iter().enumerate().skip(source.len() - 1) {
                let ancestor = &path[..=index];
                match parent {
                    super::DirectoryIdentity::Remote(id) => {
                        if !incoming
                            .directories
                            .binary_search_by(|(p, _)| p.as_slice().cmp(ancestor))
                            .is_ok_and(|i| incoming.directories[i].1 == *id)
                        {
                            return Err(refused());
                        }
                    }
                    super::DirectoryIdentity::Pending(id) => {
                        local_create(conn, binding, *id, ancestor, Some("mkdir"))?
                    }
                }
            }
        }
    }
    Ok(())
}

// Local identity is established by the existing journal and mkdir observation,
// never by a made-up remote ID/FileVersion. Even resolved same-path history is
// refused here: absence after a local delete/rename is not a fresh create.
fn local_create(
    conn: &Connection,
    binding: &crate::MountBinding,
    id: i64,
    path: &[String],
    kind: Option<&str>,
) -> Result<(), AccountError> {
    let key = super::path_key(path)?;
    let eligible: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM operation_journal j JOIN operation_parents p ON p.operation_id=j.id WHERE j.id=?1 AND j.instance=?2 AND j.space=?3 AND j.path=?4 AND j.state='pending' AND j.op_type IN ('mkdir','write') AND (?5 IS NULL OR j.op_type=?5) AND j.base_file_id IS NULL AND j.base_etag IS NULL AND j.confirmed_file_id IS NULL AND j.confirmed_etag IS NULL AND j.error_msg IS NULL AND p.destination_parents IS NULL AND NOT EXISTS(SELECT 1 FROM sync_reads WHERE operation_id=j.id) AND NOT EXISTS(SELECT 1 FROM mutation_receipts WHERE operation_id=j.id) AND NOT EXISTS(SELECT 1 FROM upload_verifications WHERE operation_id=j.id) AND NOT EXISTS(SELECT 1 FROM verified_uploads WHERE operation_id=j.id) AND NOT EXISTS(SELECT 1 FROM tree_targets WHERE operation_id=j.id) AND NOT EXISTS(SELECT 1 FROM write_dependencies WHERE operation_id=j.id OR predecessor_id=j.id) AND NOT EXISTS(SELECT 1 FROM operation_journal c WHERE c.error_msg='destination-operation:'||j.id) AND NOT EXISTS(SELECT 1 FROM operation_journal other WHERE other.id<>j.id AND (other.staged_file=j.staged_file OR (other.instance=j.instance AND other.space=j.space AND other.path=j.path))) AND ((j.op_type='write' AND EXISTS(SELECT 1 FROM dirty_roots r WHERE r.root=j.staged_file AND r.base IS NULL)) OR (j.op_type='mkdir' AND EXISTS(SELECT 1 FROM snapshots s WHERE s.instance=j.instance AND s.space=j.space AND s.path=j.path AND s.local_operation=j.id AND s.entries='[]' AND s.self_id IS NULL AND s.self_etag IS NULL AND s.issuer=?6 AND s.subject=?7))))",params![id,binding.instance,binding.space,key,kind,binding.issuer,binding.subject],|row|row.get(0)).map_err(|_|refused())?;
    if !eligible {
        return Err(refused());
    }
    let (operation, token): (String, String) = conn
        .query_row(
            "SELECT op_type,staged_file FROM operation_journal WHERE id=?1",
            [id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| refused())?;
    if operation == "write" {
        let root = super::overlay::Overlay::load_in_root(&binding.root, conn, &token)?;
        if root.original_base_json()?.is_some() {
            return Err(refused());
        }
    }
    let (name, parent) = path.split_last().ok_or_else(refused)?;
    // Unlike the projected listing, the raw saved base cannot hide an original
    // remote member behind a local overlay. A pending parent has an explicit
    // journal-bound empty base, verified by offline_directory_proof below.
    let absent: bool = conn.query_row("SELECT EXISTS(SELECT 1 FROM snapshots s WHERE s.instance=?1 AND s.space=?2 AND s.path=?3 AND s.issuer=?4 AND s.subject=?5 AND NOT EXISTS(SELECT 1 FROM json_each(s.entries) e WHERE json_extract(e.value,'$.name')=?6))",params![binding.instance,binding.space,super::path_key(parent)?,binding.issuer,binding.subject,name],|row|row.get(0)).map_err(|_|refused())?;
    if !absent {
        return Err(refused());
    }
    super::offline_directory_proof(conn, binding, parent)?;
    Ok(())
}

// Called inside the admitted IMMEDIATE writer, before journal relocation. No
// network or scratch connection: immutable original copies are the SQL donors.
pub(super) fn replace(
    conn: &Connection,
    binding: &crate::MountBinding,
    source: &[String],
    destination: &[String],
    target: (&str, &str),
) -> Result<(), AccountError> {
    let account = (binding.instance.as_str(), binding.space.as_str());
    let (instance, space) = account;
    let owner:bool=conn.query_row("SELECT EXISTS(SELECT 1 FROM account_identities WHERE instance=?1 AND issuer=?2 AND subject=?3)",params![instance,binding.issuer,binding.subject],|row|row.get(0)).map_err(|_|refused())?;
    if !owner {
        return Err(refused());
    }
    if source.is_empty()
        || destination.is_empty()
        || source.starts_with(destination)
        || destination.starts_with(source)
        || !valid_path(source)
        || !valid_path(destination)
        || !crate::dav::valid_remote_id(target.0)
        || !crate::dav::strong_etag(target.1)
    {
        return Err(refused());
    }
    let mut owners = Vec::new();
    let mut after = None;
    let mut metadata = 0u64;
    let mut entries = 0usize;
    let mut payload = 0u64;
    let ancestors = [source, destination]
        .into_iter()
        .flat_map(|p| (0..=p.len()).map(move |n| super::path_key(&p[..n])))
        .collect::<Result<std::collections::BTreeSet<_>, _>>()?;
    let ancestors = serde_json::to_string(&ancestors).map_err(|_| refused())?;
    let source_key = super::path_key(source)?;
    let destination_key = super::path_key(destination)?;
    let source_prefix = format!("{},", source_key.trim_end_matches(']'));
    let source_upper = format!("{}-", source_key.trim_end_matches(']'));
    let destination_prefix = format!("{},", destination_key.trim_end_matches(']'));
    let destination_upper = format!("{}-", destination_key.trim_end_matches(']'));
    // Page original roots only. No insertion or deletion occurs until the
    // entire bounded plan has been validated, so reused rowids cannot feed it.
    loop {
        let mut statement=conn.prepare("SELECT rowid,CASE WHEN length(CAST(root AS BLOB))<=16777216 THEN root END,length(CAST(root AS BLOB))+length(CAST(directories AS BLOB))+length(CAST(manifest AS BLOB)) FROM pins WHERE instance=?1 AND space=?2 AND (?3 IS NULL OR rowid>?3) AND (root IN (SELECT value FROM json_each(?4)) OR (root>=?5 AND root<?6) OR (root>=?7 AND root<?8)) ORDER BY rowid LIMIT 32").map_err(|_|refused())?;
        let page = statement
            .query_map(
                params![
                    instance,
                    space,
                    after,
                    ancestors,
                    source_prefix,
                    source_upper,
                    destination_prefix,
                    destination_upper
                ],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, u64>(2)?,
                    ))
                },
            )
            .map_err(|_| refused())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| refused())?;
        if page.is_empty() {
            break;
        }
        for (id, encoded, bytes) in page {
            after = Some(id);
            let root: Vec<String> = serde_json::from_str(&encoded).map_err(|_| refused())?;
            if !valid_path(&root) {
                return Err(refused());
            }
            super::path_key(&root)?;
            if ![source, destination]
                .iter()
                .any(|p| root.starts_with(p) || p.starts_with(&root))
            {
                continue;
            }
            metadata = metadata
                .checked_add(bytes)
                .filter(|n| *n <= 16777216)
                .ok_or_else(refused)?;
            let tree = verified_tree(conn, account, &root).inspect_err(|_| {
                #[cfg(feature = "fault-injection")]
                eprintln!("cirrus lab pin plan: invalid stored owner {root:?}");
            })?;
            if destination.starts_with(&root)
                && subtree(&tree, destination)
                    != (PinTree {
                        is_dir: true,
                        directories: vec![(destination.to_vec(), target.0.to_owned())],
                        files: Vec::new(),
                    })
            {
                return Err(refused());
            }
            entries = entries
                .checked_add(tree.directories.len() + tree.files.len())
                .filter(|n| *n <= 4097)
                .ok_or_else(refused)?;
            for file in &tree.files {
                payload = payload
                    .checked_add(file.size)
                    .filter(|n| *n <= MAX_PIN_BYTES)
                    .ok_or_else(refused)?;
            }
            if root.starts_with(destination)
                && (root != destination
                    || !tree.is_dir
                    || tree.directories != vec![(destination.to_vec(), target.0.to_owned())]
                    || !tree.files.is_empty())
            {
                return Err(refused());
            }
            owners.push(Owner {
                root,
                tree,
                copy: String::new(),
            });
        }
    }
    // Every intersecting pair, including destination/common ancestors, must
    // agree. Byte comparison uses verified canonical 128KiB chunk boundaries,
    // never an optional server whole-file hash or an arbitrary latest owner.
    for (index, a) in owners.iter().enumerate() {
        for b in &owners[index + 1..] {
            let (outer, inner) = if b.root.starts_with(&a.root) {
                (a, b)
            } else if a.root.starts_with(&b.root) {
                (b, a)
            } else {
                continue;
            };
            if subtree(&outer.tree, &inner.root) != inner.tree
                || !super::overlapping_pin_chunks_match(
                    conn,
                    instance,
                    space,
                    &super::path_key(&outer.root)?,
                    &inner.root,
                )?
            {
                #[cfg(feature = "fault-injection")]
                eprintln!(
                    "cirrus lab pin plan: overlapping owner disagreement {:?} / {:?}",
                    outer.root, inner.root
                );
                return Err(refused());
            }
        }
    }
    // Agreement above makes each sorted donor deterministic, never a choice
    // between differing versions or health. A complete fragment union may
    // supply incoming coverage when there is no containing capture.
    owners.sort_by(|a, b| a.root.cmp(&b.root));
    let containing = owners.iter().any(|owner| source.starts_with(&owner.root));
    let receiving = owners
        .iter()
        .any(|owner| destination.starts_with(&owner.root) && owner.root != destination);
    let exact = owners.iter().any(|owner| owner.root == source);
    let split = owners.iter().any(|owner| {
        owner.root.len() < source.len()
            && source.starts_with(&owner.root)
            && !destination.starts_with(&owner.root)
    });
    // Unchanged siblings are historical captures, not assertions about today's
    // remote listing. Bind only incoming/target slices to this MOVE's proof.
    // Independent rebasing preserves existing local-child semantics. Synthesis
    // separately proves pristine local additions after covering every remote
    // member, regardless of whether coverage has one owner or several.
    for owner in &owners {
        let path = if source.starts_with(&owner.root) {
            source
        } else if owner.root.starts_with(source) {
            owner.root.as_slice()
        } else {
            continue;
        };
        super::complete_incoming_pin(
            &binding.root,
            conn,
            instance,
            space,
            &owner.root,
            path,
            &rebase(path, source, destination)?,
        )?;
    }
    let incoming = if containing || receiving {
        Some(incoming_tree(conn, binding, source, &owners)?)
    } else {
        None
    };
    if receiving || split {
        validate_local_additions(
            conn,
            binding,
            source,
            &incoming.as_ref().ok_or_else(refused)?.tree,
        )?;
    }
    let mut active = Vec::new();
    let mut size = PlanSize::default();
    for (index, owner) in owners.iter().enumerate() {
        if owner.root.starts_with(destination) {
            continue;
        }
        let moving = owner.root.starts_with(source);
        let mut tree = PinTree {
            is_dir: owner.tree.is_dir,
            directories: Vec::new(),
            files: Vec::new(),
        };
        let mut files = Vec::new();
        for (path, id) in &owner.tree.directories {
            if !moving && (path.starts_with(source) || path.starts_with(destination)) {
                continue;
            }
            tree.directories
                .push((rebase(path, source, destination)?, id.clone()));
        }
        for file in &owner.tree.files {
            if !moving && (file.path.starts_with(source) || file.path.starts_with(destination)) {
                continue;
            }
            let mut next = file.clone();
            next.path = rebase(&file.path, source, destination)?;
            tree.files.push(next);
            files.push((index, file.path.clone()));
        }
        if !moving && destination.starts_with(&owner.root) {
            let incoming = incoming.as_ref().ok_or_else(refused)?;
            for (path, id) in &incoming.tree.directories {
                tree.directories
                    .push((rebase(path, source, destination)?, id.clone()));
            }
            for (file, origin) in incoming.tree.files.iter().zip(&incoming.files) {
                let mut file = file.clone();
                file.path = rebase(&file.path, source, destination)?;
                tree.files.push(file);
                files.push(origin.clone());
            }
        }
        let mut next = Active {
            root: rebase(&owner.root, source, destination)?,
            tree,
            files,
        };
        bound_active(&mut next, &mut size)?;
        active.push(next);
    }
    if split && !receiving && !exact {
        let incoming = incoming.as_ref().ok_or_else(refused)?;
        let mut tree = subtree(&incoming.tree, source);
        let files = incoming.files.clone();
        for (path, _) in &mut tree.directories {
            *path = rebase(path, source, destination)?;
        }
        for file in &mut tree.files {
            file.path = rebase(&file.path, source, destination)?;
        }
        let mut next = Active {
            root: destination.to_vec(),
            tree,
            files,
        };
        bound_active(&mut next, &mut size)?;
        active.push(next);
    }
    let mut roots = std::collections::BTreeSet::new();
    for owner in &active {
        if !roots.insert(owner.root.clone()) {
            return Err(refused());
        }
    }
    // All checks precede mutation. Copies remain independently recoverable;
    // rebuilding active rows from them avoids root collisions and in-place
    // traversal hazards. No retained-copy/dirty-root ownership is retired.
    for owner in &mut owners {
        let key = super::path_key(&owner.root)?;
        let count=conn.execute("INSERT INTO pin_copies(instance,space,root,is_dir,directories,manifest,issuer,subject,displaced_path,target_id,target_etag) SELECT p.instance,p.space,p.root,p.is_dir,p.directories,p.manifest,a.issuer,a.subject,?4,?5,?6 FROM pins p JOIN account_identities a ON a.instance=p.instance WHERE p.instance=?1 AND p.space=?2 AND p.root=?3",params![instance,space,key,super::path_key(destination)?,target.0,target.1]).map_err(|error|super::sqlite_storage_error(error,"cannot retain displaced pin"))?;
        if count != 1 {
            return Err(refused());
        }
        owner.copy = conn.last_insert_rowid().to_string();
        conn.execute("INSERT INTO pin_copy_files SELECT instance,space,?4,path,version,verified_complete FROM files WHERE instance=?1 AND space=?2 AND root=?3",params![instance,space,key,owner.copy]).map_err(|error|super::sqlite_storage_error(error,"cannot retain displaced pin versions"))?;
        conn.execute("INSERT INTO pin_copy_chunks SELECT instance,space,?4,path,offset,body,digest FROM chunks WHERE instance=?1 AND space=?2 AND root=?3",params![instance,space,key,owner.copy]).map_err(|error|super::sqlite_storage_error(error,"cannot retain displaced pin chunks"))?;
    }
    for owner in &owners {
        for table in ["chunks", "files", "pins"] {
            conn.execute(
                &format!("DELETE FROM {table} WHERE instance=?1 AND space=?2 AND root=?3"),
                params![instance, space, super::path_key(&owner.root)?],
            )
            .map_err(|error| {
                super::sqlite_storage_error(error, "cannot replace active pin ownership")
            })?;
        }
    }
    for owner in active {
        let key = super::path_key(&owner.root)?;
        conn.execute("INSERT INTO pins(instance,space,root,is_dir,directories,manifest) VALUES(?1,?2,?3,?4,?5,?6)",params![instance,space,key,owner.tree.is_dir,serde_json::to_string(&owner.tree.directories).map_err(|_|refused())?,serde_json::to_string(&owner.tree.files).map_err(|_|refused())?]).map_err(|error|super::sqlite_storage_error(error,"cannot publish transformed pin"))?;
        for (file, (donor, path)) in owner.tree.files.iter().zip(owner.files) {
            let original = super::path_key(&path)?;
            let next = super::path_key(&file.path)?;
            conn.execute("INSERT INTO files SELECT instance,space,?4,?5,?6,verified_complete FROM pin_copy_files WHERE instance=?1 AND space=?2 AND root=?3 AND path=?7",params![instance,space,owners[donor].copy,key,next,serde_json::to_string(file).map_err(|_|refused())?,original]).map_err(|error|super::sqlite_storage_error(error,"cannot publish transformed pin version"))?;
            conn.execute("INSERT INTO chunks SELECT instance,space,?4,?5,offset,body,digest FROM pin_copy_chunks WHERE instance=?1 AND space=?2 AND root=?3 AND path=?6",params![instance,space,owners[donor].copy,key,next,original]).map_err(|error|super::sqlite_storage_error(error,"cannot publish transformed pin contents"))?;
        }
    }
    Ok(())
}
