//! Local-only export of an explicitly selected retained pin version.
use std::io::Write;
use std::path::{Component, Path};

use md5::Md5;
use rusqlite::{Connection, OptionalExtension, params};
use rustix::{
    fs::{self, FileType, Mode, OFlags, ResolveFlags},
    process,
};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::{AccountError, FileVersion, offline};

const CHUNK: u64 = 128 * 1024;
const MAX_PIN_BYTES: u64 = 1024 * 1024 * 1024;
const PAGE: i64 = 16;

#[derive(Clone, Copy)]
enum PinTables {
    Active,
    Copy,
}
impl PinTables {
    fn files(self) -> &'static str {
        match self {
            Self::Active => "files",
            Self::Copy => "pin_copy_files",
        }
    }
    fn chunks(self) -> &'static str {
        match self {
            Self::Active => "chunks",
            Self::Copy => "pin_copy_chunks",
        }
    }
}

fn invalid() -> AccountError {
    AccountError::new("invalid or incomplete retained pin")
}

fn key(path: &[String]) -> Result<String, AccountError> {
    if path.len() > 128
        || path.iter().any(|s| {
            s.is_empty()
                || s == "."
                || s == ".."
                || s.contains('/')
                || s.chars().any(char::is_control)
        })
    {
        return Err(AccountError::new("invalid Space path"));
    }
    serde_json::to_string(path).map_err(|_| invalid())
}

pub(crate) fn list(
    instance: &str,
    space_root: Option<(&str, &[String])>,
    offset: u32,
) -> Result<Vec<(String, String)>, AccountError> {
    let mut conn = offline::database()?;
    let tx = conn.transaction().map_err(|_| invalid())?;
    let mut result = Vec::new();
    if let Some((space, root)) = space_root {
        let root = key(root)?;
        let mut stmt = tx.prepare("SELECT CASE WHEN length(path)<=24000 THEN path END,CASE WHEN length(version)<=24000 THEN version END FROM files WHERE instance=?1 AND space=?2 AND root=?3 ORDER BY path LIMIT ?4 OFFSET ?5").map_err(|_| invalid())?;
        let rows = stmt
            .query_map(params![instance, space, root, PAGE, offset], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|_| invalid())?;
        for row in rows {
            let (path, version) = row.map_err(|_| invalid())?;
            let fingerprint = selector(
                &tx,
                PinTables::Active,
                instance,
                space,
                &root,
                &path,
                &version,
            )?;
            let item = (path, format!("{fingerprint}\n{version}"));
            if !push_page(&mut result, item)? {
                break;
            }
        }
    } else {
        let mut stmt = tx.prepare("SELECT CASE WHEN length(space)<=24000 THEN space END,CASE WHEN length(root)<=24000 THEN root END FROM pins WHERE instance=?1 ORDER BY space,root LIMIT ?2 OFFSET ?3").map_err(|_| invalid())?;
        let rows = stmt
            .query_map(params![instance, PAGE, offset], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|_| invalid())?;
        for row in rows {
            let item = row.map_err(|_| invalid())?;
            if !push_page(&mut result, item)? {
                break;
            }
        }
    }
    tx.commit().map_err(|_| invalid())?;
    Ok(result)
}

// The selector binds the exact stored metadata and ordered chunk digests. It is
// an identity fence, not an assertion that those digests or bytes are valid.
fn selector(
    conn: &Connection,
    tables: PinTables,
    instance: &str,
    space: &str,
    root: &str,
    path: &str,
    version: &str,
) -> Result<String, AccountError> {
    let mut hash = Sha256::new();
    hash.update((version.len() as u64).to_be_bytes());
    hash.update(version.as_bytes());
    let mut stmt = conn.prepare(&format!("SELECT offset,CASE WHEN length(digest)<=1024 THEN digest END FROM {} WHERE instance=?1 AND space=?2 AND root=?3 AND path=?4 ORDER BY offset LIMIT 8193",tables.chunks())).map_err(|_| invalid())?;
    let mut rows = stmt
        .query(params![instance, space, root, path])
        .map_err(|_| invalid())?;
    let mut count = 0;
    while let Some(row) = rows.next().map_err(|_| invalid())? {
        count += 1;
        if count > 8192 {
            return Err(invalid());
        }
        let offset: i64 = row.get(0).map_err(|_| invalid())?;
        let digest: String = row.get(1).map_err(|_| invalid())?;
        hash.update(offset.to_be_bytes());
        hash.update((digest.len() as u64).to_be_bytes());
        hash.update(digest.as_bytes());
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn push_page(
    page: &mut Vec<(String, String)>,
    item: (String, String),
) -> Result<bool, AccountError> {
    let size = item.0.len().saturating_add(item.1.len());
    if size > 24_000 {
        return Err(AccountError::new("retained pin entry exceeds IPC limit"));
    }
    if page.iter().map(|(a, b)| a.len() + b.len()).sum::<usize>() + size > 24_000 {
        return Ok(false);
    }
    page.push(item);
    Ok(true)
}

// Reads only a single bounded SQLite chunk at a time. Checks both chunk digests
// and the supported advertised digests; unsupported algorithms remain unverified.
fn verify_file(
    conn: &Connection,
    tables: PinTables,
    instance: &str,
    space: &str,
    root: &str,
    version: &FileVersion,
    mut output: Option<&mut std::fs::File>,
) -> Result<(), AccountError> {
    if version.instance != instance || version.space != space || version.size > MAX_PIN_BYTES {
        return Err(invalid());
    }
    let path = key(&version.path)?;
    let mut stmt = conn.prepare(&format!("SELECT offset,CASE WHEN length(body)<=131072 THEN body ELSE NULL END,CASE WHEN length(digest)=64 THEN digest END FROM {} WHERE instance=?1 AND space=?2 AND root=?3 AND path=?4 ORDER BY offset",tables.chunks())).map_err(|_| invalid())?;
    let mut rows = stmt
        .query(params![instance, space, root, path])
        .map_err(|_| invalid())?;
    let (mut sha256, mut sha1, mut md5) = (Sha256::new(), Sha1::new(), Md5::new());
    let mut offset = 0u64;
    while let Some(row) = rows.next().map_err(|_| invalid())? {
        let position: i64 = row.get(0).map_err(|_| invalid())?;
        // The SQL length check prevents materializing a corrupt, oversized blob.
        let body: Vec<u8> = row.get(1).map_err(|_| invalid())?;
        let digest: String = row.get(2).map_err(|_| invalid())?;
        if position < 0
            || position as u64 != offset
            || offset >= version.size
            || body.len() as u64 != (version.size - offset).min(CHUNK)
            || format!("{:x}", Sha256::digest(&body)) != digest
        {
            return Err(invalid());
        }
        sha256.update(&body);
        sha1.update(&body);
        md5.update(&body);
        if let Some(file) = output.as_deref_mut() {
            file.write_all(&body).map_err(|_| {
                AccountError::new("export failed; destination may contain partial data")
            })?;
        }
        offset += body.len() as u64;
    }
    if offset != version.size {
        return Err(invalid());
    }
    let digests = [
        ("SHA256", format!("{:x}", sha256.finalize())),
        ("SHA1", format!("{:x}", sha1.finalize())),
        ("MD5", format!("{:x}", md5.finalize())),
    ];
    for checksum in version
        .checksums
        .iter()
        .flat_map(|s| s.split_ascii_whitespace())
    {
        let (algorithm, expected) = checksum.split_once(':').ok_or_else(invalid)?;
        if let Some((_, actual)) = digests
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case(&algorithm.replace('-', "")))
            && !expected.eq_ignore_ascii_case(actual)
        {
            return Err(invalid());
        }
    }
    Ok(())
}

// Rename admission needs the same byte/digest checks without creating output.
pub(crate) fn verify_active_file(
    conn: &Connection,
    instance: &str,
    space: &str,
    root: &str,
    version: &FileVersion,
) -> Result<(), AccountError> {
    verify_file(
        conn,
        PinTables::Active,
        instance,
        space,
        root,
        version,
        None,
    )
}

pub(crate) fn export(
    instance: &str,
    space: &str,
    root: &[String],
    path: &[String],
    expected_selector: &str,
    destination: &Path,
) -> Result<(), AccountError> {
    export_pin(
        instance,
        space,
        root,
        path,
        expected_selector,
        destination,
        None,
    )
}

fn export_pin(
    instance: &str,
    space: &str,
    root: &[String],
    path: &[String],
    expected_selector: &str,
    destination: &Path,
    copy: Option<i64>,
) -> Result<(), AccountError> {
    let root_key = copy
        .map(|id| id.to_string())
        .map_or_else(|| key(root), Ok)?;
    let tables = if copy.is_some() {
        PinTables::Copy
    } else {
        PinTables::Active
    };
    let path_key = key(path)?;
    if path.is_empty() || !path.starts_with(root) {
        return Err(invalid());
    }
    if expected_selector.len() != 64 || !expected_selector.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AccountError::new("invalid retained version selector"));
    }
    let mut conn = offline::database()?;
    let tx = conn.transaction().map_err(|_| invalid())?;
    if let Some(id) = copy {
        check_copy(&tx, instance, space, id)?;
    }
    let metadata_query = if copy.is_some() {
        "SELECT is_dir,CASE WHEN length(directories)<=16777216 THEN directories END,CASE WHEN length(manifest)<=16777216 THEN manifest END FROM pin_copies WHERE instance=?1 AND space=?2 AND id=?3"
    } else {
        "SELECT is_dir,CASE WHEN length(directories)<=16777216 THEN directories END,CASE WHEN length(manifest)<=16777216 THEN manifest END FROM pins WHERE instance=?1 AND space=?2 AND root=?3"
    };
    let (is_dir, directories, manifest): (bool, String, String) = tx
        .query_row(metadata_query, params![instance, space, root_key], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .optional()
        .map_err(|_| invalid())?
        .ok_or_else(invalid)?;
    let versions: Vec<FileVersion> = serde_json::from_str(&manifest).map_err(|_| invalid())?;
    let dirs: Vec<(Vec<String>, String)> =
        serde_json::from_str(&directories).map_err(|_| invalid())?;
    if versions.len() + dirs.len() > 4097
        || versions.windows(2).any(|w| w[0].path >= w[1].path)
        || dirs.windows(2).any(|w| w[0].0 >= w[1].0)
        || (is_dir && !dirs.iter().any(|(path, _)| path == root))
        || (!is_dir && (!dirs.is_empty() || versions.len() != 1 || versions[0].path != root))
    {
        return Err(invalid());
    }
    for (dir, _) in &dirs {
        key(dir)?;
        if !dir.starts_with(root)
            || (dir != root
                && !dirs.iter().any(|(parent, _)| {
                    dir.split_last().is_some_and(|(_, prefix)| prefix == parent)
                }))
        {
            return Err(invalid());
        }
    }
    let count: usize = tx.query_row(&format!("SELECT count(*) FROM {} WHERE instance=?1 AND space=?2 AND root=?3 AND verified_complete=1",tables.files()), params![instance, space, root_key], |r| r.get(0)).map_err(|_| invalid())?;
    if count != versions.len() {
        return Err(invalid());
    }
    let mut selected = None;
    let mut total = 0u64;
    for version in &versions {
        if !version.path.starts_with(root)
            || dirs.iter().any(|(dir, _)| *dir == version.path)
            || (is_dir
                && !dirs.iter().any(|(dir, _)| {
                    version
                        .path
                        .split_last()
                        .is_some_and(|(_, parent)| parent == dir)
                }))
        {
            return Err(invalid());
        }
        total = total
            .checked_add(version.size)
            .filter(|n| *n <= MAX_PIN_BYTES)
            .ok_or_else(invalid)?;
        let file_key = key(&version.path)?;
        let encoded: String = tx.query_row(&format!("SELECT CASE WHEN length(version)<=16777216 THEN version END FROM {} WHERE instance=?1 AND space=?2 AND root=?3 AND path=?4 AND verified_complete=1",tables.files()), params![instance, space, root_key, file_key], |r| r.get(0)).optional().map_err(|_| invalid())?.ok_or_else(invalid)?;
        let stored: FileVersion = serde_json::from_str(&encoded).map_err(|_| invalid())?;
        if stored != *version {
            return Err(invalid());
        }
        if file_key == path_key
            && selector(&tx, tables, instance, space, &root_key, &file_key, &encoded)?
                != expected_selector
        {
            return Err(AccountError::new("retained version changed; list it again"));
        }
        verify_file(&tx, tables, instance, space, &root_key, version, None)?;
        if file_key == path_key {
            selected = Some(version);
        }
    }
    let selected = selected.ok_or_else(invalid)?;
    write_output(destination, |output| {
        verify_file(
            &tx,
            tables,
            instance,
            space,
            &root_key,
            selected,
            Some(output),
        )
    })
}

fn check_copy(
    conn: &Connection,
    instance: &str,
    space: &str,
    id: i64,
) -> Result<Vec<String>, AccountError> {
    if id <= 0 {
        return Err(invalid());
    }
    offline::check_retained_identity(conn, instance, space)?;
    let root:String=conn.query_row("SELECT CASE WHEN length(c.root)<=24000 THEN c.root END FROM pin_copies c JOIN account_identities a ON a.instance=c.instance AND a.issuer=c.issuer AND a.subject=c.subject WHERE c.instance=?1 AND c.space=?2 AND c.id=?3",params![instance,space,id],|r|r.get(0)).optional().map_err(|_|invalid())?.ok_or_else(invalid)?;
    let path: Vec<String> = serde_json::from_str(&root).map_err(|_| invalid())?;
    key(&path)?;
    Ok(path)
}

pub(crate) fn pin_copies(
    instance: &str,
    offset: u32,
) -> Result<Vec<(String, String)>, AccountError> {
    let conn = offline::database()?;
    let mut stmt=conn.prepare("SELECT id,space,root,is_dir,displaced_path,target_id,target_etag FROM pin_copies WHERE instance=?1 ORDER BY id LIMIT ?2 OFFSET ?3").map_err(|_|invalid())?;
    let mut rows = stmt
        .query(params![instance, PAGE, offset])
        .map_err(|_| invalid())?;
    let mut result = Vec::new();
    while let Some(row) = rows.next().map_err(|_| invalid())? {
        let id: i64 = row.get(0).map_err(|_| invalid())?;
        let space: String = row.get(1).map_err(|_| invalid())?;
        let root = check_copy(&conn, instance, &space, id)?;
        let displaced: String = row.get(4).map_err(|_| invalid())?;
        let info = serde_json::json!({"id":id,"space":space,"root":root,"is_directory":row.get::<_,bool>(3).map_err(|_|invalid())?,"displaced_path":serde_json::from_str::<Vec<String>>(&displaced).map_err(|_|invalid())?,"target_id":row.get::<_,String>(5).map_err(|_|invalid())?,"target_etag":row.get::<_,String>(6).map_err(|_|invalid())?,"status":"immutable retained pin copy; not a live namespace; remove only by copy ID"});
        if !push_page(&mut result, (id.to_string(), info.to_string()))? {
            break;
        }
    }
    Ok(result)
}

pub(crate) fn pin_copy_entries(
    instance: &str,
    space: &str,
    id: i64,
    offset: u32,
) -> Result<Vec<(String, String)>, AccountError> {
    let mut conn = offline::database()?;
    let tx = conn.transaction().map_err(|_| invalid())?;
    let captured_root = check_copy(&tx, instance, space, id)?;
    let dirs: String = tx
        .query_row(
            "SELECT CASE WHEN length(directories)<=16777216 THEN directories END FROM pin_copies WHERE instance=?1 AND space=?2 AND id=?3",
            params![instance, space, id],
            |r| r.get(0),
        )
        .map_err(|_| invalid())?;
    let dirs: Vec<(Vec<String>, String)> = serde_json::from_str(&dirs).map_err(|_| invalid())?;
    if dirs.len() > 4097 {
        return Err(invalid());
    }
    let mut entries = Vec::new();
    for (path, resource) in dirs {
        key(&path)?;
        // PinTree represents the Space root by an empty ID, not an observed
        // remote resource ID. Preserve that explicit sentinel, never invent one.
        let space_root = path.is_empty() && captured_root.is_empty() && resource.is_empty();
        if !path.starts_with(&captured_root)
            || (!space_root && !crate::dav::valid_remote_id(&resource))
        {
            return Err(invalid());
        }
        entries.push((key(&path)?,serde_json::json!({"kind":"directory","path":path,"id":if space_root {None}else{Some(resource)},"status":if space_root {"captured Space root; resource ID not recorded; no file payload"}else{"captured directory identity; no file payload"}}).to_string()));
    }
    let root = id.to_string();
    let mut stmt=tx.prepare("SELECT CASE WHEN length(path)<=24000 THEN path END,CASE WHEN length(version)<=24000 THEN version END FROM pin_copy_files WHERE instance=?1 AND space=?2 AND root=?3 ORDER BY path LIMIT 4098").map_err(|_|invalid())?;
    let rows = stmt
        .query_map(params![instance, space, root], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })
        .map_err(|_| invalid())?;
    for row in rows {
        if entries.len() >= 4097 {
            return Err(invalid());
        }
        let (path, version) = row.map_err(|_| invalid())?;
        let file: FileVersion = serde_json::from_str(&version).map_err(|_| invalid())?;
        if key(&file.path)? != path
            || !file.path.starts_with(&captured_root)
            || file.instance != instance
            || file.space != space
        {
            return Err(invalid());
        }
        let selector = selector(
            &tx,
            PinTables::Copy,
            instance,
            space,
            &root,
            &path,
            &version,
        )?;
        entries.push((
            path,
            serde_json::json!({"kind":"file","path":file.path,"size":file.size,"version":file,"selector":selector})
                .to_string(),
        ));
    }
    drop(stmt);
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut result = Vec::new();
    for entry in entries
        .into_iter()
        .skip(offset as usize)
        .take(PAGE as usize)
    {
        if !push_page(&mut result, entry)? {
            break;
        }
    }
    tx.commit().map_err(|_| invalid())?;
    Ok(result)
}

pub(crate) fn export_pin_copy(
    instance: &str,
    space: &str,
    id: i64,
    path: &[String],
    selector: &str,
    destination: &Path,
) -> Result<(), AccountError> {
    let root = check_copy(&offline::database()?, instance, space, id)?;
    export_pin(
        instance,
        space,
        &root,
        path,
        selector,
        destination,
        Some(id),
    )
}

pub(crate) fn remove_pin_copy(instance: &str, space: &str, id: i64) -> Result<(), AccountError> {
    let mut conn = offline::database()?;
    let tx = conn.transaction().map_err(|_| invalid())?;
    check_copy(&tx, instance, space, id)?;
    for table in ["pin_copy_chunks", "pin_copy_files"] {
        tx.execute(
            &format!("DELETE FROM {table} WHERE instance=?1 AND space=?2 AND root=?3"),
            params![instance, space, id.to_string()],
        )
        .map_err(|_| invalid())?;
    }
    tx.execute(
        "DELETE FROM pin_copies WHERE instance=?1 AND space=?2 AND id=?3",
        params![instance, space, id],
    )
    .map_err(|_| invalid())?;
    tx.commit().map_err(|_| invalid())
}

fn write_output(
    destination: &Path,
    write: impl FnOnce(&mut std::fs::File) -> Result<(), AccountError>,
) -> Result<(), AccountError> {
    if !destination.is_absolute()
        || destination
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err(AccountError::new(
            "destination must be an absolute path without traversal",
        ));
    }
    let parent = destination
        .parent()
        .ok_or_else(|| AccountError::new("invalid destination"))?;
    let name = destination
        .file_name()
        .ok_or_else(|| AccountError::new("invalid destination"))?;
    let dir = fs::openat2(
        fs::CWD,
        parent,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| AccountError::new("cannot open destination parent without symlinks"))?;
    let stat =
        fs::fstat(&dir).map_err(|_| AccountError::new("cannot inspect destination parent"))?;
    if stat.st_uid != process::geteuid().as_raw() || stat.st_mode & 0o022 != 0 {
        return Err(AccountError::new(
            "destination parent must be user-owned and not group or world writable",
        ));
    }
    // Never export into a FUSE mount, including this client's remote-backed mount.
    if fs::fstatfs(&dir)
        .map_err(|_| AccountError::new("cannot inspect destination filesystem"))?
        .f_type
        == 0x6573_5546
    {
        return Err(AccountError::new(
            "destination cannot be on a FUSE filesystem",
        ));
    }
    let fd = fs::openat2(
        &dir,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::from_raw_mode(0o600),
        ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    )
    .map_err(|_| AccountError::new("destination exists or cannot be created"))?;
    let stat = fs::fstat(&fd)
        .map_err(|_| AccountError::new("export failed; destination may contain partial data"))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_uid != process::geteuid().as_raw()
        || stat.st_nlink != 1
    {
        return Err(AccountError::new(
            "export failed; destination may contain partial data",
        ));
    }
    let mut output = std::fs::File::from(fd);
    write(&mut output)
        .map_err(|_| AccountError::new("export failed; destination may contain partial data"))?;
    output
        .sync_all()
        .and_then(|()| fs::fsync(&dir).map_err(std::io::Error::from))
        .map_err(|_| AccountError::new("export failed; destination may contain partial data"))?;
    Ok(())
}

fn staged_digest(
    file: &offline::StagedSnapshot,
    mut output: Option<&mut std::fs::File>,
) -> Result<(u64, String), AccountError> {
    let mut hash = Sha256::new();
    let mut size = 0u64;
    while size < file.len() {
        let buffer = file.range(size, (file.len() - size).min(CHUNK) as u32)?;
        size += buffer.len() as u64;
        hash.update(&buffer);
        if let Some(output) = output.as_deref_mut() {
            output
                .write_all(&buffer)
                .map_err(|_| AccountError::new("cannot write retained staged file"))?;
        }
    }
    file.verify()?;
    Ok((size, format!("{:x}", hash.finalize())))
}

fn staged_selector(
    id: i64,
    space: &str,
    path: &str,
    name: &str,
    size: u64,
    digest: &str,
) -> String {
    let mut hash = Sha256::new();
    hash.update(b"cirrus-dirty-export-schema16");
    hash.update(id.to_be_bytes());
    for part in [space, path, name, digest] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part.as_bytes());
    }
    hash.update(size.to_be_bytes());
    format!("{:x}", hash.finalize())
}

pub(crate) fn staged_list(
    instance: &str,
    offset: u32,
) -> Result<Vec<(String, String)>, AccountError> {
    let conn = offline::database()?;
    let mut result = Vec::new();
    // Listing selects immutable roots without hashing logical file contents.
    // Otherwise even listing a retained sparse TiB file would scan a TiB.
    let rows = {
        let mut stmt = conn.prepare("SELECT id,CASE WHEN length(space)<=24000 THEN space END,CASE WHEN length(path)<=24000 THEN path END,CASE WHEN length(state)<=64 THEN state END,CASE WHEN length(staged_file)<=64 THEN staged_file END FROM operation_journal WHERE instance=?1 AND op_type='write' ORDER BY id LIMIT ?2 OFFSET ?3").map_err(|_| AccountError::new("cannot list retained staged files"))?;
        let rows = stmt
            .query_map(params![instance, PAGE, offset], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })
            .map_err(|_| AccountError::new("cannot list retained staged files"))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|_| AccountError::new("cannot list retained staged files"))?
    };
    for (id, space, path, state, name) in rows {
        let parts: Vec<String> =
            serde_json::from_str(&path).map_err(|_| AccountError::new("invalid journal path"))?;
        key(&parts)?;
        let info = offline::StagedSnapshot::open(&name)
            .and_then(|file| Ok((file.len(), file.root_digest()?)))
            .ok();
        let selected = info
            .as_ref()
            .map(|(size, digest)| staged_selector(id, &space, &path, &name, *size, digest));
        let value = serde_json::json!({"id":id,"space":space,"path":parts,"state":state,"staged_file":name,"size":info.as_ref().map(|v| v.0),"sha256":null,"selector":selected,"integrity":"immutable manifest verified; payload blocks and full-stream SHA-256 checked during export; exact original base may be unavailable","status":"retained local snapshot; may require original content; remote outcome not asserted"}).to_string();
        if !push_page(&mut result, (id.to_string(), value))? {
            break;
        }
    }
    Ok(result)
}

pub(crate) fn staged_export(
    instance: &str,
    id: i64,
    expected: &str,
    destination: &Path,
) -> Result<(), AccountError> {
    if id <= 0 || expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(AccountError::new("invalid retained staged selection"));
    }
    let mut conn = offline::database()?;
    let tx = conn
        .transaction()
        .map_err(|_| AccountError::new("cannot inspect retained staged file"))?;
    let (space, path, name): (String, String, String) = tx.query_row("SELECT space,path,staged_file FROM operation_journal WHERE instance=?1 AND id=?2 AND op_type='write'", params![instance,id], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional().map_err(|_| AccountError::new("cannot inspect retained staged file"))?.ok_or_else(|| AccountError::new("retained staged entry is unavailable"))?;
    tx.commit()
        .map_err(|_| AccountError::new("cannot inspect retained staged file"))?;
    let parts: Vec<String> =
        serde_json::from_str(&path).map_err(|_| AccountError::new("invalid journal path"))?;
    key(&parts)?;
    let file = offline::StagedSnapshot::open(&name)?;
    if staged_selector(id, &space, &path, &name, file.len(), &file.root_digest()?) != expected {
        return Err(AccountError::new(
            "retained staged file changed; list it again",
        ));
    }
    let (size, digest) = staged_digest(&file, None)?;
    write_output(destination, |output| {
        let actual = staged_digest(&file, Some(output))?;
        if actual != (size, digest) {
            return Err(AccountError::new(
                "retained staged file changed during recovery",
            ));
        }
        Ok(())
    })
}
