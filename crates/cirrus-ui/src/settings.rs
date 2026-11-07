use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::PathBuf;

fn directory() -> Option<PathBuf> {
    let root = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .filter(|p| p.is_absolute())
                .map(|p| p.join(".config"))
        })?;
    Some(root.join("cirrus-drive"))
}

pub fn server() -> Option<String> {
    let path = directory()?.join("server-url");
    if !fs::symlink_metadata(&path).ok()?.file_type().is_file() {
        return None;
    }
    let mut value = String::new();
    fs::File::open(path)
        .ok()?
        .take(4097)
        .read_to_string(&mut value)
        .ok()?;
    if value.len() > 4096 || !value.starts_with("https://") || value.chars().any(char::is_control) {
        return None;
    }
    Some(value)
}

pub fn save_server(value: &str) -> io::Result<()> {
    if value.len() > 4096 || !value.starts_with("https://") || value.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid server URL",
        ));
    }
    let dir =
        directory().ok_or_else(|| io::Error::other("configuration directory is unavailable"))?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&dir)?;
    if !fs::symlink_metadata(&dir)?.file_type().is_dir() {
        return Err(io::Error::other(
            "configuration directory is not a directory",
        ));
    }
    let temp = dir.join(format!(".server-url-{}", std::process::id()));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)?;
    let result = (|| {
        file.write_all(value.as_bytes())?;
        file.sync_all()?;
        fs::rename(&temp, dir.join("server-url"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}
