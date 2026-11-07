#!/usr/bin/env python3
"""Install/remove known user artifacts; never recursively remove user state."""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import sqlite3
import stat
import subprocess
import sys
from contextlib import closing

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
APP_ID = 0x43445231


def absolute(name, value):
    if not value or not re.fullmatch(r"/[A-Za-z0-9_./-]+", value):
        raise ValueError(f"{name} must be an absolute path without spaces or special characters")
    path = Path(value)
    if ".." in path.parts or path == Path("/"):
        raise ValueError(f"unsafe {name}")
    return path


def locations():
    home = absolute("HOME", os.environ.get("HOME", ""))
    prefix = absolute("PREFIX", os.environ.get("PREFIX", str(home / ".local")))
    dest = os.environ.get("DESTDIR", "")
    dest = absolute("DESTDIR", dest) if dest else None
    def physical(path):
        return dest / path.relative_to("/") if dest else path
    targets = {
        "daemon": physical(prefix / "bin/cirrus-daemon"),
        "ui": physical(prefix / "bin/cirrus-ui"),
        "service": physical(home / ".config/systemd/user/cirrus-drive.service"),
        "desktop": physical(prefix / "share/applications/cirrus-drive.desktop"),
    }
    return home, prefix, dest, physical, targets, physical(prefix / "share/cirrus-drive/install.json")


def digest(data):
    return hashlib.sha256(data).hexdigest()


def regular(path):
    info = path.lstat()
    return stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid() and info.st_nlink == 1


def create(path, data, mode):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb") as out:
            out.write(data)
            out.flush()
            os.fsync(out.fileno())
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        raise


def install(args):
    if args:
        raise ValueError("usage: install.sh")
    _, prefix, _, _, targets, manifest = locations()
    bindir = Path(os.environ.get("CIRRUS_BIN_DIR", str(ROOT / "target/debug")))
    sources = [bindir / "cirrus-daemon", bindir / "cirrus-ui"]
    if not all(path.is_file() and os.access(path, os.X_OK) for path in sources):
        raise ValueError("build cirrus-daemon and cirrus-ui before installing")
    capability = subprocess.run([str(sources[0]), "--lab-capabilities"], capture_output=True, text=True, timeout=10)
    if capability.returncode == 0 and capability.stdout.strip() == "cirrus-drive disposable account and mount lab v1":
        raise ValueError("refusing to install a fault-injection daemon; rebuild without the feature")
    service = (HERE / "cirrus-drive.service").read_text()
    daemon = str(prefix / "bin/cirrus-daemon")
    service = service.replace("ExecStart=cirrus-daemon\n", f"ExecStart={daemon}\n")
    service = service.replace("cirrus-daemon --stop", f"{daemon} --stop")
    desktop = (HERE / "cirrus-drive.desktop").read_text().replace("Exec=cirrus-ui\n", f"Exec={prefix}/bin/cirrus-ui\n")
    contents = {"daemon": sources[0].read_bytes(), "ui": sources[1].read_bytes(),
                "service": service.encode(), "desktop": desktop.encode()}
    if manifest.exists() or manifest.is_symlink() or any(path.exists() or path.is_symlink() for path in targets.values()):
        raise ValueError("installation target already exists; no existing files were replaced")
    written = []
    try:
        for key, path in targets.items():
            create(path, contents[key], 0o755 if key in ("daemon", "ui") else 0o644)
            written.append(path)
        record = {key: digest(contents[key]) for key in targets}
        create(manifest, (json.dumps(record, sort_keys=True) + "\n").encode(), 0o600)
    except BaseException:
        for path in reversed(written):
            try:
                path.unlink()
            except OSError:
                pass
        raise
    print("installed user artifacts; enable the user service explicitly if desired")


def state_guard(state):
    """Return held lock fds and known clean files, or fail without deleting anything."""
    if not state.exists() and not state.is_symlink():
        return [], []
    current = Path("/")
    for part in state.parts[1:]:
        current /= part
        if current.is_symlink():
            raise ValueError("state path contains a symlink; state preserved")
    info = state.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
        raise ValueError("state directory is not a private user-owned directory")
    names = {p.name for p in state.iterdir()}
    if names - {"state.db", "cache.db", "account.lock", "sync.lock", "staging.lock", "scheduler.lock", "staging", "directory-snapshots"}:
        raise ValueError("unrecognized state or SQLite recovery files; state preserved")
    staging = state / "staging"
    if "staging" in names:
        entry = staging.lstat()
        if not stat.S_ISDIR(entry.st_mode) or entry.st_uid != os.geteuid() or stat.S_IMODE(entry.st_mode) != 0o700 or any(staging.iterdir()):
            raise ValueError("staging contains data or is unsafe; state preserved")
    if "directory-snapshots" in names:
        snapshots = state / "directory-snapshots"
        entry = snapshots.lstat()
        if not stat.S_ISDIR(entry.st_mode) or entry.st_uid != os.geteuid() or stat.S_IMODE(entry.st_mode) != 0o700 or any(snapshots.iterdir()):
            raise ValueError("directory snapshots contain files or are unsafe; state preserved")
    locks = []
    try:
        for name, content in (("sync.lock", b"cirrus-drive sync lock v1\n"),
                              ("account.lock", b"cirrus-drive account lock v1\n"),
                              ("staging.lock", b"cirrus-drive staging lock v1\n"),
                              ("scheduler.lock", b"cirrus-drive scheduler lock v1\n")):
            if name not in names:
                continue
            marker = state / name
            if not regular(marker) or stat.S_IMODE(marker.stat().st_mode) != 0o600 or marker.read_bytes() != content:
                raise ValueError("unrecognized coordination lock; state preserved")
            fd = os.open(marker, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            locks.append(fd)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise ValueError("account state is in use; state preserved")
        db = state / "state.db"
        if "state.db" in names:
            if not regular(db) or stat.S_IMODE(db.stat().st_mode) != 0o600:
                raise ValueError("offline database is unsafe; state preserved")
            with closing(sqlite3.connect(f"file:{db}?mode=ro", uri=True)) as conn:
                app = conn.execute("PRAGMA application_id").fetchone()[0]
                version = conn.execute("PRAGMA user_version").fetchone()[0]
                tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                expected = {"account_identities", "snapshots", "pins", "files", "chunks", "operation_journal", "directory_moves", "tree_proofs", "tree_targets", "write_dependencies", "operation_parents", "removal_versions", "upload_verifications", "sync_spaces", "sync_reads", "mutation_receipts", "verified_uploads", "dirty_roots", "dirty_bases", "dirty_preparations"}
                if app != APP_ID:
                    raise ValueError("unrecognized offline database; state preserved")
                if version != 17:
                    raise ValueError("unsupported offline database version; state preserved")
                expected |= {"pin_copies", "pin_copy_files", "pin_copy_chunks", "sqlite_sequence"}
                if tables != expected:
                    raise ValueError("unrecognized offline database; state preserved")
                if conn.execute("SELECT EXISTS(SELECT 1 FROM pins)").fetchone()[0]:
                    raise ValueError("pins exist; state preserved")
                if any(conn.execute(f"SELECT EXISTS(SELECT 1 FROM {table})").fetchone()[0] for table in ("pin_copies", "pin_copy_files", "pin_copy_chunks")):
                    raise ValueError("retained pin copies exist; state preserved")
                if conn.execute("SELECT EXISTS(SELECT 1 FROM operation_journal)").fetchone()[0]:
                    raise ValueError("journal entries exist; state preserved")
                if conn.execute("SELECT EXISTS(SELECT 1 FROM directory_moves)").fetchone()[0]:
                    raise ValueError("directory move records exist; state preserved")
                if conn.execute("SELECT EXISTS(SELECT 1 FROM write_dependencies)").fetchone()[0]:
                    raise ValueError("write dependencies exist; state preserved")
                if conn.execute("SELECT EXISTS(SELECT 1 FROM operation_parents)").fetchone()[0]:
                    raise ValueError("operation parent records exist; state preserved")
                if conn.execute("SELECT EXISTS(SELECT 1 FROM upload_verifications)").fetchone()[0]:
                    raise ValueError("upload verification records exist; state preserved")
                for table in ("tree_proofs", "tree_targets", "removal_versions", "sync_reads", "mutation_receipts", "verified_uploads", "dirty_roots", "dirty_bases", "dirty_preparations"):
                    if conn.execute(f"SELECT EXISTS(SELECT 1 FROM {table})").fetchone()[0]:
                        raise ValueError("sync operation records exist; state preserved")
        if "cache.db" in names:
            cache = state / "cache.db"
            if not regular(cache) or stat.S_IMODE(cache.stat().st_mode) != 0o600:
                raise ValueError("clean cache is unsafe; state preserved")
            with closing(sqlite3.connect(f"file:{cache}?mode=ro", uri=True)) as conn:
                app = conn.execute("PRAGMA application_id").fetchone()[0]
                version = conn.execute("PRAGMA user_version").fetchone()[0]
                tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                if app != 0x43444331 or version != 2 or tables != {"ranges", "generation"}:
                    raise ValueError("unrecognized clean cache; state preserved")
        return locks, [state / name for name in ("state.db", "cache.db", "sync.lock", "account.lock", "staging.lock", "scheduler.lock", "staging", "directory-snapshots") if name in names]
    except BaseException:
        for fd in locks:
            os.close(fd)
        raise


def stop_daemon(daemon, dest, home):
    if dest or home != Path(pwd.getpwuid(os.geteuid()).pw_dir):
        return False
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if not runtime:
        raise ValueError("XDG_RUNTIME_DIR is required to verify daemon and mount state")
    runtime = absolute("XDG_RUNTIME_DIR", runtime)
    socket = runtime / "cirrus-drive.sock"
    record = runtime / "cirrus-drive.mount"
    if not socket.exists() and not socket.is_symlink():
        if record.exists() or record.is_symlink():
            raise ValueError("mount recovery record exists; inspect it before uninstalling")
        return False
    if not regular(daemon) or not os.access(daemon, os.X_OK):
        raise ValueError("cannot verify or stop the running daemon")
    status = subprocess.run([str(daemon), "--mount-status"], capture_output=True, text=True, timeout=20)
    if status.returncode:
        raise ValueError("cannot verify mount status; daemon and files preserved")
    mounted = "mounted:" in status.stdout
    stop = subprocess.run([str(daemon), "--stop"], capture_output=True, text=True, timeout=40)
    if stop.returncode or socket.exists() or socket.is_symlink():
        raise ValueError("daemon did not stop safely; files preserved")
    return mounted


def uninstall(args):
    if args not in ([], ["--purge-clean-state"]):
        raise ValueError("usage: uninstall.sh [--purge-clean-state]")
    home, _, dest, physical, targets, manifest = locations()
    if not regular(manifest):
        raise ValueError("installation manifest is missing or unsafe")
    record = json.loads(manifest.read_text())
    if set(record) != set(targets):
        raise ValueError("unrecognized installation manifest")
    for key, path in targets.items():
        if not regular(path) or digest(path.read_bytes()) != record[key]:
            raise ValueError(f"installed {key} changed or is missing; no files removed")
    mounted = stop_daemon(targets["daemon"], dest, home)
    reason = None
    locks, clean = [], []
    state = physical(home / ".local/state/cirrus-drive")
    if args:
        try:
            if mounted:
                raise ValueError("a mount was active; state preserved")
            if not dest and home == Path(pwd.getpwuid(os.geteuid()).pw_dir) and " - fuse.cirrus-drive " in Path("/proc/self/mountinfo").read_text():
                raise ValueError("a Cirrus mount is active; state preserved")
            if not dest and home == Path(pwd.getpwuid(os.geteuid()).pw_dir) and (state.exists() or state.is_symlink()):
                raise ValueError("automatic purge of live account state is not yet qualified; state preserved")
            locks, clean = state_guard(state)
        except (OSError, ValueError, sqlite3.Error) as error:
            reason = str(error)
    try:
        for path in targets.values():
            path.unlink()
        manifest.unlink()
        if args and reason is None:
            for path in clean:
                if path.name in ("staging", "directory-snapshots"):
                    path.rmdir()
                else:
                    path.unlink()
            if state.exists():
                state.rmdir()
    finally:
        for fd in locks:
            os.close(fd)
    if reason:
        raise ValueError(reason)
    print("removed installed artifacts" + (" and clean state" if args else "; state and keyring preserved"))


if __name__ == "__main__":
    try:
        if len(sys.argv) < 2 or sys.argv[1] not in ("install", "uninstall"):
            raise ValueError("expected install or uninstall")
        (install if sys.argv[1] == "install" else uninstall)(sys.argv[2:])
    except (OSError, ValueError, sqlite3.Error, subprocess.SubprocessError) as error:
        print(f"cirrus packaging: {error}", file=sys.stderr)
        raise SystemExit(1)
