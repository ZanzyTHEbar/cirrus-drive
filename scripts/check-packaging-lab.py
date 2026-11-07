#!/usr/bin/env python3
"""Exercise install and conservative uninstall in a disposable DESTDIR."""

import os
import fcntl
import hashlib
import json
from pathlib import Path
import shutil
import signal
import sqlite3
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory(prefix="cirrus-packaging-") as temp:
        root = Path(temp)
        home = "/home/cirrus-lab"
        env = dict(os.environ, HOME=home, PREFIX=home + "/.local", DESTDIR=str(root / "image"))
        env.pop("CIRRUS_BIN_DIR", None)
        if os.environ.get("CARGO_TARGET_DIR"):
            target = Path(os.environ["CARGO_TARGET_DIR"])
            env["CIRRUS_BIN_DIR"] = str((target if target.is_absolute() else ROOT / target) / "debug")

        evidence = os.environ.get("CIRRUS_TEST_PACKAGING_EVIDENCE")
        output = Path(evidence) / root.name if evidence else None
        if output:
            output.mkdir(mode=0o700, parents=True, exist_ok=False)
        sequence = 0
        timeout_release = None

        def proc_state(pid):
            result = {"pid": pid}
            for name in ("stat", "status", "wchan", "syscall", "stack", "cmdline", "task/" + str(pid) + "/children"):
                try:
                    with (Path("/proc") / str(pid) / name).open("rb") as file:
                        result[name] = file.read(32768).decode(errors="replace").replace("\0", " ")
                except OSError as error:
                    result[name] = {"errno": error.errno}
            if isinstance(result.get("stat"), str):
                result["start_ticks"] = result["stat"].rsplit(")", 1)[1].split()[19]
            result["fds"] = {}
            try:
                for descriptor in (Path("/proc") / str(pid) / "fd").iterdir():
                    try:
                        result["fds"][descriptor.name] = os.readlink(descriptor)
                    except OSError as error:
                        result["fds"][descriptor.name] = {"errno": error.errno}
            except OSError as error:
                result["fd_error"] = error.errno
            return result

        def filesystem_state():
            # Fixed, fixture-owned paths only; never inspect a user's live home.
            base = root / "image" / home.lstrip("/")
            names = (".local/bin/cirrus-daemon", ".local/bin/cirrus-ui",
                     ".config/systemd/user/cirrus-drive.service",
                     ".local/share/applications/cirrus-drive.desktop",
                     ".local/share/cirrus-drive/install.json",
                     ".local/state/cirrus-drive/state.db", ".local/state/cirrus-drive/cache.db",
                     ".local/share/keyrings/keep")
            result = {}
            for name in names:
                path = base / name
                try:
                    stat = path.lstat()
                    row = {"size": stat.st_size, "mode": stat.st_mode, "inode": stat.st_ino,
                           "mtime_ns": stat.st_mtime_ns}
                    # Large executable hashes could themselves block timeout capture.
                    if path.is_file() and stat.st_size <= 1024 * 1024:
                        row["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
                    result[name] = row
                except FileNotFoundError:
                    result[name] = None
            return result

        def run(name, *args):
            nonlocal sequence
            command = [str(ROOT / "packaging" / name), *args]
            if output is None:
                return subprocess.run(command, env=env, capture_output=True, text=True, timeout=30)
            sequence += 1
            started = time.monotonic()
            record = {"command": command, "root": str(root), "time_ns": time.time_ns(),
                      "before": filesystem_state()}
            with subprocess.Popen(command, env=env, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, text=True) as process:
                record["launched"] = proc_state(process.pid)
                print(f"OWNED packaging: root={root} pid={process.pid} start_ticks={record['launched'].get('start_ticks')} step={sequence} command={name}", flush=True)
                try:
                    stdout, stderr = process.communicate(timeout=30)
                except subprocess.TimeoutExpired:
                    record["timeout_process"] = proc_state(process.pid)
                    children = record["timeout_process"].get("task/" + str(process.pid) + "/children")
                    if isinstance(children, str):
                        record["timeout_children"] = [proc_state(int(pid)) for pid in children.split()]
                    record["timeout_files"] = filesystem_state()
                    record["timeout_elapsed"] = time.monotonic() - started
                    process.kill()
                    if timeout_release is not None:
                        # Retire the controlled kernel barrier before waiting
                        # for the killed owner; never make cleanup await itself.
                        timeout_release()
                    stdout, stderr = process.communicate()
                    record["stdout"], record["stderr"] = stdout, stderr
                    raise
                finally:
                    record["elapsed"] = time.monotonic() - started
                    record["returncode"] = process.returncode
                    record["after"] = filesystem_state()
                    (output / f"{sequence:02}-{name}.json").write_text(json.dumps(record, indent=2))
                return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)

        def success(result):
            if result.returncode:
                raise RuntimeError(result.stderr)

        success(run("install.sh"))
        base = root / "image" / home.lstrip("/")
        daemon = base / ".local/bin/cirrus-daemon"
        service = base / ".config/systemd/user/cirrus-drive.service"
        assert daemon.is_file() and os.access(daemon, os.X_OK)
        assert "ExecStart=/home/cirrus-lab/.local/bin/cirrus-daemon" in service.read_text()
        before = daemon.read_bytes()
        assert run("install.sh").returncode != 0 and daemon.read_bytes() == before
        keyring = base / ".local/share/keyrings/keep"
        keyring.parent.mkdir(parents=True)
        keyring.write_text("preserve")
        state = base / ".local/state/cirrus-drive"
        state.mkdir(parents=True, mode=0o700)
        db = state / "state.db"
        with sqlite3.connect(db) as conn:
            conn.executescript("PRAGMA application_id=1128550961; PRAGMA user_version=17;"
                               "CREATE TABLE account_identities(instance TEXT PRIMARY KEY, issuer TEXT NOT NULL, subject TEXT NOT NULL);"
                               "CREATE TABLE snapshots(instance TEXT NOT NULL, space TEXT NOT NULL, path TEXT NOT NULL, entries TEXT NOT NULL, updated INTEGER NOT NULL, self_id TEXT, self_etag TEXT, local_operation INTEGER, issuer TEXT NOT NULL, subject TEXT NOT NULL, PRIMARY KEY(instance,space,path));"
                               "CREATE TABLE pins(instance TEXT NOT NULL, space TEXT NOT NULL, root TEXT NOT NULL, is_dir INTEGER NOT NULL, directories TEXT NOT NULL, manifest TEXT NOT NULL, PRIMARY KEY(instance,space,root));"
                               "CREATE TABLE files(instance TEXT NOT NULL, space TEXT NOT NULL, root TEXT NOT NULL, path TEXT NOT NULL, version TEXT NOT NULL, verified_complete INTEGER NOT NULL CHECK(verified_complete=1), PRIMARY KEY(instance,space,root,path));"
                               "CREATE TABLE chunks(instance TEXT NOT NULL, space TEXT NOT NULL, root TEXT NOT NULL, path TEXT NOT NULL, offset INTEGER NOT NULL, body BLOB NOT NULL, digest TEXT NOT NULL, PRIMARY KEY(instance,space,root,path,offset));"
                               "CREATE TABLE pin_copies(id INTEGER PRIMARY KEY AUTOINCREMENT,instance TEXT,space TEXT,root TEXT,is_dir INTEGER,directories TEXT,manifest TEXT,issuer TEXT,subject TEXT,displaced_path TEXT,target_id TEXT,target_etag TEXT);"
                               "CREATE TABLE pin_copy_files(instance TEXT,space TEXT,root TEXT,path TEXT,version TEXT,verified_complete INTEGER);"
                               "CREATE TABLE pin_copy_chunks(instance TEXT,space TEXT,root TEXT,path TEXT,offset INTEGER,body BLOB,digest TEXT);"
                               "CREATE TABLE operation_journal (id INTEGER PRIMARY KEY, instance TEXT NOT NULL, space TEXT NOT NULL, path TEXT NOT NULL, op_type TEXT NOT NULL, base_file_id TEXT, base_etag TEXT, staged_file TEXT NOT NULL, state TEXT NOT NULL CHECK(state IN ('pending','conflict','synced','uncertain','resolved')), error_msg TEXT, updated_at INTEGER NOT NULL, confirmed_file_id TEXT, confirmed_etag TEXT);"
                               "CREATE TABLE directory_moves (operation_id INTEGER PRIMARY KEY, destination TEXT NOT NULL, source_entry TEXT NOT NULL, target_id TEXT, target_etag TEXT, offline INTEGER NOT NULL DEFAULT 0 CHECK(offline IN (0,1)));"
                               "CREATE TABLE tree_proofs(operation_id INTEGER NOT NULL, path TEXT NOT NULL, self_id TEXT NOT NULL, self_etag TEXT NOT NULL, generation INTEGER NOT NULL, digest TEXT NOT NULL, entries TEXT NOT NULL, PRIMARY KEY(operation_id,path));"
                               "CREATE TABLE tree_targets(operation_id INTEGER PRIMARY KEY, self_id TEXT NOT NULL, self_etag TEXT NOT NULL, generation INTEGER NOT NULL, entries TEXT NOT NULL CHECK(entries='[]'), issuer TEXT NOT NULL, subject TEXT NOT NULL);"
                               "CREATE TABLE write_dependencies (operation_id INTEGER PRIMARY KEY, predecessor_id INTEGER NOT NULL UNIQUE);"
                               "CREATE TABLE operation_parents (operation_id INTEGER PRIMARY KEY, parents TEXT NOT NULL, destination_parents TEXT);"
                               "CREATE TABLE removal_versions(operation_id INTEGER NOT NULL, etag TEXT NOT NULL, PRIMARY KEY(operation_id,etag));"
                               "CREATE TABLE upload_verifications (operation_id INTEGER PRIMARY KEY, operation TEXT NOT NULL, digest TEXT NOT NULL, size INTEGER NOT NULL, version TEXT, verified_offset INTEGER NOT NULL, parent_index INTEGER NOT NULL);"
                               "CREATE TABLE sync_spaces (instance TEXT NOT NULL, space TEXT NOT NULL, issuer TEXT NOT NULL, subject TEXT NOT NULL, phase TEXT NOT NULL, failures INTEGER NOT NULL, next_at INTEGER NOT NULL, cause TEXT, last_verified INTEGER, verified_through INTEGER NOT NULL, attention_stamp TEXT, PRIMARY KEY(instance,space));"
                               "CREATE TABLE sync_reads (operation_id INTEGER PRIMARY KEY, snapshot TEXT NOT NULL, phase TEXT NOT NULL, entries TEXT NOT NULL, updated_at INTEGER NOT NULL);"
                               "CREATE TABLE mutation_receipts (operation_id INTEGER PRIMARY KEY, kind TEXT NOT NULL, snapshot TEXT NOT NULL, extra TEXT NOT NULL);"
                               "CREATE TABLE verified_uploads (operation_id INTEGER PRIMARY KEY, digest TEXT NOT NULL, version TEXT NOT NULL);"
                               "CREATE TABLE dirty_roots (root TEXT PRIMARY KEY, digest TEXT NOT NULL, size INTEGER NOT NULL, base TEXT);"
                               "CREATE TABLE dirty_bases (version TEXT NOT NULL, offset INTEGER NOT NULL, object TEXT NOT NULL, PRIMARY KEY(version,offset));"
                               "CREATE TABLE dirty_preparations (version TEXT PRIMARY KEY, offset INTEGER NOT NULL);"
                               "CREATE INDEX space_pending ON operation_journal(instance,space,state,op_type,id);"
                               "INSERT INTO operation_journal(instance, space, path, op_type, staged_file, state, updated_at) VALUES ('lab', 'space', '[\"file\"]', 'write', 'staged', 'pending', 0);")
        db.chmod(0o600)
        with sqlite3.connect(db) as conn:
            conn.execute("PRAGMA user_version=15")
        unsupported_bytes = db.read_bytes()
        refused = run("uninstall.sh", "--purge-clean-state")
        assert refused.returncode != 0 and db.exists(), refused.stderr
        assert db.read_bytes() == unsupported_bytes, "schema-15 database was modified"
        assert "unsupported offline database version; state preserved" in refused.stderr, refused.stderr
        with sqlite3.connect(db) as conn:
            assert conn.execute("PRAGMA user_version").fetchone()[0] == 15
            assert conn.execute("SELECT COUNT(*) FROM operation_journal").fetchone()[0] == 1
            conn.execute("PRAGMA user_version=17")
        if os.environ.get("CIRRUS_TEST_PACKAGING_INPUT_LEASE") == "1":
            if output is None:
                raise RuntimeError("controlled input lease requires private packaging evidence")
            # Only complete copies of the actual paired binaries, never a fake
            # executable or a lease on the repository/installed target.
            source = Path(env.get("CIRRUS_BIN_DIR", ROOT / "target/debug"))
            bindir = root / "leased-binaries"
            bindir.mkdir(mode=0o700)
            for name in ("cirrus-daemon", "cirrus-ui"):
                shutil.copy2(source / name, bindir / name)
            previous_bindir = env.get("CIRRUS_BIN_DIR")
            env["CIRRUS_BIN_DIR"] = str(bindir)
            break_requested = threading.Event()
            previous_handler = signal.signal(signal.SIGIO, lambda *_: break_requested.set())
            preserved = filesystem_state()
            try:
                with (bindir / "cirrus-ui").open("r+b") as leased:
                    fcntl.fcntl(leased, fcntl.F_SETOWN, os.getpid())
                    fcntl.fcntl(leased, fcntl.F_SETLEASE, fcntl.F_WRLCK)
                    lease_held = [True]
                    def release_lease():
                        if lease_held[0]:
                            fcntl.fcntl(leased, fcntl.F_SETLEASE, fcntl.F_UNLCK)
                            lease_held[0] = False
                    timeout_release = release_lease
                    try:
                        try:
                            run("install.sh")
                        except subprocess.TimeoutExpired:
                            assert break_requested.is_set(), "timeout was not at the owned input lease"
                        else:
                            raise AssertionError("installer bypassed a real write lease on its UI input")
                        assert filesystem_state() == preserved, "input-read timeout changed install/state/keyring files"
                    finally:
                        release_lease()
            finally:
                timeout_release = None
                signal.signal(signal.SIGIO, previous_handler)
                if previous_bindir is None:
                    env.pop("CIRRUS_BIN_DIR", None)
                else:
                    env["CIRRUS_BIN_DIR"] = previous_bindir
            print("PASS CONTROL: actual owned UI input lease causes the unchanged 30s installer timeout before output creation; pending State/keyring sentinel unchanged; child reaped and lease released (not attribution of historical timeout)", flush=True)
        success(run("install.sh"))
        cache = state / "cache.db"
        with sqlite3.connect(cache) as conn:
            conn.executescript("PRAGMA application_id=1128547121; PRAGMA user_version=2;"
                               "CREATE TABLE ranges(issuer TEXT, subject TEXT, version TEXT, offset INTEGER, body BLOB, digest TEXT, accessed INTEGER);"
                               "CREATE TABLE generation(value INTEGER NOT NULL); INSERT INTO generation VALUES(0);")
        cache.chmod(0o600)
        refused = run("uninstall.sh", "--purge-clean-state")
        assert refused.returncode != 0 and db.exists() and cache.exists() and not daemon.exists(), refused.stderr
        assert "journal entries exist; state preserved" in refused.stderr, refused.stderr
        success(run("install.sh"))
        with sqlite3.connect(db) as conn:
            conn.execute("DELETE FROM operation_journal")
            conn.execute("INSERT INTO pins VALUES ('lab', 'space', '[]', 1, '[]', '[]')")
        refused = run("uninstall.sh", "--purge-clean-state")
        assert refused.returncode != 0 and db.exists() and not daemon.exists(), refused.stderr
        assert "pins exist; state preserved" in refused.stderr, refused.stderr
        success(run("install.sh"))
        with sqlite3.connect(db) as conn:
            conn.execute("DELETE FROM pins")
            conn.execute("INSERT INTO pin_copies(instance,space,root) VALUES ('lab','space','[]')")
        refused = run("uninstall.sh", "--purge-clean-state")
        assert refused.returncode != 0 and db.exists() and not daemon.exists(), refused.stderr
        assert "retained pin copies exist; state preserved" in refused.stderr, refused.stderr
        success(run("install.sh"))
        with sqlite3.connect(db) as conn:
            conn.execute("DELETE FROM pin_copies")
            conn.execute("INSERT INTO directory_moves(operation_id, destination, source_entry) VALUES (1, '[]', '{}')")
        refused = run("uninstall.sh", "--purge-clean-state")
        assert refused.returncode != 0 and db.exists() and not daemon.exists(), refused.stderr
        assert "directory move records exist; state preserved" in refused.stderr, refused.stderr
        success(run("install.sh"))
        with sqlite3.connect(db) as conn:
            conn.execute("DELETE FROM directory_moves")
            conn.execute("INSERT INTO operation_parents VALUES (1, '[]', NULL)")
        refused = run("uninstall.sh", "--purge-clean-state")
        assert refused.returncode != 0 and db.exists() and not daemon.exists(), refused.stderr
        assert "operation parent records exist; state preserved" in refused.stderr, refused.stderr
        success(run("install.sh"))
        with sqlite3.connect(db) as conn:
            conn.execute("DELETE FROM operation_parents")
        for name, content in (("sync.lock", b"cirrus-drive sync lock v1\n"),
                              ("staging.lock", b"cirrus-drive staging lock v1\n"),
                              ("scheduler.lock", b"cirrus-drive scheduler lock v1\n")):
            marker = state / name
            marker.write_bytes(content)
            marker.chmod(0o600)
            with marker.open("rb") as held:
                fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
                refused = run("uninstall.sh", "--purge-clean-state")
                assert refused.returncode != 0 and db.exists() and marker.exists(), refused.stderr
                assert "account state is in use; state preserved" in refused.stderr, refused.stderr
            success(run("install.sh"))
        snapshots = state / "directory-snapshots"
        snapshots.mkdir(mode=0o700)
        unknown = snapshots / "preserve-unknown"
        unknown.write_text("not disposable without inspection")
        refused = run("uninstall.sh", "--purge-clean-state")
        assert refused.returncode != 0 and db.exists() and unknown.read_text() == "not disposable without inspection", refused.stderr
        assert "directory snapshots contain files or are unsafe; state preserved" in refused.stderr, refused.stderr
        unknown.unlink()
        success(run("install.sh"))
        success(run("uninstall.sh", "--purge-clean-state"))
        assert not state.exists() and keyring.read_text() == "preserve"
        print("PASS: isolated install, dirty/pinned refusal, clean purge and keyring preservation")


if __name__ == "__main__":
    main()
