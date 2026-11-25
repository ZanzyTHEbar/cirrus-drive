#!/usr/bin/env python3
"""Offline source inventory, not a legal opinion or a binary linkage audit.

Python 3.11+, Cargo and the pinned sources/toolchain must already be installed.
--refresh writes LICENSES; --archive writes a new explicit output. Other modes
are read-only. No builds or network calls.
"""

import argparse
from collections import Counter, defaultdict
from contextlib import ExitStack
import fnmatch
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import stat
import subprocess
import sys
import tarfile
import tomllib

ROOT = Path(__file__).resolve().parent.parent
BUNDLE = ROOT / "LICENSES"
TARGET = "x86_64-unknown-linux-gnu"
ROOTS = {"cirrus-cli", "cirrus-daemon", "cirrus-ui"}
COMMAND = ["cargo", "metadata", "--offline", "--locked", "--format-version", "1",
           "--filter-platform", TARGET]
NOTICE_NAME = re.compile(r"license|licence|copying|notice|copyright|unlicense", re.I)


def git_blob(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def generated_inputs(label, source, exact, retain):
    specs = json.loads((BUNDLE / "generated-input-spec.json").read_text())
    selected = [s for s in specs if s["package"] == label]
    if not selected:
        return [], None
    spec, = selected
    info = json.loads(exact(source / ".cargo_vcs_info.json"))
    require(info["git"]["sha1"] == spec["revision"] and info["path_in_vcs"] == spec["package_path"],
            f"generated-input package revision changed: {label}")
    trees = {}
    for repo, rev in {(spec["repository"], spec["revision"]), (spec["input_repository"], spec["input_revision"])}:
        tree = json.loads((BUNDLE / "provenance/trees" / (rev + ".json")).read_text())
        require(tree["repository"] == repo and tree["revision"] == rev and tree["truncated"] is False,
                f"invalid recorded upstream tree: {label}")
        trees[rev] = {e["path"]: e for e in tree["tree"]}
    if spec["submodule"]:
        link = trees[spec["revision"]][spec["submodule"]]
        require(link["mode"] == "160000" and link["sha"] == spec["input_revision"], f"submodule drift: {label}")
    records = json.loads((BUNDLE / "generated-inputs.json").read_text())
    record, = [r for r in records if r["package"] == label]
    expected = {(rev, e["path"], kind) for rev, patterns, kind in
                [(spec["revision"], spec["drivers"], "driver"), (spec["input_revision"], spec["inputs"], "input")]
                for e in trees[rev].values() if e["type"] == "blob" and any(fnmatch.fnmatchcase(e["path"], p) for p in patterns)}
    require(expected == {(f["revision"], f["path"], f["kind"]) for f in record["files"]}, f"generated inputs omitted: {label}")
    notices = []
    for f in record["files"]:
        data = gzip.decompress((BUNDLE / f["file"]).read_bytes())
        entry = trees[f["revision"]][f["path"]]
        require(git_blob(data) == f["git_blob"] == entry["sha"] and digest(data) == f["sha256"], f"generated input corrupt: {label}/{f['path']}")
        require(f["repository"] == (spec["repository"] if f["kind"] == "driver" else spec["input_repository"]), "generated input repository changed")
        if f["kind"] == "driver":
            continue
        excerpts = []
        if NOTICE_NAME.search(Path(f["path"]).name):
            excerpts.append(data)
        elif f["path"].endswith(".grammar.json"):
            match = re.search(rb'"copyright"\s*:\s*\[.*?\]', data, re.S)
            if match:
                excerpts.append(match.group())
        elif f["path"].endswith(".xml"):
            excerpts += [m.group(1) for m in re.finditer(rb"<copyright(?:\s[^>]*)?>(.*?)</copyright>", data, re.S)]
            excerpts += [m.group(1) for m in re.finditer(rb"<comment>(.*?)</comment>", data, re.S)
                         if re.search(rb"copyright", m.group(1), re.I)]
            # XCB uses XML comments, unlike Wayland's <copyright> elements.
            excerpts += [m.group(1) for m in re.finditer(rb"<!--(.*?)-->", data, re.S)
                         if re.search(rb"copyright", m.group(1), re.I)]
            require(bool(excerpts), f"per-input XML copyright notice absent: {f['path']}")
        elif f["path"].endswith(".h"):
            headers = [m.group() for m in re.finditer(rb"/\*.*?\*/", data, re.S)
                       if re.search(rb"copyright", m.group(), re.I)]
            require(bool(headers), f"native input header grant missing: {f['path']}")
            excerpts.extend(headers)
        for index, excerpt in enumerate(excerpts):
            notices.append(retain(excerpt, f["path"], kind="generated-input-notice", url=f["url"],
                                  input_git_blob=f["git_blob"], occurrence=index))
    # Published outputs match the very same source-control snapshot as its drivers.
    anchors = []
    for pattern in spec["published_generated"]:
        paths = sorted(source.glob(pattern))
        require(bool(paths), f"published generated output absent: {label}/{pattern}")
        for path in paths:
            relative = path.relative_to(source).as_posix()
            blob = git_blob(exact(path))
            require(trees[spec["revision"]][spec["package_path"] + "/" + relative]["sha"] == blob,
                    f"published generated output differs from upstream snapshot: {label}/{relative}")
            anchors.append({"path": relative, "git_blob": blob})
    require(bool(notices), f"no generated input notices: {label}")
    return notices, {"spec": spec, "published_outputs": anchors, "files": record["files"]}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def run(command, cwd=ROOT):
    return subprocess.check_output(command, cwd=cwd, timeout=60)


def encoded(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def historical_native():
    """Validate retained artifact evidence without asserting it describes today's source."""
    data = (BUNDLE / "native-linkage.json").read_bytes()
    review = json.loads((BUNDLE / "review.json").read_text())
    require(review["historical_native_sha256"] == digest(data), "historical native record anchor mismatch")
    native = json.loads(data)
    require(native["schema"] == 2 and native["qualification"] ==
            {"status": "historical-only", "current_artifact_qualified": False}, "unsupported native evidence classification")
    require(native["target"] == TARGET and native["fault_injection"] is False, "native artifact configuration mismatch")

    def checksum(value):
        require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value), "invalid native SHA-256")

    def relative(value, basename=False):
        require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9._+@/-]+", value), "unsafe native path")
        path = PurePosixPath(value)
        require(not path.is_absolute() and path.as_posix() == value and value != "." and ".." not in path.parts
                and (not basename or len(path.parts) == 1), "unsafe native path")

    checksum(native["source_content_digest"])
    require(bool(native["project_files"]), "native project bindings missing")
    for name, expected in native["project_files"].items():
        relative(name)
        checksum(expected)
        # Historical first-party paths may change or disappear; never rebind them here.
    documents = {}
    for document in native["documents"]:
        name = document["file"]
        relative(name)
        checksum(document["sha256"])
        require(name == "native/" + document["sha256"] + ".txt" and name not in documents,
                "invalid or duplicate native document reference")
        path = BUNDLE / name
        require(not path.is_symlink() and path.resolve().is_relative_to(BUNDLE.resolve()), "unsafe native document")
        text = path.read_bytes()
        require(bool(text.strip()) and digest(text) == document["sha256"], "native license text missing or corrupt")
        require(bool(document["origins"]), "native document origin missing")
        for origin in document["origins"]:
            if "package" in origin:
                relative(origin["document"])
                require(bool(origin["package"]) and bool(origin["version"]), "native package origin missing")
            else:
                relative(origin["common_license"], basename=True)
        documents[name] = document
    require({p.relative_to(BUNDLE).as_posix() for p in (BUNDLE / "native").rglob("*") if p.is_file()} == set(documents),
            "unreferenced or missing native license documents")
    packages = {}
    for row in native["system_package_documents"]:
        key = row["package"] + "@" + row["version"]
        require(key not in packages and row["copyright"] in documents, "invalid native package document reference")
        require(any(o.get("package") == row["package"] and o.get("version") == row["version"]
                    for o in documents[row["copyright"]]["origins"]), "native package origin mismatch")
        packages[key] = row
    for document in documents.values():
        for origin in document["origins"]:
            if "package" in origin:
                key = origin["package"] + "@" + origin["version"]
                require(key in packages and packages[key]["copyright"] == document["file"], "native origin package reference mismatch")
    binaries = native["binaries"]
    require(set(binaries) == {"cirrus-daemon", "cirrus-ui"}, "historical native binary identities changed")
    static = {name: set() for name in binaries}
    for row in native["system_static_inputs"]:
        relative(row["file"], basename=True)
        checksum(row["file_sha256"])
        require(row["package"] in packages, "native static package reference missing")
        name = row["file"]
        if row["archive_member"] is not None:
            relative(row["archive_member"], basename=True)
            name += "(" + row["archive_member"] + ")"
        require(bool(row["binaries"]) and set(row["binaries"]) <= set(binaries), "native static binary reference missing")
        for binary in row["binaries"]:
            require(name not in static[binary], "duplicate native static input")
            static[binary].add(name)
    for name, binary in binaries.items():
        checksum(binary["sha256"])
        checksum(binary["link_map_sha256"])
        require(type(binary["bytes"]) is int and binary["bytes"] > 0 and re.fullmatch(r"[0-9]+\.[0-9]+", binary["glibc_floor"]),
                "invalid native binary size/version")
        require(set(binary["system_static_inputs"]) == static[name], "native static attribution mismatch")
        for archive in binary["archive_input_basenames"]:
            relative(archive, basename=True)
        for soname in binary["needed"]:
            relative(soname, basename=True)
        require({r["soname"] for r in binary["system_libraries"]} == set(binary["needed"]), "native ELF dependency reference mismatch")
        for library in binary["system_libraries"]:
            checksum(library["sha256"])
            require(library["package"] in packages, "native library package reference missing")
    for loader in native["source_declared_loaders"]:
        relative(loader["source"])
        relative(loader["soname"], basename=True)
        require(type(loader["available_on_build_host"]) is bool, "invalid historical loader availability")
        if loader["available_on_build_host"]:
            checksum(loader["sha256"])
            require(loader["package"] in packages, "native loader package reference missing")
    return native


def inventory():
    meta = json.loads(run(COMMAND))
    packages = {p["id"]: p for p in meta["packages"]}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    roles = defaultdict(set)

    def walk(pid, role):
        if role in roles[pid]:
            return
        roles[pid].add(role)
        for dep in nodes[pid]["deps"]:
            for kind in dep["dep_kinds"]:
                if kind["kind"] == "dev":
                    continue
                macro = any("proc-macro" in t["kind"] for t in packages[dep["pkg"]]["targets"])
                tool = role == "build-tool" or kind["kind"] == "build" or macro
                walk(dep["pkg"], "build-tool" if tool else "runtime-candidate")

    roots = [p for p in packages.values() if p["name"] in ROOTS and p["id"] in meta["workspace_members"]]
    require({p["name"] for p in roots} == ROOTS, "distribution roots changed")
    for p in roots:
        walk(p["id"], "runtime-candidate")
    lock = tomllib.loads((ROOT / "Cargo.lock").read_text())["package"]
    locked = {(p["name"], p["version"], p.get("source")): p for p in lock}
    output = {}
    records = []
    generated = []
    chosen = set()
    supplements = json.loads((BUNDLE / "upstream.json").read_text())

    def retain(data, source_path, **extra):
        require(bool(data.strip()), f"empty notice: {source_path}")
        data.decode("utf-8")
        suffix = ".html" if source_path.endswith(".html") else ".txt"
        name = "texts/" + digest(data) + suffix
        output[name] = data
        return {"file": name, "sha256": digest(data), "source_path": source_path, **extra}

    for pid in sorted(roles, key=lambda i: (packages[i]["name"], packages[i]["version"])):
        p = packages[pid]
        key = (p["name"], p["version"], p["source"])
        require(key in locked, f"not pinned: {p['name']}")
        chosen.add(key)
        # First-party manifests are bound separately; the project LICENSE applies.
        if pid in meta["workspace_members"]:
            continue
        source = Path(p["manifest_path"]).parent
        label = p["name"] + "@" + p["version"]
        notices = []
        paths = sorted(f for f in source.rglob("*") if f.is_file() and NOTICE_NAME.search(f.name))
        archive = None
        git_root = None
        if p["source"].startswith("registry+"):
            crate = source.parents[2] / "cache" / source.parent.name / (source.name + ".crate")
            require(digest(crate.read_bytes()) == locked[key]["checksum"], f"archive checksum mismatch: {label}")
            archive = tarfile.open(crate, "r:gz")
            prefix = source.name + "/"
            expected = {m.name[len(prefix):] for m in archive.getmembers()
                        if m.isfile() and m.name.startswith(prefix) and NOTICE_NAME.search(Path(m.name).name)}
            require(expected == {f.relative_to(source).as_posix() for f in paths},
                    f"cached license documents missing or added: {label}")
        else:
            require(p["source"].startswith("git+"), f"unsupported source: {label}")
            git_root = Path(run(["git", "rev-parse", "--show-toplevel"], source).decode().strip())
            require(run(["git", "rev-parse", "HEAD"], source).decode().strip() == p["source"].split("#")[-1],
                    f"git revision mismatch: {label}")

        def exact(f):
            data = f.read_bytes()
            if archive:
                member = archive.extractfile(source.name + "/" + f.relative_to(source).as_posix())
                require(member is not None and member.read() == data, f"source differs from pinned archive: {label}/{f.name}")
            else:
                upstream = run(["git", "show", "HEAD:" + f.relative_to(git_root).as_posix()], git_root)
                require(upstream == data, f"source differs from pinned revision: {label}/{f.name}")
            return data

        try:
            exact(source / "Cargo.toml")
            if p["license_file"]:
                f = source / p["license_file"]
                require(f.is_file() and f.resolve().is_relative_to(source.resolve()), f"missing declared license file: {label}")
                if f not in paths:
                    paths.append(f)
            if git_root:
                paths.append(git_root / "LICENSE")
            for f in paths:
                base = git_root if git_root else source
                notices.append(retain(exact(f), f.relative_to(base).as_posix(), kind="upstream-document"))
            # Protocol-generated Rust inherits per-protocol notices, not just the wrapper license.
            for f in sorted(source.rglob("*.xml")):
                data = exact(f)
                for index, match in enumerate(re.finditer(rb"<copyright(?:\s[^>]*)?>(.*?)</copyright>", data, re.S)):
                    notices.append(retain(match.group(1), f.relative_to(source).as_posix(),
                                          kind="protocol-copyright", occurrence=index))
            # Native crypto has per-file grants in addition to its aggregate licenses.
            if p["name"] == "ring":
                for f in sorted(source.rglob("*")):
                    if f.suffix not in {".c", ".h", ".S", ".rs"} or not f.is_file():
                        continue
                    data = exact(f)
                    header = re.match(rb"(?:\s+|//[^\n]*(?:\n|$)|/\*.*?\*/)*", data, re.S).group()
                    if re.search(rb"copyright|license|permission", header, re.I):
                        notices.append(retain(header, f.relative_to(source).as_posix(), kind="source-header"))
            if p["name"] == "libsqlite3-sys":
                f = source / "sqlite3/sqlite3.h"
                header = re.match(rb"/\*.*?\*/", exact(f), re.S)
                require(header is not None and b"disclaims copyright" in header.group(), "SQLite grant not found")
                notices.append(retain(header.group(), "sqlite3/sqlite3.h", kind="source-header"))
            for s in supplements:
                if s["package"] != label:
                    continue
                info = json.loads(exact(source / ".cargo_vcs_info.json"))
                require(info["git"]["sha1"] == s["revision"], f"upstream revision drift: {label}")
                require(p["repository"].rstrip("/").endswith("/" + s["repository"]), f"repository drift: {label}")
                data = (BUNDLE / "upstream" / label / s["path"]).read_bytes()
                blob = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
                require(blob == s["git_blob"], f"upstream blob mismatch: {label}")
                url = f"https://raw.githubusercontent.com/{s['repository']}/{s['revision']}/{s['path']}"
                notices.append(retain(data, s["path"], kind="pinned-upstream-document", url=url, git_blob=blob))
            extra, provenance = generated_inputs(label, source, exact, retain)
            notices.extend(extra)
            if provenance:
                generated.append(provenance)
        finally:
            if archive:
                archive.close()
        require(bool(notices), f"no license text for {label}; obtain exact upstream text before refreshing")
        records.append({"package": label, "source": p["source"], "checksum": locked[key].get("checksum"),
                        "repository": p["repository"], "declared_license": p["license"],
                        "roles": sorted(roles[pid]), "features": sorted(nodes[pid]["features"]),
                        "links": p["links"], "notices": notices})

    rustc = run(["rustc", "-vV"]).decode()
    channel = tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"]
    require(f"release: {channel}\n" in rustc and f"host: {TARGET}\n" in rustc,
            "installed Rust toolchain/host does not match this notice inventory's supported configuration")
    sysroot = Path(run(["rustc", "--print", "sysroot"]).decode().strip())
    docs = sysroot / "share/doc/rust"
    std_notices = []
    for f in [docs / "COPYRIGHT-library.html", *sorted((docs / "licenses").glob("*.txt"))]:
        data = f.read_bytes()
        require(bool(data.strip()), "empty toolchain license")
        name = "rust-standard-library/" + f.relative_to(docs).as_posix()
        output[name] = data
        std_notices.append({"file": name, "sha256": digest(data),
                            "source_path": f.relative_to(docs).as_posix(), "kind": "toolchain-document"})
    require(len(std_notices) > 1, "Rust standard-library license texts unavailable")
    manifests = [ROOT / "Cargo.toml", ROOT / "rust-toolchain.toml"]
    manifests.extend(Path(p["manifest_path"]) for p in packages.values() if p["id"] in meta["workspace_members"])
    excluded = [{"name": n, "version": v, "source": s} for n, v, s in locked if (n, v, s) not in chosen]
    result = {"schema": 1, "target": TARGET, "roots": sorted(ROOTS), "metadata_command": COMMAND,
              "feature_policy": "workspace defaults; no fault-injection; non-dev edges; host tools classified separately; metadata feature union is not a Cargo unit graph",
              "lock_sha256": digest((ROOT / "Cargo.lock").read_bytes()),
              "inputs": {f.relative_to(ROOT).as_posix(): digest(f.read_bytes()) for f in sorted(manifests)},
              "packages": records, "unselected_lock_packages": excluded,
              "generated_input_provenance": generated,
              "rust_standard_library": {"rustc": rustc, "notices": std_notices}}
    native = historical_native()
    result["qualification"] = "source-notices-only; historical native evidence is not current artifact qualification"
    result["native_linkage"] = native
    output["inventory.json"] = encoded(result)
    index = ["# Dependency notice index", "", "Generated from the pinned source graph; see [scope and limitations](../THIRD_PARTY_NOTICES.md).",
             "", "License expressions below are upstream declarations, not substitutes for the linked texts.", "",
             "| Package | Role | Declared license | Retained texts (upstream paths) |", "| --- | --- | --- | --- |"]
    for p in records:
        links = "; ".join(f"[{n['source_path']}]({n['file']})" for n in p["notices"])
        index.append(f"| {p['package']} | {', '.join(p['roles'])} | {p['declared_license']} | {links} |")
    index += ["", "## Rust standard library", "", "```text", result["rust_standard_library"]["rustc"].rstrip(), "```", ""]
    index += [f"- [{n['source_path']}]({n['file']})" for n in std_notices]
    index += ["", "## Historical native runtime and startup materials", "",
              "[Historical binary hashes, linkage and unresolved obligations](native-linkage.json).",
              "Independently anchored by review.json; not current-source or current-binary native qualification.",
              "These package documents may cover more components than the linked objects; system libraries are not bundled.", ""]
    index += [f"- [{', '.join(o.get('package', o.get('common_license', 'license')) for o in d['origins'])}]({d['file']})"
              for d in native["documents"]]
    output["INDEX.md"] = ("\n".join(index) + "\n").encode()
    return result, output


def verify(output):
    for name, data in output.items():
        require((BUNDLE / name).is_file() and (BUNDLE / name).read_bytes() == data, f"missing or stale artifact: LICENSES/{name}")
    actual = {p.relative_to(BUNDLE).as_posix() for directory in ("texts", "rust-standard-library")
              for p in (BUNDLE / directory).rglob("*") if p.is_file()}
    expected = {name for name in output if name.startswith(("texts/", "rust-standard-library/"))}
    require(actual == expected, "unreferenced or missing retained texts")


def complete(result):
    review = json.loads((BUNDLE / "review.json").read_text())
    require(result["native_linkage"]["qualification"]["status"] != "historical-only",
            "historical native evidence does not qualify current release artifacts; selected-candidate qualification is not implemented")
    require(review["lock_sha256"] == result["lock_sha256"], "review lock binding is stale")
    require(review["inventory_sha256"] == digest(encoded(result)), "review inventory binding is stale")
    require(not review["blockers"], "distribution review blocked: " + "; ".join(review["blockers"]))
    require(review["source_notices_reviewed"] is True and review["native_artifact_reviewed"] is True,
            "source/native review not complete")


def bundle_files():
    files = {name: (ROOT / name).read_bytes() for name in ("LICENSE", "THIRD_PARTY_NOTICES.md")}
    for path in sorted(BUNDLE.rglob("*")):
        require(not path.is_symlink(), "symlinks are not permitted in the notice bundle")
        if path.is_file() and path != BUNDLE / "SHA256SUMS":
            files["LICENSES/" + path.relative_to(BUNDLE).as_posix()] = path.read_bytes()
    return files


def verify_bundle():
    files = bundle_files()
    sums = "".join(f"{digest(data)}  {name}\n" for name, data in sorted(files.items())).encode()
    require((BUNDLE / "SHA256SUMS").read_bytes() == sums, "bundle checksums missing or stale; inspect changes, then --refresh")
    files["LICENSES/SHA256SUMS"] = sums
    for name in ("THIRD_PARTY_NOTICES.md", "LICENSES/README.md", "LICENSES/INDEX.md"):
        for link in re.findall(r"\]\(([^)]+)\)", files[name].decode()):
            if not link.startswith(("https:", "http:", "#")):
                target = (ROOT / name).parent / link
                require(target.resolve().is_relative_to(ROOT) and target.is_file(), f"broken bundle link: {name}: {link}")
    return files


def verify_packaged(files, directories):
    for directory in directories:
        require(directory is not None and directory.resolve() != ROOT, "actual staging/extraction notice directories required")
        for name, data in files.items():
            path = directory / name
            require(path.is_file() and not path.is_symlink() and path.read_bytes() == data, f"packaged notice missing or changed: {name}")


def refresh_bundle(output):
    """Preflight the whole tree, then replace individual files through pinned directories.

    Replacement never writes an existing inode, even if a target is swapped after
    its last check. This is per-file atomic, not a transaction across the bundle.
    """
    def relative(name):
        path = PurePosixPath(name)
        require(re.fullmatch(r"[A-Za-z0-9._+@/-]+", name) and not path.is_absolute()
                and path.as_posix() == name and name != "." and ".." not in path.parts, "unsafe refresh output path")
        return path.parts

    def regular(info):
        require(not stat.S_ISLNK(info.st_mode), "symlinks are not permitted in refresh output")
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid(), "refresh file is not a user-owned regular file")
        require(info.st_nlink == 1, "hardlinked files are not permitted in refresh output")

    def identity(info):
        return None if info is None else (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                                          info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    with ExitStack() as stack:
        def directory(name, parent=None):
            fd = os.open(name, flags, dir_fd=parent)
            stack.callback(os.close, fd)
            info = os.fstat(fd)
            require(info.st_uid in (0, os.geteuid()) and not info.st_mode & stat.S_IWOTH,
                    "unsafe refresh ancestor directory")
            return fd

        # Do not let even a bundle-root/ancestor symlink redirect refresh writes.
        anchor = directory("/")
        for part in BUNDLE.parts[1:]:
            anchor = directory(part, anchor)
        require(os.fstat(anchor).st_uid == os.geteuid(), "refresh directory is not user-owned")
        directories = {"": anchor}
        entries, contents = {}, {}
        pending = [""]
        while pending:
            parent = pending.pop()
            fd = directories[parent]
            for leaf in os.listdir(fd):
                name = parent + "/" + leaf if parent else leaf
                relative(name)
                info = os.stat(leaf, dir_fd=fd, follow_symlinks=False)
                require(not stat.S_ISLNK(info.st_mode), "symlinks are not permitted in refresh output")
                entries[name] = info
                if stat.S_ISDIR(info.st_mode):
                    child = directory(leaf, fd)
                    require(identity(os.fstat(child)) == identity(info) and info.st_uid == os.geteuid(),
                            "refresh directory changed or is not user-owned")
                    directories[name] = child
                    pending.append(name)
                else:
                    regular(info)
                    # NONBLOCK avoids a FIFO substitution blocking before fstat.
                    with os.fdopen(os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK,
                                           dir_fd=fd), "rb") as source:
                        regular(os.fstat(source.fileno()))
                        require(identity(os.fstat(source.fileno())) == identity(info), "refresh input changed during preflight")
                        contents[name] = source.read()

        require("SHA256SUMS" not in output, "refresh checksum must be generated separately")
        files = {name: (ROOT / name).read_bytes() for name in ("LICENSE", "THIRD_PARTY_NOTICES.md")}
        files.update({"LICENSES/" + name: data for name, data in contents.items() if name != "SHA256SUMS"})
        files.update({"LICENSES/" + name: data for name, data in output.items()})
        planned = dict(output)
        planned["SHA256SUMS"] = "".join(f"{digest(data)}  {name}\n" for name, data in sorted(files.items())).encode()
        missing = set()
        # Validate EVERY planned leaf and parent before mkdir, temp creation or replacement.
        for name in planned:
            parts = relative(name)
            if name in entries:
                regular(entries[name])
            for end in range(1, len(parts)):
                parent = "/".join(parts[:end])
                require(parent not in planned, "refresh output is also an output parent")
                if parent in entries:
                    require(stat.S_ISDIR(entries[parent].st_mode), "refresh parent is not a directory")
                elif parent not in directories:
                    missing.add(parent)
        for name in sorted(missing, key=lambda n: (n.count("/"), n)):
            parts = relative(name)
            parent = directories["/".join(parts[:-1])]
            os.mkdir(parts[-1], mode=0o755, dir_fd=parent)  # EEXIST is a race, not permission to follow it.
            directories[name] = directory(parts[-1], parent)

        for name, data in planned.items():
            parts = relative(name)
            parent, leaf = directories["/".join(parts[:-1])], parts[-1]

            def unchanged():
                try:
                    current = os.stat(leaf, dir_fd=parent, follow_symlinks=False)
                except FileNotFoundError:
                    current = None
                if current is not None:
                    regular(current)
                require(identity(current) == identity(entries.get(name)), "refresh output changed since preflight")

            unchanged()
            temporary = ".cirrus-refresh-" + secrets.token_hex(16)
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                         0o666, dir_fd=parent)
            try:
                with os.fdopen(fd, "wb") as destination:
                    if name in entries:
                        os.fchmod(destination.fileno(), stat.S_IMODE(entries[name].st_mode))
                    destination.write(data)
                    destination.flush()
                    os.fsync(destination.fileno())
                unchanged()
                os.replace(temporary, leaf, src_dir_fd=parent, dst_dir_fd=parent)
                temporary = None  # The name is free after commit; do not unlink a new occupant.
                os.fsync(parent)
            finally:
                if temporary is not None:
                    try:
                        os.unlink(temporary, dir_fd=parent)
                    except FileNotFoundError:
                        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    for name in ("refresh", "verify", "complete", "packaging", "packaging-content", "source-provenance"):
        mode.add_argument("--" + name, action="store_true")
    mode.add_argument("--archive", type=Path, help="write a verified checksum-pinned notice source archive")
    parser.add_argument("--user-notices-dir", type=Path, help="staged per-user share/licenses/cirrus-drive directory")
    parser.add_argument("--arch-notices-dir", type=Path, help="extracted Arch usr/share/licenses/cirrus-drive directory")
    args = parser.parse_args()
    result, output = inventory()
    if args.refresh:
        # Discover and validate every input before writing; never emit placeholders.
        refresh_bundle(output)
    verify(output)
    files = verify_bundle()
    if args.source_provenance:
        require({p["spec"]["package"] for p in result["generated_input_provenance"]} ==
                {s["package"] for s in json.loads((BUNDLE / "generated-input-spec.json").read_text())}, "generated provenance coverage incomplete")
    if args.packaging or args.packaging_content:
        require(args.user_notices_dir is not None and args.arch_notices_dir is not None,
                "both actual per-user install staging and extracted Arch package notices directories are required")
    if args.complete or args.packaging:
        complete(result)
    if args.packaging or args.packaging_content:
        verify_packaged(files, (args.user_notices_dir, args.arch_notices_dir))
    if args.archive:
        with args.archive.open("xb") as dest, gzip.GzipFile(fileobj=dest, mode="wb", mtime=0, filename="") as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for name, data in sorted(files.items()):
                    entry = tarfile.TarInfo("cirrus-notices/" + name)
                    entry.size, entry.mode, entry.mtime = len(data), 0o644, 0
                    archive.addfile(entry, io.BytesIO(data))
        print(f"notice archive sha256={digest(args.archive.read_bytes())}")
    counts = Counter(",".join(p["roles"]) for p in result["packages"])
    text_names = {name for name in output if name.startswith(("texts/", "rust-standard-library/"))}
    text_names.update(d["file"] for d in result.get("native_linkage", {}).get("documents", []))
    print(json.dumps({"third_party_packages": len(result["packages"]), "roles": counts,
                      "unselected_lock_packages": len(result["unselected_lock_packages"]),
                      "distinct_texts": len(text_names)}, sort_keys=True))
    print("GENERATED INPUT PROVENANCE VERIFIED (source only; not current binary qualification)" if args.source_provenance else
          "NOTICE CONTENTS VERIFIED (not release qualification)" if args.packaging_content else
          "THIRD PARTY PACKAGING VERIFIED" if args.packaging else
          "THIRD PARTY BUNDLE COMPLETE" if args.complete else "SOURCE NOTICE CONTENTS VERIFIED (not current binary qualification)")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, subprocess.SubprocessError, tarfile.TarError) as error:
        print(f"third-party notices: {error}", file=sys.stderr)
        sys.exit(1)
