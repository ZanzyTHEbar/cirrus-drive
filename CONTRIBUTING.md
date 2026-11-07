# Contributing

Use a disposable Linux account, OpenCloud instance and data for mount or sync testing. Never run mutation or fault-injection labs against a production server, real credentials or existing files. Review lab scripts before running them: several depend on host-specific paths and create containers, keyrings and FUSE mounts.

Build and run the workspace checks with the pinned Rust toolchain:

```sh
cargo fmt --all --check
cargo check --locked --workspace
cargo test --locked --workspace
```

For packaging changes, build the normal workspace binaries without fault-injection features and run `python3 scripts/check-packaging-lab.py` in a suitable disposable environment. Set `TMPDIR` to a writable local filesystem with enough space; the packaging lab requires a path without spaces or special characters. Mount labs also need to execute copied binaries and create FUSE mounts there, and use `/dev/shm` for private runtime directories. Other dependencies and isolation requirements are described in the scripts; review them before use.

Keep changes focused and explain behavior and validation in the pull request. For a bug report, include the affected version, steps to reproduce with disposable data, expected and actual behavior, and relevant sanitized logs. Do not post credentials, authorization URLs, personal paths, file contents or private server details.
