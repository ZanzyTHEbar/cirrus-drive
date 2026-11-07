# Cirrus Drive

Cirrus Drive is an `experimental` early alpha Linux OpenCloud client. 

This was made partially because u do not like the native Qt OpenCloud app, interface, or filesystem implementation on Linux.

A per-user daemon mounts Spaces through FUSE; a desktop window and CLI control the daemon. Files are read on demand, and edits are staged locally for synchronization.

## Requirements

- Linux with FUSE 3 (`/dev/fuse` and `fusermount3`), a private `XDG_RUNTIME_DIR`, and Linux 5.6 or newer with `openat2` available.
- A graphical session with a browser, desktop portal and an unlocked Secret Service keyring for sign-in. The desktop window also needs a working Vulkan implementation.
- Rust toolchain from `rust-toolchain.toml` and the native libraries required to build the workspace. State must be on a supported local filesystem. Network and FUSE filesystems are not supported for state.

Only one account is supported for now. Multiple Spaces may be mounted at separate locations. Credentials are stored in Secret Service. Local state and file content are stored under `~/.local/state/cirrus-drive` without application-level encryption. Same-user processes are not isolated from one another. Storage controls do not impose a hard global limit. 

> [!NOTE]
> This is eadly aloha and experimental
> There is no state migration or account-removal workflow yet. Updates may reject older state rather than migrate it. This will be fixed soon.

## Build and install

```sh
cargo build --locked --workspace
./packaging/install.sh
systemctl --user daemon-reload
systemctl --user start cirrus-drive.service
```

The installer uses the debug binaries in `target/debug`, installs user-local binaries, a systemd user service and a desktop launcher, and refuses to replace existing installation files. It does not start or enable the service. To use release binaries instead, build with `cargo build --locked --workspace --release` and run `CIRRUS_BIN_DIR="$PWD/target/release" ./packaging/install.sh`. An experimental Arch package recipe is described in [packaging/arch/README.md](packaging/arch/README.md).

Alternatively, run `target/debug/cirrus-daemon` in a terminal. The daemon must remain running while the mount is in use. Run `target/debug/cirrus-ui` for the window. The commands below assume the installed binaries are on `PATH`.

## Connect and mount

```sh
cirrus-daemon --connect https://cloud.example
cirrus-daemon --spaces https://cloud.example
cirrus-daemon --select-space https://cloud.example SPACE_ID
cirrus-daemon --mount-space https://cloud.example SPACE_ID /absolute/path/to/empty-directory
cirrus-daemon --mounts
```

Replace the URL and Space ID with those of your instance. The mountpoint must be an existing empty, user-owned directory with mode `0700`. Omit the mountpoint to create a default directory under your home. For a private CA, append `--ca-cert /path/to/ca.pem` to `--connect`. Closing the window does not stop the daemon.

## Sync, status and recovery

```sh
cirrus-daemon --status
cirrus-daemon --sync-status https://cloud.example SPACE_ID
cirrus-daemon --sync-space https://cloud.example SPACE_ID
cirrus-daemon --journal https://cloud.example
cirrus-daemon --unmount-space https://cloud.example SPACE_ID
```

A successful mount enables automatic write-back for that Space. Explicit sync is also available. Check sync status and the journal for pending, conflict or uncertain operations. Do not assume a failed or uncertain operation was applied or safely replayed. If the daemon crashes, restart it and use `cirrus-daemon --recover-mount /absolute/path/to/mountpoint` for each recorded mount before mounting again. Recovery checks ownership and does not remove the mountpoint.

Retained staged files and pinned copies can be inspected and exported using the commands in `cirrus-daemon --help`; retain the local state when investigating a problem. Saved metadata can be stale, and offline reads fail when the necessary content is unavailable. Do not delete local state or keyring entries to resolve an error without first preserving the data you need.

To uninstall user artifacts, unmount all Spaces and stop the service first, then run `./packaging/uninstall.sh`. The default uninstall retains local state and credentials. See `cirrus-daemon --help` and `cirrus-ui --help` for additional commands.

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md). Cirrus Drive is licensed under [Apache License 2.0](LICENSE); dependencies have their own licenses. See the [Rune and font notices](THIRD_PARTY_NOTICES.md).
