# Cirrus Drive

Cirrus Drive is an experimental early-alpha OpenCloud client for Linux, with macOS support under development.

This was made partially because I do not like the native Qt OpenCloud app, interface, or filesystem implementation on Linux.

A per-user daemon mounts Spaces through FUSE; a desktop window and CLI control the daemon. Files are read on demand, and edits are staged locally for synchronization.

v0.1 targets unmodified stock OpenCloud; a custom backend or Reva fork is not required. Cirrus does not add stronger server-side atomicity or concurrency guarantees. Remote bytes are not guaranteed to be atomically bound to observed versions, and concurrent remote changes can cause lost updates during writes, deletes and renames. Local `fsync` does not mean an upload is confirmed. Evaluate this alpha with disposable data and keep independent backups; pinned or staged content is not a backup.

The macOS source and build targets are experimental. Compile/link and standalone worker checks do not establish an installed app, Finder extension, Keychain or Spotlight integration. The instructions below cover Linux, not macOS installation.

## Linux requirements

- Linux with FUSE 3 (`/dev/fuse` and `fusermount3`), a private `XDG_RUNTIME_DIR`, a user D-Bus session, and Linux 5.6 or newer with `openat2` available.
- A graphical session with a browser, desktop portal and an unlocked Secret Service keyring for sign-in. The desktop window also needs a working Vulkan implementation.
- Rust toolchain from `rust-toolchain.toml` and the native libraries required to build the workspace. State requires a local filesystem accepted by the coordination checks: ext2/3/4, XFS, Btrfs, tmpfs, F2FS or ZFS. This is an implementation allowlist, not a tested durability matrix; tmpfs is volatile. Network and FUSE filesystems are not supported for state.

Only one account is supported for now. Multiple Spaces may be mounted at separate locations. Credentials are stored in Secret Service. Local state and file content are stored under `~/.local/state/cirrus-drive` without application-level encryption. Same-user processes are not isolated from one another. Storage controls do not impose a hard global limit.

> [!NOTE]
> This is an experimental early alpha, not a production-ready filesystem.
> There is no state migration or account-removal workflow yet. Updates may reject older state rather than migrate it.

Locking the keyring does not encrypt or revoke access to retained local content. Private file permissions do not protect it from other processes running as you, administrators or someone with access to the underlying disk.

## Experimental filesystem scope

Tested scope is Linux x86_64, one writer and two independent Space mounts, with small-file create/edit/save/rename/delete workflows and headless Vim 9.1 using `-Nu NONE -i NONE -es`. Explicit writable-offline edits, restart/reconnect, local CLI export and stale-mount recovery, and opt-in budget/reserve refusals with clean-cache reclamation have bounded coverage. This does not establish a maximum tested capacity or throughput, general application or GUI compatibility, read-only offline coverage, physical disk-failure durability or safe concurrent server editing. No Linux distribution, desktop environment or release package is qualified.

The implemented common operations are directory listing, on-demand regular-file reads, create, write, append, truncate, mkdir, unlink, empty rmdir and bounded rename/replacement. This is not a qualified application-compatibility or full POSIX contract. File rename can upload the destination before deleting the source; it is not a remote atomic rename. Directory moves and open-unlinked/replaced-file handling are partial. Cross-Space moves are not atomic.

Mounts are private and `noexec`, `nosuid`, `nodev`. File modes are presented as `0600` and directory modes as `0700`, not remote POSIX permissions. Permission/ownership/timestamp changes, executable bits, symlinks, hard links, special files, extended attributes and POSIX record locking are unsupported. Rename exchange and whiteout are unsupported. Do not use the mount as a database, VM disk or a substitute for a local POSIX filesystem.

Implementation refusal ceilings include 128 open files and 128 open directory handles per mount, 16,384 tracked nodes, and remote listings bounded by 16,383 entries and 2 MiB of encoded metadata. Pins are bounded snapshots (4,096 entries, depth 128, 1 GiB of content per pin), not continuously updated mirrors. Smaller operations may still be refused because of metadata, storage, identity or unresolved-operation constraints. These ceilings are not tested capacity, performance or scale guarantees; no production operating envelope is currently qualified.

## Build and install (Linux)

```sh
cargo build --locked --workspace
./packaging/install.sh
systemctl --user daemon-reload
systemctl --user start cirrus-drive.service
```

The installer uses the debug binaries in `target/debug`, installs user-local binaries, a systemd user service and a desktop launcher, and refuses to replace existing installation files. It does not start or enable the service. To use release binaries instead, build with `cargo build --locked --workspace --release` and run `CIRRUS_BIN_DIR="$PWD/target/release" ./packaging/install.sh`. An experimental Arch package recipe is described in [packaging/arch/README.md](packaging/arch/README.md). Both recipes include the retained [license and notice bundle](THIRD_PARTY_NOTICES.md); release-specific dependency review and actual package qualification remain incomplete and are required before distribution.

Alternatively, run `target/debug/cirrus-drive-service` in a terminal. The service must remain running while the mount is in use. `cirrus-daemon` is the command client; it never starts the service. Run `target/debug/cirrus-ui` for the window. The commands below assume the installed binaries are on `PATH`.

Use matching binaries. Standard and package-managed installations still upgrade through [Stop, uninstall or upgrade](#stop-uninstall-or-upgrade). A user-managed installation can opt in to [signed live scheduling and staged-read planner updates](packaging/linux-live-release.md) after its first maintenance transition. The FUSE transport and resident operation executor are not replaced live.

If the Linux service reports that offline State requires maintenance, stop all
Cirrus services for this account, unmount their drives, and stop any other
program using this State directory. Then run the new service binary as the
same user, with the normal `XDG_RUNTIME_DIR`:

```sh
cirrus-drive-service --prepare-state --legacy-writers-stopped
```

Restart the service only after the command succeeds. Preparation upgrades
known State schemas in place; it does not replace the database or staged
objects. Older binaries may ignore the maintenance lock, so running this
command is not a substitute for stopping them. Do not restore an older
database to roll back the software: it would omit edits acknowledged since
the upgrade. Use only a previous binary that can read and write the current State.

## Connect and mount

```sh
cirrus-daemon --connect https://cloud.example
cirrus-daemon --spaces https://cloud.example
cirrus-daemon --mount-space https://cloud.example SPACE_ID /absolute/path/to/empty-directory
cirrus-daemon --mounts
```

Replace the URL and use the ID from `--spaces`. The mountpoint must be an existing empty, user-owned directory with mode `0700`. Omit the mountpoint to create a default directory under your home; this always requires a fresh authenticated Space listing with a unique, safe name. For a private CA, append `--ca-cert /path/to/ca.pem` to `--connect`. Closing the window does not stop the daemon.

Space operations take an explicit ID and no longer save a selected Space. This build cannot read older disposable sign-ins saved with Space-selection fields.

With an explicit mountpoint, `--mount-space` can resume an ordinary mount if the very first connection to the server for the Space listing is refused or the host or network is unreachable. It requires readable, complete saved credentials with no interrupted refresh, a prior activation for that exact Space, and a retained root directory that matches the saved account identity. It does not fall back on ambiguous timeouts, TLS or HTTP failures, incomplete listings, or a listing that omits the Space. The same mount can use the server again when connectivity returns and access checks succeed.

## List and import files

List the Space root and stage a local file using the signed-in account:

```sh
cirrus-daemon --ls-space https://cloud.example SPACE_ID
cirrus-daemon --stage-file-space https://cloud.example SPACE_ID /draft.txt /absolute/path/to/local-draft.txt
```

Omitting the listing path lists the root. The import takes the destination path inside the Space first, then the absolute path to a regular local source file. It stages the whole file; success does not confirm an upload.

To stage using only retained state, use `--stage-file-offline-space` instead:

```sh
cirrus-daemon --stage-file-offline-space https://cloud.example SPACE_ID /draft.txt /absolute/path/to/local-draft.txt
```

This needs a matching retained account and previously activated Space, plus saved directory evidence for the destination. It does not use credentials, contact the server or activate sync. It does not turn off background sync for a Space that was already activated.

`cirrus-daemon --pins-space https://cloud.example SPACE_ID` reports local pin status, not server freshness. Append `--check-remote` to request an authenticated comparison; if the service cannot complete it, check stderr for the reason. An `available offline` result can still be based on local state alone.

## Sync, status and recovery

```sh
cirrus-daemon --status
cirrus-daemon --sync-status https://cloud.example SPACE_ID
cirrus-daemon --sync-space https://cloud.example SPACE_ID
cirrus-daemon --journal https://cloud.example
cirrus-daemon --unmount-space https://cloud.example SPACE_ID
```

A successful online mount records that Space as activated for automatic write-back. Starting `cirrus-drive-service --no-auto-sync` disables the worker, not explicit sync. `--sync-space` targets one Space; `--sync HTTPS_URL` is account-wide. `--sync-status` reports local status for one Space. `--journal HTTPS_URL` reads the account-wide local journal without syncing; use `--journal-space HTTPS_URL SPACE_ID` to narrow it. If the client reports an unknown outcome after submission, inspect the relevant local state before repeating a change.

If the daemon crashes, restart it and use `cirrus-daemon --recover-mount /absolute/path/to/mountpoint` for each recorded mount before mounting again. Recovery checks ownership and does not remove the mountpoint.

Retained staged files and pinned copies can be inspected and exported using the commands in `cirrus-daemon --help`; retain the local state when investigating a problem. Saved metadata can be stale, and offline reads fail when the necessary content is unavailable. Do not delete local state or keyring entries to resolve an error without first preserving the data you need.

Online mounts require authentication and network access for uncached data and remote checks. Pinning is explicit; merely listing or opening a file does not make a whole Space available offline. `--mount-offline-space` exposes retained data read-only without credentials/network and requires the service's `--no-auto-sync` option. `--mount-offline-writable-space` explicitly permits bounded local edits and namespace changes against the retained identity; the mount does not check the remote state. It needs saved parent/directory evidence and available original content, not just a remembered pathname. Unavailable content, incomplete trees and unsafe replacements are refused. Offline mount access does not disable authenticated background sync for activated Spaces when automatic sync is enabled.

Repeated saves to the same file replace the queued local version while it is still unsent, without changing its original remote base. If an upload has started, a later save can be visible locally while waiting for confirmation of the earlier version. An uncertain upload may already have changed the server: Cirrus does not replay it just because sync is run again, and later saves do not bypass it.

Local write/flush/`fsync` success is not remote confirmation or a power-loss guarantee. Check `--sync-status` and `--journal` for pending, conflict or uncertain operations. Preserve and export retained versions before resolving a conflict or using `--acknowledge`; acknowledgement is not a merge or proof of the remote bytes and does not authorize replay. Export with `--export-staged`, `--export-retained` or `--export-pin-copy`, using selectors from the corresponding retained-data listings and a new absolute local destination outside FUSE, in a user-owned directory not writable by others. Missing or corrupt required bytes can fail export and leave partial output; a retained copy may be stale and does not establish the server outcome. No safe concurrent-server-editing mode is currently qualified.

Use `--storage-status` to inspect local usage and `--storage-limits` / `--set-storage-limits BUDGET_BYTES RESERVE_BYTES` for opt-in admission controls. These are not a hard global quota or a guarantee against disk exhaustion: database, temporary and retained-history growth are not completely bounded by them. Automatic reclamation removes only persisted clean cache, never staged edits, pins, recovery copies or charged orphan files. Retained data can keep growing; preserve exports and independent backups before explicitly removing it.

Before unpin, repin or rename transforms active pin ownership, required original ranges for affected retained edits and recovery versions are durably protected using verified local pin bytes. Capturing missing originals requires agreement among all eligible owners, including hashless copies. Offline protection needs no credentials or network. Missing, corrupt or conflicting required bytes, or insufficient storage, leave the pins and namespace intact; clean cache and retained-copy exports are not original protection.

Offline remote-directory replacement of an exact empty target transforms overlapping pins within bounded entry, byte and metadata limits. Independently pinned source roots follow the move; source ancestors retain their siblings, and destination ancestors gain the fully captured incoming subtree. Coverage may combine agreeing verified source fragments with complete saved directory proofs; descendant directories, including empty ones, need captured metadata. New local creations with no conflicting history move separately, without becoming pinned. Each affected original pin becomes a separate recovery copy, including displaced target pins. Missing content, conflicting captures and unresolved overlapping moves are refused. Pin captures exclude later dirty edits, and pending moves may report stale metadata. Use `--pins-space` and `--pin-copies` before explicitly removing a pin or copy.

## Stop, uninstall or upgrade

1. Close files and applications using the mounts, and change any terminal's working directory to a location outside the mounts.
2. Unmount each Space in the Cirrus UI or with `cirrus-daemon --unmount-space HTTPS_URL SPACE_ID`. Use the installed client that matches the running service, including when preparing to upgrade.
3. Run `cirrus-daemon --mounts` and verify that it succeeds and lists no mounts. Then stop the service with `systemctl --user stop cirrus-drive.service` (or `cirrus-daemon --stop` if you started it in a terminal).

Prefer Cirrus's own unmount command. If an idle mount was already removed with a strict `fusermount3 -u`, use `cirrus-daemon --recover-mount MOUNTPOINT` before remounting, or use `cirrus-daemon --stop` to retire it during normal shutdown. If recovery reports another mount at that path or ambiguous ownership, pause the uninstall or upgrade and inspect the mount. Do not remove the owner record or force-detach a mount to bypass the error.

Once the service has stopped, use `./packaging/uninstall.sh` to remove the user-installed artifacts. It retains local state and credentials. To upgrade, then install and start the new matching versions. See `cirrus-daemon --help` and `cirrus-ui --help` for additional commands.

Pre-release development state has no migration requirement or compatibility promise. Preserve anything needed before upgrading; do not assume a newer binary can open or safely downgrade that state. Live policy rollback does not migrate or revert data. There is no supported in-place resident state upgrade or rollback procedure. Installation, upgrade, crash recovery and hardware/power-loss durability are not yet production-qualified.

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md). Cirrus Drive is licensed under [Apache License 2.0](LICENSE); dependencies have their own licenses. See the [Rune and font notices](THIRD_PARTY_NOTICES.md).
