# Signed live scheduling and staged-read planner updates on Linux

A compatible policy release can change which eligible Space gets the next
automatic sync turn without restarting `cirrus-drive-service` or remounting.
The resident keeps the FUSE connection and handles, credentials, journal,
schedule admission, verification and DAV effects. The policy process has a
private inherited channel and receives only the size of a resident-selected
fair cohort. It has no account objects, tokens, file paths or write authority
in that protocol. The resident fences the old generation, drains its admitted
turn, and then makes the replacement active.

The same release can also replace the staged-read planner on existing mounts
and already-open file handles. This does not replace the entire filesystem
engine. If a release lists a different resident executable, `--release-status`
reports **resident update pending**.
New CLI invocations and reopened UI windows use the same selected release;
already open windows and the resident continue running their original code.

## Install and activate

Start with a trusted local build. The first transition from a legacy or
standard installation requires the normal stop, unmount and uninstall
procedure. For a user-managed installation, provision the raw 32-byte public
Ed25519 key obtained through a trusted channel:

```sh
./packaging/install.sh --trust-key /absolute/path/to/release.pub
systemctl --user daemon-reload
systemctl --user start cirrus-drive.service
python3 packaging/manage.py release /absolute/path/to/signed-release
cirrus-daemon --release-status
```

Before the first release is selected, installed launchers use the local
bootstrap clients and managed automatic transfers are paused. The release
command stages a set and asks the running resident to authenticate, negotiate
and activate it. It never restarts systemd. A successful reply identifies the
resident PID and executable digest, the selected and previous release IDs,
and the actual worker PID, generation and executable digest. If the command
loses its reply, inspect `--release-status` before retrying. A staged
directory alone is not evidence of activation.
While `draining_policy_turn` is true, the prior generation is still selected
and no new turn is admitted for it. If publication was visible but its
directory sync failed, status reports that the selected generation is live
with unknown durability; the command does not acknowledge durable success.

`cirrus-daemon --rollback-release` starts and negotiates the previous signed
policy and selects its matching CLI and UI. It never restores an older
database, discards pending bytes, or authorizes replay of an uncertain
mutation. If the running policy exits or sends an invalid response,
automatic transfers pause and status reports it; FUSE, resident status and
manual account operations remain resident. Use rollback or request the
already-staged release again with `--activate-release RELEASE_ID`.

To change the resident, plan normal maintenance. Stop the service and
unmount, uninstall with the installed management script, archive the
preserved `share/cirrus-drive/releases-v1` directory under the user prefix,
and install the new trusted build. Preserve the separate account state and
keyring. This path does not promise a state-schema downgrade or preservation of
existing open descriptors across maintenance. Package-manager installations
do not participate in this user-managed release path.

## Bundle contract

A bundle includes `cirrus-drive-service`, `cirrus-control-worker`,
`cirrus-daemon`, `cirrus-ui`, `manifest.json`, and `manifest.sig`. The signature
is the raw 64-byte Ed25519 signature of the exact JSON file bytes. The
manifest binds one complete set and has these fields:

```json
{
  "format": 1,
  "release": "example-1",
  "target_os": "linux",
  "target_arch": "x86_64",
  "public_protocol": 3,
  "worker_protocol": 1,
  "worker_role": "eligible-space-policy",
  "store_access": "none",
  "artifacts": {
    "resident": "<SHA-256 of cirrus-drive-service>",
    "worker": "<SHA-256 of cirrus-control-worker>",
    "cli": "<SHA-256 of cirrus-daemon>",
    "ui": "<SHA-256 of cirrus-ui>"
  }
}
```

Use unique release IDs and lowercase hexadecimal SHA-256 values. The first
release ABI accepts native little-endian x86-64 and AArch64 Linux ELF files. The
installed release store is reserved for Cirrus; the packaging script never
overwrites an existing release ID. A release publisher must use matching
non-lab binaries and provide the applicable notices. Only install a key
trusted to authorize native binaries running as your user. The protocol and
descriptor boundary are not a sandbox for malicious signer-approved code.
There is no bundled production signing key, downloader, automatic key
rotation, or package-manager replacement path.

If a damaged client set prevents the normal launcher from starting, use
`$PREFIX/libexec/cirrus-drive/cirrus-daemon --release-status` (the default
prefix is `~/.local`). This is the installed bootstrap client, also used by
the service's stop command. It does not depend on the selected release.

## Mounted staged-read planner ABI 1

The first transition to a resident with this ABI requires maintenance. It
accepts format-1 sets with the built-in exact-read planner, or format-2 sets
with an additional `artifacts.read_engine` SHA-256 field. For format 2,
include `cirrus-read-engine.json` (up to 1 KiB) in the signed set:

```json
{
  "role": "mounted-staged-read-plan",
  "abi": 1,
  "rules": ["cover", "stitch", "fetch_exact"]
}
```

On a staged read that misses its exact cache key, the ordered rules can
slice one cached range (`cover`), compose a gapless span from at most four
ranges (`stitch`), or use the ordinary exact demand read (`fetch_exact`,
required last). The program runs locally with no process round trip. It
cannot request additional bytes, open a file, change a handle, issue DAV, or
publish a reply. The resident supplies only exact-version cached ranges,
verifies the staged binding, checks coverage, and rechecks the current
handle and cache generation before replying.

Activation authenticates and negotiates the whole set before changing
selection. The resident publishes the new read program in a single atomic
generation change shared by existing and future mounts. A proposal from a
retired generation that was not yet admitted falls back to the resident's
exact demand path. Already-admitted reads can complete through the same
resident and still receive its final validation; no other reader or replier
takes ownership. Rollback republishes the previous verified program (or
built-in exact planner) as a new generation.

Use `cirrus-daemon --mount-engines` to see the program actually serving
live mounts and each mount's cumulative composed reads. This is independent
of whether the background scheduling worker has paused. Live changes are
limited to this read-plan ABI; clean reads, write/flush/fsync, directory
cursors, credentials, storage and remote effects stay resident. Changes to
FUSE transport, mount flags or INIT-negotiated features still require
maintenance. Neither the planner nor its rollback migrates account state.

## Linux automatic credential writer policy

A compatible managed resident can independently select a built-in credential
policy from an optional top-level `credential_policy` field in a signed
manifest. The only accepted values are `"standard-v1"` (one second per
method on an automatic writer connection) and `"slow-keyring-v1"` (two
seconds). This does not replace OAuth, Secret Service, or the credential
format. Foreground operations and shared read-only connections keep their
existing behavior.

```sh
python3 packaging/manage.py stage-release /absolute/path/to/signed-release
cirrus-daemon --activate-credential-policy example-1
cirrus-daemon --credential-policy
cirrus-daemon --rollback-credential-policy
```

The resident verifies the manifest using the installed release key and
checks the release target and protocol. It does not launch the bundle's
worker, change the scheduler or read-planner selection, or open account
State or the keyring to activate a profile. It refuses to switch while an
account operation is active, rotated credentials are awaiting persistence,
or the exclusive operation bus name cannot be acquired. Retry after normal
account work clears the blocker. Rollback restores the resident's built-in
`standard-v1`; it does not restore an old token. This selection lasts only
for the resident process and resets to `standard-v1` on restart. Inspect
`--credential-policy` if a change request loses its reply.

## Disposable native fixture

`scripts/check-nonread-lab.py --live-release` exercises the installed path
with two actual FUSE mounts, a private D-Bus/keyring and a local DAV fixture.
It needs matching normal CLI/service/UI/worker builds in
`CIRRUS_LAB_RELEASE_BIN_DIR`, fault-enabled CLI/service builds in
`CIRRUS_LAB_FAULT_BIN_DIR`, and a compatible test worker in
`CIRRUS_LAB_RELEASE_WORKER_B` that chooses the last eligible index rather than
the first. Optionally supply `CIRRUS_LAB_RELEASE_STALE_WORKER`, which negotiates
normally but returns the wrong generation after the handshake probe. Use a
private scratch `TMPDIR` on a filesystem that supports Cirrus's state and
socket operations, and a namespace or host that permits FUSE mounts. The
fixture creates its own disposable signing key; it does not use production
credentials or the default keyring.
Use `--live-release-engine` to also qualify covering/stitching on an already
open detached file, rejection of an incompatible signed program, a
generation change while a plan is staged, and durable program selection
across an explicit stop and restart.
