#ifndef CIRRUS_RETAINED_H
#define CIRRUS_RETAINED_H
#include <stddef.h>
#include <stdint.h>

/* Private in-process ABI v1; not an IPC/auth boundary or FileProvider API.
 * All handles are Rust-owned. Close exactly once on the creating OS thread.
 * Every account operation is synchronous and must stay on that OS thread.
 * Child handles retain their parents/root/binding, so parents may close first.
 * Never pass foreign, wrong-kind, stale or already closed pointers. A nonnull
 * pointer must reference its stated live allocation; null/length checks cannot
 * prove provenance. Inputs live through the call; outputs must not alias inputs.
 * Only request cancellation and dispatcher pause may run concurrently: keep the handle alive until
 * all operations/cancel calls have joined. It is one-shot; never reset.
 * No other concurrent use or close. On INTERNAL, discard the entire session
 * (close only); no panic unwinds across C. Allocation abort is process-fatal.
 * Strings are UTF-8 (no NUL/control bytes), <=16384 bytes; paths JSON string
 * arrays, <=128 safe components. Retained read APIs never authenticate or network.
 * Application/dispatcher/mutation APIs explicitly authenticate or execute work.
 */
typedef void *CirrusRetainedHandle;
typedef struct { const uint8_t *data; size_t len; } CirrusRetainedText;
enum {
    CIRRUS_OK=0, CIRRUS_INVALID_ABI=1, CIRRUS_CANCELLED=2,
    CIRRUS_UNAVAILABLE=3, CIRRUS_STALE=4, CIRRUS_CAPACITY=5, CIRRUS_INTERNAL=6,
    CIRRUS_PAGE_EXPIRED=7, CIRRUS_ANCHOR_EXPIRED=8, CIRRUS_SIGNIN_FINISHING=9,
    CIRRUS_RETAINED_SPACE_NOT_READY=10, CIRRUS_MUTATION_PENDING=11,
    CIRRUS_MUTATION_CONFLICT=12, CIRRUS_MUTATION_UNCERTAIN=13,
    CIRRUS_MUTATION_UNSUPPORTED=14, CIRRUS_CONFIRMED_DELETED=15
};
enum { CIRRUS_RETAINED_PAGE_BYTES=262144 };

/* Explicit filesystem App Group and separate Keychain access group identifiers.
 * Rust verifies both signed-process entitlement memberships via Security;
 * the fixed linked Swift adapter resolves the Foundation OS container URL.
 * No arbitrary path/HOME fallback. Strict physical Root admission may refuse
 * even a genuine entitled container (e.g. an ALLOW ACL). No Keychain I/O here.
 */
int32_t cirrus_retained_open(CirrusRetainedText app_group,
    CirrusRetainedText keychain_group, CirrusRetainedHandle *out);
int32_t cirrus_retained_request(CirrusRetainedHandle *out);
int32_t cirrus_retained_cancel(CirrusRetainedHandle request);
int32_t cirrus_retained_close(CirrusRetainedHandle handle);
int32_t cirrus_retained_bind(CirrusRetainedHandle core, CirrusRetainedText instance,
    CirrusRetainedText space, CirrusRetainedHandle *out);
int32_t cirrus_retained_list(CirrusRetainedHandle binding, CirrusRetainedText path_json,
    CirrusRetainedHandle request, CirrusRetainedHandle *out);
/* Copies <=32 metadata entries as JSON into the caller's EXACT 262144-byte
 * buffer, no borrowed engine memory. Empty JSON array means end. next is the
 * last cookie (unchanged at end); written=0 on failure. Release buffers in Swift.
 */
int32_t cirrus_retained_page(CirrusRetainedHandle listing, uint64_t after,
    CirrusRetainedHandle request, uint8_t *buffer, size_t capacity,
    size_t *written, uint64_t *next);
/* Opens the exact listed id/etag/size, not whichever version now occupies a path.
 * STALE only for a concrete version mismatch; ambiguous engine errors are
 * UNAVAILABLE, never guessed noSuchItem. Existing engine capacity predicates
 * and actual output errno may yield CAPACITY; other engine errors stay opaque.
 */
int32_t cirrus_retained_version(CirrusRetainedHandle binding,
    CirrusRetainedText path_json, CirrusRetainedText id, CirrusRetainedText etag,
    uint64_t size, CirrusRetainedHandle request, CirrusRetainedHandle *out);
/* fd is caller-owned EXCL-created empty 0600 regular file, nlink1, current UID.
 * The existing strict DENY-only Darwin ACL policy also applies before bytes.
 * Caller exclusively owns it through return, and owns all failure cleanup.
 * Never pass an engine/storage descriptor. This call does not close/unlink/
 * publish it. Bounded <=128KiB ranges, pwrite short-write/EINTR handling,
 * fsync, then exact version/request revalidation. No zero-range empty-file read.
 * Revalidate again immediately before the caller's no-replace publication.
 */
int32_t cirrus_retained_materialize(CirrusRetainedHandle version, int32_t fd,
    CirrusRetainedHandle request);
int32_t cirrus_retained_verify(CirrusRetainedHandle version, CirrusRetainedHandle request);
/* Exact staged Version observation, no network/credentials. Copied JSON
 * {operation,result}, PAGE_BYTES. Pending/conflict/uncertain/resolved are not
 * remote success. Confirmed writes require matching verified_uploads evidence.
 * Unknown/changed identities return UNAVAILABLE, never guessed missing data.
 */
int32_t cirrus_retained_operation(CirrusRetainedHandle staged_version,
    CirrusRetainedHandle request, uint8_t *buffer, size_t capacity, size_t *written);
/* Durable catalog, same handle/thread/pointer contracts as above. Domain is
 * explicit configuration bound immutably to the retained principal and Space.
 * read operations: 0 capture(container, "name"|"date") -> JSON token string;
 * 1 page(container, token) -> JSON page; 2 lookup(FPID, "") -> JSON item;
 * 3 changes("", anchor or "") -> JSON changes. All are retained observations,
 * NEVER authoritative remote freshness, absence, deletion or sync completion.
 * Exactly PAGE_BYTES output; written=0 on error. Tokens are <500 UTF-8 bytes.
 */
int32_t cirrus_catalog_open(CirrusRetainedHandle binding, CirrusRetainedText domain,
    CirrusRetainedHandle *out);
/* Noncreating resume by actual OS domain ID. Saved identity and epoch must still
 * match the retained account/activation/root. Unknown/foreign IDs UNAVAILABLE.
 * No credentials, configuration tuple, display-name inference or ID allocation.
 */
int32_t cirrus_catalog_resume(CirrusRetainedHandle core, CirrusRetainedText domain,
    CirrusRetainedHandle *out);
int32_t cirrus_catalog_read(CirrusRetainedHandle catalog, uint32_t operation,
    CirrusRetainedText identifier, CirrusRetainedText argument,
    CirrusRetainedHandle request, uint8_t *buffer, size_t capacity, size_t *written);
int32_t cirrus_catalog_open_version(CirrusRetainedHandle catalog, CirrusRetainedText id,
    CirrusRetainedText etag, uint64_t size, CirrusRetainedHandle request,
    CirrusRetainedHandle *out);
/* Online noninteractive engine mutations of this catalog's immutable tuple.
 * descriptor is Request JSON; source is the OS contents URL's absolute path or
 * empty. Rust streams/hash-validates it, never receives whole-file Data.
 * NSFileProviderRequest has no persistent mutation identifier in SDK26.5:
 * exact normalized input+content digest/base/parent/name/options identifies a
 * durable postcondition request. Identical retries resume all stored child IDs.
 * Success follows exact executor confirmation AND committed catalog publication.
 * Pending/conflict/uncertain are failures, not local-stage success. Cancellation
 * requests safe executor yielding; admitted mutations/bytes survive cancellation.
 * Exactly PAGE_BYTES output JSON Reply, written=0 on error.
 */
typedef void (*CirrusMutationProgress)(void *context, uint64_t completed, uint64_t total);
int32_t cirrus_catalog_mutate(CirrusRetainedHandle catalog, CirrusRetainedText descriptor,
    CirrusRetainedText source, CirrusRetainedHandle request, CirrusMutationProgress progress, void *context, uint8_t *buffer,
    size_t capacity, size_t *written);
/* Application-only authenticated demand reads. The same strict Core admission
 * applies. One engine owner per root/principal; no scheduler or selected-Space
 * mutation. Bind uses fresh authenticated membership and retains the exact Core.
 * SignIn is request-local and distinct from retained cancellation. Only cancel
 * may cross threads, with external lifetime exclusion against close. FINISHING
 * means cancellation did NOT win; wait for connect's real terminal result.
 * Browser callback/context are borrowed synchronously through connect; URL is
 * ephemeral UTF-8 <=16384 bytes. Do not log/persist it or retain the span. The
 * callback returns OK only after the OS accepts opening it; failures propagate.
 * Invoke connect off-main-thread; never block the main thread waiting for it.
 * Generic engine/auth failures are UNAVAILABLE, never a guessed missing item.
 */
typedef int32_t (*CirrusApplicationBrowser)(void *context, CirrusRetainedText url);
int32_t cirrus_application_attempt(CirrusRetainedHandle *out);
int32_t cirrus_application_cancel(CirrusRetainedHandle attempt);
int32_t cirrus_application_connect(CirrusRetainedHandle core, CirrusRetainedText instance,
    CirrusRetainedHandle attempt, CirrusApplicationBrowser browser, void *context);
int32_t cirrus_application_spaces(CirrusRetainedHandle core, CirrusRetainedText instance,
    CirrusRetainedHandle *out);
/* Snapshot <=4096 Spaces; pages <=32, exact PAGE_BYTES output buffer. Empty
 * array means end, next is the next offset; written=0 on failure. Metadata only.
 */
int32_t cirrus_application_space_page(CirrusRetainedHandle spaces, size_t offset,
    uint8_t *buffer, size_t capacity, size_t *written, size_t *next);
int32_t cirrus_application_bind(CirrusRetainedHandle core, CirrusRetainedText instance,
    CirrusRetainedText space, CirrusRetainedHandle *out);
/* Current binding identity, NOT a fresh authentication check. Metadata JSON
 * {instance,space,issuer,subject}, no tokens. Exact PAGE_BYTES, written=0 on
 * failure. Treat principal metadata as private; do not log/persist it.
 */
int32_t cirrus_application_binding(CirrusRetainedHandle binding, uint8_t *buffer,
    size_t capacity, size_t *written);
/* Mount intent (automatically enables sync/Finder), ONLINE Bound only. Uses
 * normal guarded activation and authenticated root observation for fresh Spaces,
 * then atomically reuses/allocates the durable domain
 * for its exact canonical instance/issuer/subject/Space. Copied JSON {domain},
 * exact PAGE_BYTES, written=0 on failure. Commit precedes any caller OS API.
 * Activation may persist if a later step fails; do not claim rollback. Missing
 * activation/root at final validation => NOT_READY. No registration, staging
 * mutation or scheduler execution here. Never call for mere browsing/discovery.
 * Failure/retry never deletes or rebinds an existing domain or retained bytes.
 */
int32_t cirrus_application_domain_prepare(CirrusRetainedHandle authenticated_bound,
    uint8_t *buffer, size_t capacity, size_t *written);
/* Restore only persisted mount activations (<=64), not all accessible Spaces.
 * Existing domains resume locally without credentials/network. Pending
 * activations freshly validate membership/root before allocating domains;
 * preserves existing attention/backoff. Copied {domains:[{domain}],unavailable:count},
 * exact PAGE_BYTES, written=0 on failure. Each failed intent stays persisted.
 * Source may authenticate/network. No OS API or automatic sync dispatch here.
 */
int32_t cirrus_application_domains_restore(CirrusRetainedHandle core,
    uint8_t *buffer, size_t capacity, size_t *written);
int32_t cirrus_application_list(CirrusRetainedHandle binding, CirrusRetainedText path_json,
    CirrusRetainedText parent_id, CirrusRetainedHandle *out);
/* Automatic execution, NOT a UI action. Open accepts Core or Catalog and elects
 * one cooperating dispatcher under that admitted root. Another process's election
 * returns UNAVAILABLE; retry at a bounded lifecycle/poll interval. The handle
 * retains the root/election until owner-thread close.
 * turn executes at most one fair activated-Space engine turn, respecting existing
 * backoff, attention and background admission. It uses noninteractive credentials,
 * never a browser. Exact PAGE_BYTES output JSON {instance?,space?,progressed,status?}.
 * Status/idle/progress are scheduling observations, NOT operation completion.
 * ONLY pause (0/1) may cross threads while close is externally excluded. It
 * requests safe yielding, not atomic cancellation of an admitted remote write.
 * Clear pause on the owner only when its foreground mailbox is empty.
 */
int32_t cirrus_dispatcher_open(CirrusRetainedHandle core_or_catalog, CirrusRetainedHandle *out);
int32_t cirrus_dispatcher_pause(CirrusRetainedHandle dispatcher, int32_t paused);
int32_t cirrus_dispatcher_turn(CirrusRetainedHandle dispatcher, uint8_t *buffer,
    size_t capacity, size_t *written);
#endif
