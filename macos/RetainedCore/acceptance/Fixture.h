#include "../include/CirrusRetained.h"
/* Test artifact only, absent from production header/staticlib. */
int32_t cirrus_retained_fixture(CirrusRetainedText path, CirrusRetainedHandle *out);
int32_t cirrus_retained_fixture_bind(CirrusRetainedHandle core, CirrusRetainedText instance,
    CirrusRetainedText space, CirrusRetainedHandle *out);
/* Path JSON: <=128 safe components. The owner thread and request contracts are
 * the same as the production ABI. Pages have <=32 entries; [] means end.
 */
int32_t cirrus_retained_fixture_list(CirrusRetainedHandle binding, CirrusRetainedText path_json,
    CirrusRetainedHandle request, CirrusRetainedHandle *out);
int32_t cirrus_retained_fixture_page(CirrusRetainedHandle listing, uint64_t after,
    CirrusRetainedHandle request, uint8_t *buffer, size_t capacity,
    size_t *written, uint64_t *next);
/* Opens the exact listed id/etag/size; STALE only for a concrete mismatch. */
int32_t cirrus_retained_fixture_version(CirrusRetainedHandle binding,
    CirrusRetainedText path_json, CirrusRetainedText id, CirrusRetainedText etag,
    uint64_t size, CirrusRetainedHandle request, CirrusRetainedHandle *out);
/* Exact staged version observation as JSON {operation,result}, PAGE_BYTES. */
int32_t cirrus_retained_fixture_operation(CirrusRetainedHandle staged_version,
    CirrusRetainedHandle request, uint8_t *buffer, size_t capacity, size_t *written);
