/* CC0 license applied, see LICENSE */

#ifndef LIBPROV_TESTS_MOCK_CORE_H
#define LIBPROV_TESTS_MOCK_CORE_H

/*
 * A hand-built OpenSSL core for the libprov error tests: a test-local
 * OSSL_CORE_HANDLE, recording stubs, a call-sequence recorder, a reset
 * helper and ready-made OSSL_DISPATCH tables.  Nothing here asserts; it
 * makes values observable so a consumer can assert them.  Checks must be
 * behavioural, because struct proverr_functions_st is defined only inside
 * err.c (err.c:7-12) and include/prov/err.h:58 only forward-declares it --
 * hence two distinguishable new_error stubs, and hence the recorder that
 * exposes the ERR_raise_data() evaluation order (include/prov/err.h:49-52).
 * Reset at the START of every case, exercise, then read mock_core_obs, never
 * in the expression that triggers it: C leaves argument evaluation order
 * unspecified.  A recorded string may live ANYWHERE, mock_core_obs
 * included, so mock_core_capture() copies with memmove() and is defined
 * for overlapping as well as disjoint arguments; its comment says why.
 * No libcrypto is linked -- the accessors err.c calls expand to static
 * inline definitions, and <openssl/params.h>, whose OSSL_PARAM_*
 * families are libcrypto functions, is deliberately absent.  Every object
 * has internal linkage, so each test executable owns its own state, and
 * because this header defines objects it is guarded.
 */

#include <stdarg.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "prov/err.h"

/*
 * Included directly rather than relied on transitively through "prov/err.h",
 * which also supplies OSSL_DISPATCH, the incomplete OSSL_CORE_HANDLE, the
 * OSSL_FUNC_CORE_ ids and the OSSL_FUNC_core_*_fn typedefs used below.
 */

/*
 * Not every consumer uses every stub and table, and an unused static
 * function defined in a header draws -Wunused-function under -Wall -Wextra.
 * Spelled out here rather than borrowing OpenSSL's internal ossl_unused.
 */
#if defined(__GNUC__) || defined(__clang__)
# define MOCK_CORE_MAYBE_UNUSED __attribute__((unused))
#else
# define MOCK_CORE_MAYBE_UNUSED
#endif

/*
 * Call-sequence ordinals; each stub appends one to mock_core_obs.seq, which
 * is how the ERR_raise_data() evaluation order becomes visible.  The
 * alternate new_error stub has an ordinal of its own rather than sharing 1,
 * so a table that resolved to it shows a wrong ordinal instead of passing
 * unnoticed.  All three tables that bind it expect zero calls, so it must
 * never appear in a passing test.
 */
#define MOCK_CORE_ORD_NEW_ERROR       1
#define MOCK_CORE_ORD_SET_ERROR_DEBUG 2
#define MOCK_CORE_ORD_VSET_ERROR      3
#define MOCK_CORE_ORD_ALT_NEW_ERROR   4

/*
 * Room for ten raises in one case; an overrun is counted in
 * mock_core_obs.seq_dropped rather than written out of bounds.
 */
#define MOCK_CORE_SEQ_MAX 32

/*
 * Capacity of each recorded string copy, NUL included.  A longer string is
 * truncated, never overrun, and the untruncated pointer is recorded beside
 * every copy.
 */
#define MOCK_CORE_TEXT_MAX 256

/*
 * A function id for the unknown-id table.  <openssl/core_dispatch.h> reserves
 * 1-1023 for core-to-provider functions, so 9999 is outside that range.
 */
#define MOCK_CORE_ID_UNASSIGNED 9999

/*
 * Vararg-consumption modes for the vset_error stub.  MOCK_CORE_VA_NONE is
 * zero on purpose, so mock_core_reset() restores the safe default.
 * MOCK_CORE_VA_INT_THEN_STR names the types EXACTLY and binds the caller:
 * the two arguments after the format string must be an int and a char *.  A
 * string literal qualifies, char[N] decaying to char * and not to
 * const char *; passing a pointer whose variadic type is const char * would
 * make the stub's va_arg() request an incompatible type, which C99 7.15.1.1
 * leaves undefined.
 */
#define MOCK_CORE_VA_NONE         0
#define MOCK_CORE_VA_INT_THEN_STR 1

/*
 * OSSL_CORE_HANDLE names a struct <openssl/core.h> never defines, so this is
 * a definition rather than a redefinition, and it is what lets a test own a
 * core handle with no running provider.  err.c only passes the pointer
 * through and never reads the tag, but the tag gives the two instances below
 * distinct contents as well as distinct addresses, so a failure dump is
 * readable; what tests assert is pointer IDENTITY, the right claim for a
 * pass-through.
 */
struct ossl_core_handle_st {
  int tag;
};

#define MOCK_CORE_TAG_PRIMARY   0x11
#define MOCK_CORE_TAG_ALTERNATE 0x22

/*
 * The handle a test normally passes to proverr_new_handle().  Both instances
 * are const, which is what lets mock_core_reset() promise that NOTHING in
 * this file keeps state across a reset: the helper clears mock_core_obs,
 * which is then every mutable object here, and a case that assigned to a tag
 * would otherwise leak that write into every later case in the same
 * executable with no reset able to undo it.  Nothing is given up, because the
 * whole public surface takes the handle as a "const OSSL_CORE_HANDLE *"
 * (include/prov/err.h:60) and err.c only stores the pointer (err.c:57) and
 * forwards it (err.c:87, err.c:93, err.c:102), so no cast is needed anywhere.
 */
MOCK_CORE_MAYBE_UNUSED
static const OSSL_CORE_HANDLE mock_core_primary = { MOCK_CORE_TAG_PRIMARY };

/*
 * A second, distinct core handle, so that "the handle stored the core it was
 * given" is falsifiable rather than vacuous, and so that a duplicated handle
 * has something to be compared against when proving that
 * proverr_dup_handle() copied the core across.
 */
MOCK_CORE_MAYBE_UNUSED
static const OSSL_CORE_HANDLE mock_core_alternate =
  { MOCK_CORE_TAG_ALTERNATE };

/*
 * Everything the stubs record, as one aggregate rather than scattered
 * objects, so that "the reset helper clears every field" is verifiable at a
 * glance.  Grouped by the stub that writes them; all outputs except va_mode.
 */
struct mock_core_observations {
  unsigned long new_error_calls;
  const OSSL_CORE_HANDLE *new_error_core;

  /*
   * A correct run never touches these: the unknown-id, duplicate-id and
   * after-sentinel tables are built to assert they stay zero and NULL.
   */
  unsigned long alt_new_error_calls;
  const OSSL_CORE_HANDLE *alt_new_error_core;

  /*
   * err.c:93 forwards here.  The pointer settles pass-through for a caller
   * that supplies and retains the exact pointer; the copy settles content at
   * the moment of the call, and content is the only sound check for the
   * strings ERR_raise_data() takes from OPENSSL_FILE and OPENSSL_FUNC, since
   * C does not require equal string literals to share an address.  line is
   * stored verbatim, so INT_MIN and INT_MAX travel through unchanged.
   */
  unsigned long set_error_debug_calls;
  const OSSL_CORE_HANDLE *set_error_debug_core;
  const char *file_ptr;
  char file_text[MOCK_CORE_TEXT_MAX];
  int line;
  const char *func_ptr;
  char func_text[MOCK_CORE_TEXT_MAX];

  /*
   * err.c:102 forwards here.  reason is stored verbatim, so 0 and UINT32_MAX
   * travel through unchanged.  fmt is recorded as a POINTER because its
   * identity is the contract: ERR_raise() supplies NULL for it
   * (include/prov/err.h:47) where ERR_raise_data() supplies the caller's own
   * string.  fmt_text stays empty when fmt is NULL.
   */
  unsigned long vset_error_calls;
  const OSSL_CORE_HANDLE *vset_error_core;
  uint32_t reason;
  const char *fmt_ptr;
  char fmt_text[MOCK_CORE_TEXT_MAX];

  /*
   * va_mode is the ONE input field, set after mock_core_reset() and before
   * the call; va_consumed says whether the stub really traversed the list,
   * so recovery can be proved rather than assumed.  va_str_ptr is
   * const char * because nothing here writes through it: the stub retrieves
   * the argument as the char * the mode requires and adds the qualifier on
   * the way in, so pointer identity against the caller's string still holds.
   */
  int va_mode;
  int va_consumed;
  int va_int;
  const char *va_str_ptr;
  char va_str_text[MOCK_CORE_TEXT_MAX];

  /*
   * Which stub ran, in which order.  seq_dropped is expected to be zero; a
   * non-zero value means the case overflowed the recorder and its order
   * assertion is incomplete, which is worth knowing rather than hiding.
   */
  int seq[MOCK_CORE_SEQ_MAX];
  size_t seq_len;
  unsigned long seq_dropped;
};

/* Internal linkage: each test executable gets its own observation state. */
MOCK_CORE_MAYBE_UNUSED
static struct mock_core_observations mock_core_obs;

/*
 * Recovery is opt-in because a va_list may be traversed once, and only by
 * someone who knows the shape of what was passed.  The stub cannot work that
 * out: its format string may legitimately be NULL (include/prov/err.h:47)
 * and is not something a stub should parse, so traversing unconditionally
 * would be undefined behaviour on the common case.  A test that raised
 * ERR_raise_data(handle, 7u, "%d %s", 42, "detail") asks for those arguments
 * back by setting va_mode to MOCK_CORE_VA_INT_THEN_STR after the reset.
 * Select a mode ONLY when the varargs really have that shape; a mismatch is
 * undefined behaviour, as in any other va_arg() consumer.
 */

/*
 * Copy a string into fixed storage, truncating rather than overrunning and
 * always NUL-terminating.  A NULL source yields an empty string; the caller
 * records the pointer separately, so emptiness is never confused with NULL.
 * A counted copy with an explicit terminator, not strncpy(), which would
 * leave an exact-length source unterminated.  And memmove() for that copy,
 * not memcpy(): `text` is whatever the code under test forwarded and
 * `buffer` is a field of mock_core_obs, so a stub aimed at the buffer it is
 * about to fill, or a test re-raising with a string it read back out of
 * mock_core_obs, makes the two ranges overlap -- undefined for memcpy()
 * (C99 7.21.2.1), defined for memmove().  Detecting the overlap instead
 * would need a relational comparison between pointers into different
 * objects, which C99 6.5.8p5 leaves undefined, so it is tolerated rather
 * than screened for.  The rest of the order is already overlap-proof and
 * must stay so: strlen() finishes reading before the copy starts, and the
 * terminator lands one past the bytes just written.
 */
MOCK_CORE_MAYBE_UNUSED
static void mock_core_capture(char *buffer, size_t capacity, const char *text)
{
  size_t length;

  if (buffer == NULL || capacity == 0)
    return;

  if (text == NULL) {
    buffer[0] = '\0';
    return;
  }

  length = strlen(text);
  if (length > capacity - 1)
    length = capacity - 1;
  memmove(buffer, text, length);
  buffer[length] = '\0';
}

/*
 * Append one ordinal, or count the overflow.  Bounded by construction:
 * seq_len is incremented only inside the guarded branch, so it cannot reach
 * MOCK_CORE_SEQ_MAX and index out of range.
 */
MOCK_CORE_MAYBE_UNUSED
static void mock_core_record(int ordinal)
{
  if (mock_core_obs.seq_len < (size_t)MOCK_CORE_SEQ_MAX)
    mock_core_obs.seq[mock_core_obs.seq_len++] = ordinal;
  else
    mock_core_obs.seq_dropped++;
}


/*
 * Return the observation state to its initial condition, at the START of
 * every case so that a case returning early cannot leak observations into
 * the next.  Neither step is redundant: the memset() clears the whole
 * object, including any field a later edit adds to the struct but forgets to
 * add here, while the explicit assignments set pointers to NULL and scalars
 * to their documented defaults without assuming how a null pointer is
 * represented.  va_mode returns to MOCK_CORE_VA_NONE.  One call therefore
 * restores EVERY mutable object in this header, because mock_core_obs is the
 * only one there is: the two core handles and the nine dispatch tables are
 * const, so the case independence claimed above is structural rather than a
 * convention a reader has to trust.
 */
MOCK_CORE_MAYBE_UNUSED
static void mock_core_reset(void)
{
  size_t index;

  memset(&mock_core_obs, 0, sizeof(mock_core_obs));

  mock_core_obs.new_error_calls = 0UL;
  mock_core_obs.new_error_core = NULL;

  mock_core_obs.alt_new_error_calls = 0UL;
  mock_core_obs.alt_new_error_core = NULL;

  mock_core_obs.set_error_debug_calls = 0UL;
  mock_core_obs.set_error_debug_core = NULL;
  mock_core_obs.file_ptr = NULL;
  mock_core_obs.file_text[0] = '\0';
  mock_core_obs.line = 0;
  mock_core_obs.func_ptr = NULL;
  mock_core_obs.func_text[0] = '\0';

  mock_core_obs.vset_error_calls = 0UL;
  mock_core_obs.vset_error_core = NULL;
  mock_core_obs.reason = 0u;
  mock_core_obs.fmt_ptr = NULL;
  mock_core_obs.fmt_text[0] = '\0';

  mock_core_obs.va_mode = MOCK_CORE_VA_NONE;
  mock_core_obs.va_consumed = 0;
  mock_core_obs.va_int = 0;
  mock_core_obs.va_str_ptr = NULL;
  mock_core_obs.va_str_text[0] = '\0';

  for (index = 0; index < (size_t)MOCK_CORE_SEQ_MAX; index++)
    mock_core_obs.seq[index] = 0;
  mock_core_obs.seq_len = 0;
  mock_core_obs.seq_dropped = 0UL;
}

/*
 * The stub callbacks.  Each signature matches its OSSL_CORE_MAKE_FUNC
 * declaration exactly, which is not cosmetic: the tables store these as
 * "void (*)(void)", err.c casts back through the OSSL_FUNC_core_* accessors
 * before calling, and calling through a pointer to an incompatible type is
 * undefined behaviour.  None of them asserts, formats or fails.
 */

/*
 * OSSL_FUNC_CORE_NEW_ERROR (id 5), primary: the stub every correctly-resolved
 * table ends up bound to.
 */
MOCK_CORE_MAYBE_UNUSED
static void mock_core_new_error(const OSSL_CORE_HANDLE *prov)
{
  mock_core_obs.new_error_calls++;
  mock_core_obs.new_error_core = prov;
  mock_core_record(MOCK_CORE_ORD_NEW_ERROR);
}

/*
 * OSSL_FUNC_CORE_NEW_ERROR (id 5), alternate: interchangeable with the
 * primary as far as err.c is concerned and distinguishable as far as a test
 * is concerned, which is what makes callback resolution observable at all.
 * It appears in three tables and a passing test never sees it run; each of
 * those tables records why zero calls is the proof it needs.
 */
MOCK_CORE_MAYBE_UNUSED
static void mock_core_alt_new_error(const OSSL_CORE_HANDLE *prov)
{
  mock_core_obs.alt_new_error_calls++;
  mock_core_obs.alt_new_error_core = prov;
  mock_core_record(MOCK_CORE_ORD_ALT_NEW_ERROR);
}

/*
 * OSSL_FUNC_CORE_SET_ERROR_DEBUG (id 6).  The line number is where the
 * call-site capture becomes checkable: include/prov/err.h:51 passes
 * OPENSSL_LINE, which expands at the macro's call site, so a test records
 * __LINE__ on the same physical line as its ERR_raise() and compares -- on a
 * following line the expectation would be off by one.  The captured file and
 * function are checked by string content, since equal literals need not
 * share an address.
 */
MOCK_CORE_MAYBE_UNUSED
static void mock_core_set_error_debug(const OSSL_CORE_HANDLE *prov,
                                      const char *file, int line,
                                      const char *func)
{
  mock_core_obs.set_error_debug_calls++;
  mock_core_obs.set_error_debug_core = prov;
  mock_core_obs.file_ptr = file;
  mock_core_capture(mock_core_obs.file_text, sizeof(mock_core_obs.file_text),
                    file);
  mock_core_obs.line = line;
  mock_core_obs.func_ptr = func;
  mock_core_capture(mock_core_obs.func_text, sizeof(mock_core_obs.func_text),
                    func);
  mock_core_record(MOCK_CORE_ORD_SET_ERROR_DEBUG);
}

/*
 * OSSL_FUNC_CORE_VSET_ERROR (id 7).  The va_list is traversed here and
 * nowhere else, at most once per call, and only in the selected mode;
 * err.c:101-103 wraps this call in va_start()/va_end(), so the stub must not
 * va_end() what it did not va_start().  The retrieval TYPES matter as much as
 * the order: the string is requested as the char * that
 * MOCK_CORE_VA_INT_THEN_STR documents, then stored in the const char *
 * observation field, because differently qualified pointer types are not
 * compatible and va_arg() must be given the type actually passed.
 */
MOCK_CORE_MAYBE_UNUSED
static void mock_core_vset_error(const OSSL_CORE_HANDLE *prov, uint32_t reason,
                                 const char *fmt, va_list args)
{
  mock_core_obs.vset_error_calls++;
  mock_core_obs.vset_error_core = prov;
  mock_core_obs.reason = reason;
  mock_core_obs.fmt_ptr = fmt;
  mock_core_capture(mock_core_obs.fmt_text, sizeof(mock_core_obs.fmt_text),
                    fmt);

  if (mock_core_obs.va_mode == MOCK_CORE_VA_INT_THEN_STR) {
    char *va_str;

    mock_core_obs.va_int = va_arg(args, int);
    va_str = va_arg(args, char *);
    mock_core_obs.va_str_ptr = va_str;
    mock_core_capture(mock_core_obs.va_str_text,
                      sizeof(mock_core_obs.va_str_text), va_str);
    mock_core_obs.va_consumed = 1;
  }

  mock_core_record(MOCK_CORE_ORD_VSET_ERROR);
}

/*
 * A compile-time guard, never meant to be called: assigning each stub to a
 * pointer of the matching OSSL_FUNC_core_*_fn type -- the typedefs
 * OSSL_CORE_MAKE_FUNC emits and err.c stores -- makes the compiler check
 * every parameter and return type, so drift stops compiling here instead of
 * leaving err.c to call through a mismatched pointer.
 */
MOCK_CORE_MAYBE_UNUSED
static void mock_core_signature_check(void)
{
  OSSL_FUNC_core_new_error_fn *as_new_error = mock_core_new_error;
  OSSL_FUNC_core_new_error_fn *as_alt_new_error = mock_core_alt_new_error;
  OSSL_FUNC_core_set_error_debug_fn *as_set_error_debug =
    mock_core_set_error_debug;
  OSSL_FUNC_core_vset_error_fn *as_vset_error = mock_core_vset_error;

  (void)as_new_error;
  (void)as_alt_new_error;
  (void)as_set_error_debug;
  (void)as_vset_error;
}


/*
 * The dispatch tables: each is a table the OpenSSL core could plausibly hand
 * a provider, shaped to make one property of err.c's resolution loop
 * observable.  Those properties are all silent -- no return value, no
 * diagnostic, nothing a compiler would catch: err.c:34 stops the scan at the
 * first entry whose function_id is 0; the switch at err.c:35-45 has no
 * default label, so an unrecognised id is skipped rather than rejected; and
 * err.c:36-44 lets a later entry overwrite an earlier one, so the LAST
 * occurrence survives.  Every table ends with a literal { 0, NULL },
 * mirroring that id-0 sentinel.  The (void (*)(void)) casts are what an
 * OSSL_DISPATCH entry requires, and are safe because err.c casts back
 * through the accessors before calling.
 */

/*
 * Complete and in ascending id order: the happy path.  All three callbacks
 * resolve, so a raise yields the full sequence and no assertion in
 * err.c:47-49 can fire.
 */
MOCK_CORE_MAYBE_UNUSED
static const OSSL_DISPATCH mock_dispatch_complete[] = {
  { OSSL_FUNC_CORE_NEW_ERROR, (void (*)(void))mock_core_new_error },
  { OSSL_FUNC_CORE_SET_ERROR_DEBUG,
    (void (*)(void))mock_core_set_error_debug },
  { OSSL_FUNC_CORE_VSET_ERROR, (void (*)(void))mock_core_vset_error },
  { 0, NULL }
};

/*
 * The same three entries in a different order (7, 5, 6).  Nothing promises a
 * provider an ordered table, so behaviour must be identical to the complete
 * table -- this fixture keeps that true.
 */
MOCK_CORE_MAYBE_UNUSED
static const OSSL_DISPATCH mock_dispatch_shuffled[] = {
  { OSSL_FUNC_CORE_VSET_ERROR, (void (*)(void))mock_core_vset_error },
  { OSSL_FUNC_CORE_NEW_ERROR, (void (*)(void))mock_core_new_error },
  { OSSL_FUNC_CORE_SET_ERROR_DEBUG,
    (void (*)(void))mock_core_set_error_debug },
  { 0, NULL }
};

/*
 * Unknown ids interleaved with the three that matter: 8 and 9 are real
 * adjacent core functions, which is what a real core's table would contain,
 * and 9999 is outside the reserved range.  All three are bound to the
 * alternate stub, so tolerance is not merely inferred from a non-NULL handle
 * -- after a raise alt_new_error_calls must still be zero.
 */
MOCK_CORE_MAYBE_UNUSED
static const OSSL_DISPATCH mock_dispatch_unknown_ids[] = {
  { OSSL_FUNC_CORE_SET_ERROR_MARK, (void (*)(void))mock_core_alt_new_error },
  { OSSL_FUNC_CORE_NEW_ERROR, (void (*)(void))mock_core_new_error },
  { OSSL_FUNC_CORE_CLEAR_LAST_ERROR_MARK,
    (void (*)(void))mock_core_alt_new_error },
  { OSSL_FUNC_CORE_SET_ERROR_DEBUG,
    (void (*)(void))mock_core_set_error_debug },
  { MOCK_CORE_ID_UNASSIGNED, (void (*)(void))mock_core_alt_new_error },
  { OSSL_FUNC_CORE_VSET_ERROR, (void (*)(void))mock_core_vset_error },
  { 0, NULL }
};

/*
 * Two entries for OSSL_FUNC_CORE_NEW_ERROR, the alternate first and the
 * primary last, so err.c:37 must leave the PRIMARY stub stored and a raise
 * must fire it.  Nothing but calling it could reveal which of two equally
 * valid callbacks was kept.
 */
MOCK_CORE_MAYBE_UNUSED
static const OSSL_DISPATCH mock_dispatch_duplicate_ids[] = {
  { OSSL_FUNC_CORE_NEW_ERROR, (void (*)(void))mock_core_alt_new_error },
  { OSSL_FUNC_CORE_SET_ERROR_DEBUG,
    (void (*)(void))mock_core_set_error_debug },
  { OSSL_FUNC_CORE_VSET_ERROR, (void (*)(void))mock_core_vset_error },
  { OSSL_FUNC_CORE_NEW_ERROR, (void (*)(void))mock_core_new_error },
  { 0, NULL }
};

/*
 * A complete table, its terminator, and a fourth entry that must never be
 * read.  Binding that entry to the alternate stub makes "unreachable"
 * assertable: a loop walking one entry past err.c:34's sentinel test would
 * resolve new_error to it.
 */
MOCK_CORE_MAYBE_UNUSED
static const OSSL_DISPATCH mock_dispatch_after_sentinel[] = {
  { OSSL_FUNC_CORE_NEW_ERROR, (void (*)(void))mock_core_new_error },
  { OSSL_FUNC_CORE_SET_ERROR_DEBUG,
    (void (*)(void))mock_core_set_error_debug },
  { OSSL_FUNC_CORE_VSET_ERROR, (void (*)(void))mock_core_vset_error },
  { 0, NULL },
  { OSSL_FUNC_CORE_NEW_ERROR, (void (*)(void))mock_core_alt_new_error }
};

/*
 * The four tables that leave a callback unresolved are the only fixtures
 * whose outcome depends on how the library was compiled: in a default build
 * the assertions at err.c:47-49 are live and proverr_new_handle() aborts,
 * while with NDEBUG defined they vanish, the guard at err.c:51-54 becomes
 * reachable and it returns NULL instead.  NDEBUG has to reach the
 * translation unit holding the assert(), which is err.c; defining it only
 * where these tables are used leaves an already-compiled err.c fully live.
 * None of the four is a null dispatch pointer: the empty table is a valid,
 * correctly-terminated OSSL_DISPATCH that merely resolves nothing, reaching
 * err.c:47-49, whereas a null pointer is stopped earlier at err.c:27.
 */

/*
 * Empty but well-formed: err.c:34 exits immediately, leaving all three
 * callbacks NULL.
 */
MOCK_CORE_MAYBE_UNUSED
static const OSSL_DISPATCH mock_dispatch_empty[] = {
  { 0, NULL }
};

/* Everything except OSSL_FUNC_CORE_NEW_ERROR, isolating err.c:47. */
MOCK_CORE_MAYBE_UNUSED
static const OSSL_DISPATCH mock_dispatch_no_new_error[] = {
  { OSSL_FUNC_CORE_SET_ERROR_DEBUG,
    (void (*)(void))mock_core_set_error_debug },
  { OSSL_FUNC_CORE_VSET_ERROR, (void (*)(void))mock_core_vset_error },
  { 0, NULL }
};

/* Everything except OSSL_FUNC_CORE_SET_ERROR_DEBUG, isolating err.c:48. */
MOCK_CORE_MAYBE_UNUSED
static const OSSL_DISPATCH mock_dispatch_no_set_error_debug[] = {
  { OSSL_FUNC_CORE_NEW_ERROR, (void (*)(void))mock_core_new_error },
  { OSSL_FUNC_CORE_VSET_ERROR, (void (*)(void))mock_core_vset_error },
  { 0, NULL }
};

/* Everything except OSSL_FUNC_CORE_VSET_ERROR, isolating err.c:49. */
MOCK_CORE_MAYBE_UNUSED
static const OSSL_DISPATCH mock_dispatch_no_vset_error[] = {
  { OSSL_FUNC_CORE_NEW_ERROR, (void (*)(void))mock_core_new_error },
  { OSSL_FUNC_CORE_SET_ERROR_DEBUG,
    (void (*)(void))mock_core_set_error_debug },
  { 0, NULL }
};

#endif                          /* LIBPROV_TESTS_MOCK_CORE_H */
