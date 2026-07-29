/* CC0 license applied, see LICENSE */

/*
 * Handle lifecycle and dispatch-table resolution for err.c: what
 * proverr_new_handle() resolves out of an OSSL_DISPATCH table, what
 * proverr_dup_handle() copies, and what proverr_free_handle() must leave
 * alone.
 *
 * THE HANDLE IS OPAQUE, SO EVERY CHECK IS BEHAVIOURAL.  struct
 * proverr_functions_st is defined only inside err.c (err.c:7-12) and
 * include/prov/err.h:58 merely forward-declares it, so the type is incomplete
 * in this translation unit and handle->core, handle->core_new_error and
 * friends are not readable here -- they would not compile.  "The handle stored
 * the right core and the right callbacks" is therefore proved the only way it
 * can be: raise an error through the handle and assert WHICH stub ran, HOW
 * MANY times, IN WHAT ORDER and WITH WHAT arguments.  That is also why
 * mock_core.h binds two distinguishable new_error stubs -- without a second
 * one, "the last duplicate won" would be unobservable -- and why its
 * call-sequence recorder is load-bearing rather than decorative.
 *
 * NO ABORTING INPUT BELONGS HERE.  This target must be built from this source
 * alone and linked against libprov, whose err.c is compiled with the project's
 * default flags, so the five assertions inside err.c are LIVE.
 * proverr_new_handle(NULL, table), proverr_new_handle(core, NULL) and every
 * incomplete table -- the empty one and the three that omit one callback --
 * abort at err.c:26, err.c:27 and err.c:47-49, which would kill this process
 * in the middle of the suite.  Those inputs belong exclusively to
 * tests/test_err_death.c, which asserts the abort positively from a forked
 * child, and to tests/test_err_guards.c, which asserts the graceful NULL
 * returns that err.c:29-32 and err.c:51-54 make reachable under NDEBUG.  Do
 * not "helpfully" add a NULL-core case here.
 *
 * What is exercised here is therefore exactly the set of inputs that cannot
 * abort: tables that resolve all three callbacks -- in order, shuffled, with
 * unrecognised ids, with duplicates, with junk after the sentinel -- plus
 * proverr_dup_handle() and proverr_free_handle() including their NULL
 * arguments, neither of which asserts anything about its argument (err.c:70,
 * err.c:82).
 *
 * NO LIBCRYPTO IS CALLED.  The core is mock_core.h's hand-built one
 * throughout, and nothing here needs an OSSL_PARAM.  This file does not
 * include <openssl/params.h>, though prov/err.h reaches it transitively
 * through <openssl/core_dispatch.h> and <openssl/indicator.h>; that graph
 * belongs to the project header, and it only DECLARES the OSSL_PARAM_
 * families, which are libcrypto functions.  None of them is ever called, so
 * this binary's dynamic dependencies remain the vDSO, libc and the loader.
 */

#include "testutil.h"
#include "mock_core.h"
#include "prov/err.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*
 * Room for the longest "where: what" label composed below, with generous
 * slack: the longest pair in this file is well under half of it.
 */
#define LABEL_MAX 160

/*
 * Compose "where: what" into storage the CALLER owns, so that a failing line
 * names the case as well as the property.  It matters because the shared probe
 * below does most of the asserting: the file:line testutil.h prints is the
 * line inside that probe, identical for every case, so the case has to travel
 * in the label instead.
 *
 * The buffer is always a local of the calling function and never a static,
 * which keeps this helper re-entrant and keeps the file free of mutable state
 * of its own -- mock_core_obs is the only mutable object any case touches, and
 * mock_core_reset() owns it.  Given a nonzero capacity snprintf() truncates
 * rather than overruns and writes a terminating null (C99 7.19.6.5), and every
 * caller here passes sizeof of a LABEL_MAX array; its return value is unused
 * because a truncated label is a cosmetic loss, not a test result.
 */
static const char *case_label(char *buffer, size_t capacity,
                              const char *where, const char *what)
{
  snprintf(buffer, capacity, "%s: %s", where, what);
  return buffer;
}

/*
 * Shorthand for case_label() at the assertion site.  It reads the `label`
 * array and the `where` string from the enclosing scope, which every function
 * using it declares; spelling both out at each of the assertions below would
 * bury the values actually being asserted.  `label` must be an array rather
 * than a pointer, which every use of it is.
 */
#define AT(what) case_label(label, sizeof label, where, (what))

/*
 * The one fixture this file owns.  mock_core.h supplies nine dispatch tables
 * and every one of them -- like OSSL_DISPATCH_END in <openssl/core.h> -- ends
 * with a literal { 0, NULL }, so none of them can distinguish "the scan stops
 * where the ID is zero" from "the scan stops where the function pointer is
 * null".  <openssl/core_dispatch.h> settles which it is: id 0 "serves as a
 * marker for the end of the OSSL_DISPATCH array, and must therefore NEVER be
 * used as a function identity".  The terminator is the ID.
 *
 * This table states that as a testable claim by giving the terminating entry a
 * NON-NULL function -- bound to the alternate stub, and followed by a live
 * new_error entry that must never be reached -- so a loop that keyed off the
 * function pointer instead of the ID would resolve new_error to the alternate
 * stub and fail.  The trailing { 0, NULL } is there so such a loop stops at a
 * real terminator rather than running off the end, which would replace a clean
 * assertion failure with undefined behaviour.
 *
 * It lives here rather than in mock_core.h because it is a MALFORMED table
 * built for exactly one mutation; the nine well-formed ones stay shared.
 */
static const OSSL_DISPATCH local_dispatch_nonnull_sentinel[] = {
  { OSSL_FUNC_CORE_NEW_ERROR, (void (*)(void))mock_core_new_error },
  { OSSL_FUNC_CORE_SET_ERROR_DEBUG,
    (void (*)(void))mock_core_set_error_debug },
  { OSSL_FUNC_CORE_VSET_ERROR, (void (*)(void))mock_core_vset_error },
  { 0, (void (*)(void))mock_core_alt_new_error },
  { OSSL_FUNC_CORE_NEW_ERROR, (void (*)(void))mock_core_alt_new_error },
  { 0, NULL }
};

/*
 * Every function below spells out the project's accumulator idiom -- an "int
 * ret = 1;" of its own, then "TEST_ASSERT_...(...); ret &= test;" -- and
 * returns it, so a case reports one verdict while still printing a line per
 * assertion.  That local shadows the file-scope accumulator testutil.h
 * declares with internal linkage for the same purpose; the shadowed object is
 * untouched by this file and is independently refreshed from the counters by
 * every assertion, so it cannot accumulate across a function anyway.
 *
 * The accumulated verdicts are belt to testutil.h's braces, never a substitute
 * for them: the exit status in main() is derived from the counters as well.
 */

/*
 * The invoke-and-observe probe, written once and reused by every case: raise
 * one error through `handle` and assert everything that raise makes visible.
 *
 * ERR_raise() expands to the comma expression at include/prov/err.h:49-52, so
 * one call reaches all three forwarders -- proverr_new_error(),
 * proverr_set_error_debug() and proverr_set_error() -- and each forwards the
 * core pointer the handle stored at err.c:57 (err.c:87, err.c:93, err.c:102).
 * Pointer IDENTITY is the right claim for all three, because err.c passes the
 * pointer through and never copies what it points at.
 *
 * The raise is a statement of its own and the observations are read only
 * afterwards: C does not specify the order in which function-call arguments
 * are evaluated, so asserting an observation inside the expression that
 * triggers it would be a bug rather than a shortcut.
 *
 * The alternate new_error stub is asserted to have run zero times on EVERY
 * path, not only where a table binds it.  In the three tables that do bind it
 * -- unknown ids, duplicate ids, entries after the sentinel -- that zero is
 * the entire proof; everywhere else it is a free guarantee that resolution did
 * not drift onto it.
 *
 * Full macro-contract coverage -- the captured OPENSSL_FILE, the call-site
 * OPENSSL_LINE, OPENSSL_FUNC, the reason extremes and va_list recovery -- is
 * tests/test_err_raise.c's subject.  Here the macro is a means: it is the only
 * instrument that can see inside an opaque handle.
 */
static int raise_and_observe(const char *where,
                             const struct proverr_functions_st *handle,
                             const OSSL_CORE_HANDLE *expected_core,
                             uint32_t reason)
{
  char label[LABEL_MAX];
  int ret = 1;

  ERR_raise(handle, reason);

  TEST_ASSERT_UINT_EQ(AT("new_error calls"), mock_core_obs.new_error_calls,
                      1UL);
  ret &= test;
  TEST_ASSERT_UINT_EQ(AT("set_error_debug calls"),
                      mock_core_obs.set_error_debug_calls, 1UL);
  ret &= test;
  TEST_ASSERT_UINT_EQ(AT("vset_error calls"), mock_core_obs.vset_error_calls,
                      1UL);
  ret &= test;

  /*
   * The alternate stub is interchangeable with the primary as far as err.c is
   * concerned, so only a call count can reveal which one a table resolved to.
   */
  TEST_ASSERT_UINT_EQ(AT("alternate new_error calls"),
                      mock_core_obs.alt_new_error_calls, 0UL);
  ret &= test;

  TEST_ASSERT_PTR_EQ(AT("core forwarded to new_error"),
                     mock_core_obs.new_error_core, expected_core);
  ret &= test;
  TEST_ASSERT_PTR_EQ(AT("core forwarded to set_error_debug"),
                     mock_core_obs.set_error_debug_core, expected_core);
  ret &= test;
  TEST_ASSERT_PTR_EQ(AT("core forwarded to vset_error"),
                     mock_core_obs.vset_error_core, expected_core);
  ret &= test;

  TEST_ASSERT_UINT_EQ(AT("reason forwarded"), mock_core_obs.reason, reason);
  ret &= test;

  /*
   * ERR_raise() supplies NULL for the format string (include/prov/err.h:47),
   * so a non-NULL fmt here would mean an argument had been fabricated on the
   * way through.
   */
  TEST_ASSERT_PTR_NULL(AT("format string forwarded"), mock_core_obs.fmt_ptr);
  ret &= test;

  /*
   * Order is the contract of the comma expression at
   * include/prov/err.h:49-52, and the recorder is the only way to see it.
   */
  TEST_ASSERT_SIZE_EQ(AT("recorded call count"), mock_core_obs.seq_len,
                      (size_t)3);
  ret &= test;
  TEST_ASSERT_INT_EQ(AT("first call is new_error"), mock_core_obs.seq[0],
                     MOCK_CORE_ORD_NEW_ERROR);
  ret &= test;
  TEST_ASSERT_INT_EQ(AT("second call is set_error_debug"),
                     mock_core_obs.seq[1], MOCK_CORE_ORD_SET_ERROR_DEBUG);
  ret &= test;
  TEST_ASSERT_INT_EQ(AT("third call is vset_error"), mock_core_obs.seq[2],
                     MOCK_CORE_ORD_VSET_ERROR);
  ret &= test;

  /*
   * A dropped ordinal would mean the recorder overflowed and the order
   * assertions above are reading a truncated history, which is worth failing
   * on rather than silently trusting.
   */
  TEST_ASSERT_UINT_EQ(AT("recorder overflow count"),
                      mock_core_obs.seq_dropped, 0UL);
  ret &= test;

  return ret;
}

/*
 * Assert that a freshly resolved handle has called nothing yet.  err.c:34-45
 * only STORES callback pointers, so a resolution loop that invoked one -- or
 * a reset that failed to clear the recorder -- has to be caught before any
 * later count can be trusted.
 */
static int assert_quiescent(const char *where, const char *what)
{
  char label[LABEL_MAX];
  int ret = 1;

  TEST_ASSERT_SIZE_EQ(AT(what), mock_core_obs.seq_len, (size_t)0);
  ret &= test;
  TEST_ASSERT_UINT_EQ(AT("new_error calls while quiescent"),
                      mock_core_obs.new_error_calls, 0UL);
  ret &= test;
  TEST_ASSERT_UINT_EQ(AT("alternate new_error calls while quiescent"),
                      mock_core_obs.alt_new_error_calls, 0UL);
  ret &= test;

  return ret;
}

static int test_complete_table(void);
static int test_shuffled_table(void);
static int test_unknown_ids(void);
static int test_duplicate_ids(void);
static int test_post_sentinel_entries(void);
static int test_zero_id_terminates(void);
static int test_dup_handle(void);
static int test_free_handle(void);
static int test_distinct_cores(void);

int main(void)
{
  int ret = 1;

  ret &= test_complete_table();
  ret &= test_shuffled_table();
  ret &= test_unknown_ids();
  ret &= test_duplicate_ids();
  ret &= test_post_sentinel_entries();
  ret &= test_zero_id_terminates();
  ret &= test_dup_handle();
  ret &= test_free_handle();
  ret &= test_distinct_cores();

  /*
   * The exit status is DERIVED, never reached: TEST_REPORT() is non-zero when
   * any assertion mismatched and also when none ran at all, so falling off
   * the end of main() cannot manufacture a pass.  The accumulated case
   * verdict is folded in as well, so a case that bailed out early -- always
   * after a failed assertion, never instead of one -- cannot be lost either.
   * Both operands are 0 or 1, so the result is a valid exit status.
   */
  return TEST_REPORT("test_err_handle") | !ret;
}

/*
 * A complete table in ascending id order (5, 6, 7): the happy path, and the
 * baseline every case below is a deviation from.  The reason 42 is arbitrary
 * but asserted exactly, so a forwarder that dropped or rewrote it fails here.
 */
static int test_complete_table(void)
{
  const char *where = "complete table";
  char label[LABEL_MAX];
  struct proverr_functions_st *handle;
  int ret = 1;

  mock_core_reset();

  handle = proverr_new_handle(&mock_core_primary, mock_dispatch_complete);
  TEST_ASSERT_PTR_NOT_NULL(AT("handle"), handle);
  ret &= test;
  if (handle == NULL)
    /*
     * Nothing further is assertable and proverr_new_error() would dereference
     * the null pointer at err.c:87.  The assertion above has already recorded
     * the mismatch, so this guards against a crash; it does not skip a check.
     * The same guard appears in every case below, for this reason.
     */
    return 0;

  ret &= assert_quiescent(where, "stubs run by resolution alone");
  ret &= raise_and_observe(where, handle, &mock_core_primary, 42u);

  proverr_free_handle(handle);
  return ret;
}

/*
 * The same three entries in a different order (7, 5, 6).  Nothing promises a
 * provider an ordered dispatch table, and err.c:34-45 keys on
 * dispatch->function_id rather than on an entry's position, so behaviour must
 * be indistinguishable from the complete table above.  A loop rewritten to
 * read the table positionally would still hand back a non-NULL handle and
 * would still survive any check that stopped there; it fails here, because it
 * would bind the wrong stub to each slot and both the per-stub counts and the
 * recorded order would change.
 */
static int test_shuffled_table(void)
{
  const char *where = "shuffled table";
  char label[LABEL_MAX];
  struct proverr_functions_st *handle;
  int ret = 1;

  mock_core_reset();

  handle = proverr_new_handle(&mock_core_primary, mock_dispatch_shuffled);
  TEST_ASSERT_PTR_NOT_NULL(AT("handle"), handle);
  ret &= test;
  if (handle == NULL)
    return 0;

  ret &= assert_quiescent(where, "stubs run by resolution alone");
  ret &= raise_and_observe(where, handle, &mock_core_primary, 43u);

  proverr_free_handle(handle);
  return ret;
}

/*
 * Unrecognised ids interleaved with the three that matter.
 * mock_dispatch_unknown_ids binds OSSL_FUNC_CORE_SET_ERROR_MARK (8),
 * OSSL_FUNC_CORE_CLEAR_LAST_ERROR_MARK (9) and MOCK_CORE_ID_UNASSIGNED (9999)
 * to the ALTERNATE new_error stub, which is what turns tolerance into a
 * measurement instead of an inference from a non-NULL handle: the switch at
 * err.c:35-45 carries no default label, so an unrecognised id must be skipped
 * in silence and the alternate stub must never be stored.  8 and 9 are real
 * core function ids immediately adjacent to the three err.c wants, so a switch
 * that grew a default -- or a comparison that widened by one -- would pick
 * exactly them up.
 */
static int test_unknown_ids(void)
{
  const char *where = "unknown ids";
  char label[LABEL_MAX];
  struct proverr_functions_st *handle;
  int ret = 1;

  mock_core_reset();

  handle = proverr_new_handle(&mock_core_primary, mock_dispatch_unknown_ids);
  TEST_ASSERT_PTR_NOT_NULL(AT("handle"), handle);
  ret &= test;
  if (handle == NULL)
    return 0;

  ret &= assert_quiescent(where, "stubs run by resolution alone");

  ret &= raise_and_observe(where, handle, &mock_core_primary, 44u);

  TEST_ASSERT_PTR_NULL(AT("core seen by the alternate stub"),
                       mock_core_obs.alt_new_error_core);
  ret &= test;

  proverr_free_handle(handle);
  return ret;
}

/*
 * Two entries for OSSL_FUNC_CORE_NEW_ERROR, the alternate first and the
 * primary last.  err.c:36-38 assigns without testing whether the slot is
 * already filled, so the LAST occurrence survives and a raise must fire the
 * primary stub.
 *
 * Both counts are asserted rather than one.  "The primary ran once" alone
 * would not separate last-wins from first-wins if the primary were reachable
 * by some other route, and "the alternate never ran" alone would say nothing
 * about what was stored in its place.  raise_and_observe() requires the
 * primary exactly once AND the alternate exactly never, which together admit
 * only the last-wins reading.
 */
static int test_duplicate_ids(void)
{
  const char *where = "duplicate ids";
  char label[LABEL_MAX];
  struct proverr_functions_st *handle;
  int ret = 1;

  mock_core_reset();

  handle = proverr_new_handle(&mock_core_primary, mock_dispatch_duplicate_ids);
  TEST_ASSERT_PTR_NOT_NULL(AT("handle"), handle);
  ret &= test;
  if (handle == NULL)
    return 0;

  ret &= assert_quiescent(where, "stubs run by resolution alone");
  ret &= raise_and_observe(where, handle, &mock_core_primary, 45u);

  TEST_ASSERT_INT_EQ(AT("first ordinal is the primary stub's"),
                     mock_core_obs.seq[0], MOCK_CORE_ORD_NEW_ERROR);
  ret &= test;

  proverr_free_handle(handle);
  return ret;
}

/*
 * A complete table, its { 0, NULL } terminator, and a fourth entry that must
 * never be read -- bound to the alternate stub so that "never read" is
 * assertable rather than assumed.  err.c:34 tests function_id before each
 * iteration, so the scan stops AT the sentinel.  A loop that advanced before
 * testing, or that treated a null function pointer rather than a zero id as
 * the terminator, would resolve new_error to the entry past the end, and the
 * alternate count inside the probe would be one instead of zero.
 */
static int test_post_sentinel_entries(void)
{
  const char *where = "entries after the sentinel";
  char label[LABEL_MAX];
  struct proverr_functions_st *handle;
  int ret = 1;

  mock_core_reset();

  handle =
    proverr_new_handle(&mock_core_primary, mock_dispatch_after_sentinel);
  TEST_ASSERT_PTR_NOT_NULL(AT("handle"), handle);
  ret &= test;
  if (handle == NULL)
    return 0;

  ret &= assert_quiescent(where, "stubs run by resolution alone");
  ret &= raise_and_observe(where, handle, &mock_core_primary, 46u);

  TEST_ASSERT_PTR_NULL(AT("core seen by the post-sentinel stub"),
                       mock_core_obs.alt_new_error_core);
  ret &= test;

  proverr_free_handle(handle);
  return ret;
}

/*
 * The ZERO ID is the terminator, not the null function pointer.  err.c:34
 * tests dispatch->function_id and nothing else, which is the reading
 * <openssl/core_dispatch.h> requires when it reserves id 0 as the end-of-array
 * marker.  Every table in mock_core.h ends with { 0, NULL }, so the two
 * possible terminator rules agree on all of them and none can tell them apart;
 * local_dispatch_nonnull_sentinel exists precisely to separate them.
 *
 * With the ID rule -- the correct one -- the scan stops at the fourth entry
 * even though its function pointer is live, so the primary stub stays stored
 * and the two alternate-stub entries beyond it are never seen.  A loop that
 * continued while EITHER field was set would walk on and overwrite new_error
 * with the alternate stub, which the probe's counts reject.
 */
static int test_zero_id_terminates(void)
{
  const char *where = "zero id terminates the scan";
  char label[LABEL_MAX];
  struct proverr_functions_st *handle;
  int ret = 1;

  mock_core_reset();

  handle =
    proverr_new_handle(&mock_core_primary, local_dispatch_nonnull_sentinel);
  TEST_ASSERT_PTR_NOT_NULL(AT("handle"), handle);
  ret &= test;
  if (handle == NULL)
    return 0;

  ret &= assert_quiescent(where, "stubs run by resolution alone");
  ret &= raise_and_observe(where, handle, &mock_core_primary, 50u);

  TEST_ASSERT_PTR_NULL(AT("core seen by the terminator's own callback"),
                       mock_core_obs.alt_new_error_core);
  ret &= test;

  proverr_free_handle(handle);
  return ret;
}

/*
 * Duplication.  err.c:65-78 allocates a fresh object and shallow-copies all
 * four members into it, so three separate claims have to hold: the copy is a
 * DISTINCT object, it carries the SAME core and the same three callbacks, and
 * its lifetime is INDEPENDENT of the source's.
 *
 * With the struct private (err.c:7-12), "same contents" cannot be read out and
 * is instead proved by raising through the copy and requiring the identical
 * observation the source produces.  The independence claim is the one that
 * pins the shallow-copy semantics: a dup rewritten to alias the source, or to
 * take ownership of anything the source also owns, would leave the source
 * unusable, or leave this case reading freed memory -- which a sanitizer build
 * reports and an ordinary build may not.
 *
 * Allocation failure is the other way proverr_dup_handle() can return NULL;
 * that path needs an allocator interposer and belongs to
 * tests/test_err_alloc.c.
 */
static int test_dup_handle(void)
{
  const char *where = "dup handle";
  char label[LABEL_MAX];
  struct proverr_functions_st *source;
  struct proverr_functions_st *copy;
  int ret = 1;

  mock_core_reset();

  source = proverr_new_handle(&mock_core_primary, mock_dispatch_complete);
  TEST_ASSERT_PTR_NOT_NULL(AT("source handle"), source);
  ret &= test;
  if (source == NULL)
    return 0;

  copy = proverr_dup_handle(source);
  TEST_ASSERT_PTR_NOT_NULL(AT("copy"), copy);
  ret &= test;
  if (copy == NULL) {
    proverr_free_handle(source);
    return 0;
  }

  TEST_ASSERT_PTR_NE(AT("copy is distinct from the source"), copy, source);
  ret &= test;
  if (copy == source) {
    /*
     * A dup that handed back its own argument has already failed the assertion
     * above, and the rest of this case would free one object twice and then
     * read it back.  Stopping here keeps the TEST free of undefined behaviour
     * even when the library is broken, so the failure is reported as a
     * mismatch rather than as a crash that buries the diagnosis.
     */
    proverr_free_handle(source);
    return 0;
  }

  ret &= assert_quiescent(where, "stubs run by new_handle and dup together");

  ret &= raise_and_observe("dup handle / raise through the copy", copy,
                           &mock_core_primary, 47u);

  /*
   * Independent lifetime.  err.c:80-83 frees exactly the object it was handed,
   * so the source must still be fully functional afterwards -- not merely
   * non-NULL, but still forwarding the same core to the same three stubs in
   * the same order.
   */
  proverr_free_handle(copy);

  mock_core_reset();
  ret &= raise_and_observe("dup handle / source after the copy was freed",
                           source, &mock_core_primary, 48u);

  proverr_free_handle(source);

  /*
   * err.c:70 rejects a null source before it allocates, so there is nothing to
   * copy, nothing to free and nothing to call.  Asserting the callback counts
   * as well as the NULL return is what keeps this from being a check that the
   * call merely returned.
   */
  mock_core_reset();
  copy = proverr_dup_handle(NULL);
  TEST_ASSERT_PTR_NULL(AT("dup of a null handle"), copy);
  ret &= test;
  ret &= assert_quiescent(where, "stubs run by dup of a null handle");
  TEST_ASSERT_UINT_EQ(AT("set_error_debug calls after dup of null"),
                      mock_core_obs.set_error_debug_calls, 0UL);
  ret &= test;
  TEST_ASSERT_UINT_EQ(AT("vset_error calls after dup of null"),
                      mock_core_obs.vset_error_calls, 0UL);
  ret &= test;

  return ret;
}

/*
 * Freeing.  err.c:80-83 is a plain free(), and free(NULL) is defined to do
 * nothing (C99 7.20.3.2), so a null handle must be accepted.  Surviving the
 * call is not the assertion -- that would be a check that the code ran -- the
 * assertions are that no stub was invoked, and that freeing a LIVE handle
 * invokes nothing either.
 *
 * The live-handle half is asserted twice over: the counts must be unchanged
 * across the free, and they must still hold their absolute values afterwards.
 * The delta alone would be satisfied if both sides were zero, which is exactly
 * what a free that also reset the observation state would produce.
 *
 * WHAT THIS CASE CANNOT REACH, AND WHERE IT IS REACHED INSTEAD.  Everything
 * asserted here is about what proverr_free_handle() must NOT do.  The positive
 * fact -- that it releases the block, that it releases exactly the block it
 * was given, and that it releases it exactly once -- is invisible from this
 * translation unit: the function returns nothing, writes through nothing and
 * calls no stub, so a body deleted outright would satisfy every assertion
 * below.  Proving the release therefore needs the allocator itself to be the
 * witness, which needs link-time interposition, which is a per-target link
 * option and not something a source file can arrange for itself.  That is
 * exactly what tests/test_err_alloc.c is registered with, and its cases A-9 to
 * A-12 assert the release positively: pointer identity of the block handed to
 * free, a call count of exactly one per release, the source surviving while
 * its duplicate's block goes away, and a ledger of blocks supplied against
 * blocks released that must close at zero.  Nothing here is redundant with
 * those -- the two halves are complementary, and this comment exists so that a
 * reader who notices the gap can find where it is closed rather than
 * concluding it is open.
 */
static int test_free_handle(void)
{
  const char *where = "free handle";
  char label[LABEL_MAX];
  struct proverr_functions_st *handle;
  unsigned long new_error_before;
  unsigned long set_error_debug_before;
  unsigned long vset_error_before;
  size_t recorded_before;
  int ret = 1;

  mock_core_reset();

  proverr_free_handle(NULL);
  ret &= assert_quiescent(where, "stubs run by freeing a null handle");
  TEST_ASSERT_UINT_EQ(AT("set_error_debug calls after free of null"),
                      mock_core_obs.set_error_debug_calls, 0UL);
  ret &= test;
  TEST_ASSERT_UINT_EQ(AT("vset_error calls after free of null"),
                      mock_core_obs.vset_error_calls, 0UL);
  ret &= test;

  handle = proverr_new_handle(&mock_core_primary, mock_dispatch_complete);
  TEST_ASSERT_PTR_NOT_NULL(AT("handle"), handle);
  ret &= test;
  if (handle == NULL)
    return 0;

  ret &= raise_and_observe("free handle / raise before the free", handle,
                           &mock_core_primary, 49u);

  /* Read the observations, then act: never both in one expression. */
  new_error_before = mock_core_obs.new_error_calls;
  set_error_debug_before = mock_core_obs.set_error_debug_calls;
  vset_error_before = mock_core_obs.vset_error_calls;
  recorded_before = mock_core_obs.seq_len;

  proverr_free_handle(handle);

  TEST_ASSERT_UINT_EQ(AT("new_error calls unchanged across the free"),
                      mock_core_obs.new_error_calls, new_error_before);
  ret &= test;
  TEST_ASSERT_UINT_EQ(AT("set_error_debug calls unchanged across the free"),
                      mock_core_obs.set_error_debug_calls,
                      set_error_debug_before);
  ret &= test;
  TEST_ASSERT_UINT_EQ(AT("vset_error calls unchanged across the free"),
                      mock_core_obs.vset_error_calls, vset_error_before);
  ret &= test;
  TEST_ASSERT_SIZE_EQ(AT("recorded call count unchanged across the free"),
                      mock_core_obs.seq_len, recorded_before);
  ret &= test;

  /* The absolute values, so the deltas above cannot pass vacuously. */
  TEST_ASSERT_UINT_EQ(AT("new_error calls after the free"),
                      mock_core_obs.new_error_calls, 1UL);
  ret &= test;
  TEST_ASSERT_SIZE_EQ(AT("recorded call count after the free"),
                      mock_core_obs.seq_len, (size_t)3);
  ret &= test;
  TEST_ASSERT_UINT_EQ(AT("alternate new_error calls after the free"),
                      mock_core_obs.alt_new_error_calls, 0UL);
  ret &= test;

  return ret;
}

/*
 * A handle forwards the core it was GIVEN, not a core the library holds
 * globally.  err.c:57 stores the argument and err.c:87, err.c:93 and
 * err.c:102 forward that stored pointer, so two handles built over the two
 * distinct fixtures in mock_core.h must forward two distinct pointers.
 *
 * Both halves are stated: each handle forwards its own core (inside the probe)
 * and the alternate handle does NOT forward the primary's.  The negative half
 * is what catches a store that ignored its argument in favour of a file-scope
 * value, since a single-core case would pass either way.
 */
static int test_distinct_cores(void)
{
  const char *where = "distinct cores";
  char label[LABEL_MAX];
  struct proverr_functions_st *primary_handle;
  struct proverr_functions_st *alternate_handle;
  int ret = 1;

  mock_core_reset();

  /*
   * The claim is only falsifiable if the fixtures really are two objects
   * (mock_core.h defines them separately), so that precondition is asserted
   * rather than trusted.
   */
  TEST_ASSERT_PTR_NE(AT("the two core fixtures are distinct objects"),
                     &mock_core_primary, &mock_core_alternate);
  ret &= test;

  primary_handle =
    proverr_new_handle(&mock_core_primary, mock_dispatch_complete);
  TEST_ASSERT_PTR_NOT_NULL(AT("handle over the primary core"),
                           primary_handle);
  ret &= test;

  alternate_handle =
    proverr_new_handle(&mock_core_alternate, mock_dispatch_complete);
  TEST_ASSERT_PTR_NOT_NULL(AT("handle over the alternate core"),
                           alternate_handle);
  ret &= test;

  if (primary_handle == NULL || alternate_handle == NULL) {
    proverr_free_handle(primary_handle);
    proverr_free_handle(alternate_handle);
    return 0;
  }

  TEST_ASSERT_PTR_NE(AT("the two handles are distinct objects"),
                     primary_handle, alternate_handle);
  ret &= test;

  /*
   * That verdict is a PRECONDITION for everything below, not a remark, so it
   * is captured and acted on.  Every line that follows either reads through
   * both handles or releases both, and all of it is defined only if they
   * really are two objects: against a library that pooled or cached handles
   * -- returning its single object twice -- an ungated body would raise
   * through a handle it had already freed, make the "each handle forwards its
   * OWN core" checks below meaningless, and finally free that one object
   * TWICE at the tail of this function.  That is a double free (CWE-415): it
   * turns a clean, self-diagnosing contract mismatch into heap corruption or
   * an abort, and an abort discards whatever stdout still had buffered,
   * taking the failure line that explains it with it.
   *
   * The aliased path therefore releases the object EXACTLY ONCE and returns
   * failure, exactly as the null-handle guard above does.  `ret` is already 0
   * because the assertion recorded the mismatch -- which is the diagnosis,
   * and is what testutil.h's counters derive the exit status from -- but 0 is
   * returned explicitly so the verdict does not depend on that coupling.
   */
  if (primary_handle == alternate_handle) {
    proverr_free_handle(primary_handle);
    return 0;
  }

  ret &= assert_quiescent(where, "stubs run by building both handles");

  ret &= raise_and_observe("distinct cores / primary handle", primary_handle,
                           &mock_core_primary, 0x11u);

  mock_core_reset();
  ret &= raise_and_observe("distinct cores / alternate handle",
                           alternate_handle, &mock_core_alternate, 0x22u);

  TEST_ASSERT_PTR_NE(AT("the alternate handle did not forward the primary"
                        " core"),
                     mock_core_obs.new_error_core, &mock_core_primary);
  ret &= test;

  proverr_free_handle(primary_handle);
  proverr_free_handle(alternate_handle);
  return ret;
}
