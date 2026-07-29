/* CC0 license applied, see LICENSE */

/*
 * proverr_new_handle()'s TWO argument-validation contracts, asserted from ONE
 * source compiled TWICE.
 *
 * err.c validates its arguments twice over: with assert() (err.c:26, :27, :47,
 * :48, :49) and again with a preprocessor-guarded early return (err.c:29-32,
 * err.c:51-54).  The two mechanisms are MUTUALLY EXCLUSIVE under any single
 * set of flags.  Where an assertion is live it aborts the process before the
 * matching early return can be taken; where NDEBUG has removed the assertions
 * the early return is what runs.  No single compilation can observe both, so
 * covering both means compiling this source twice, from two registered
 * targets.
 *
 * One case, test_common_happy_path(), is asserted IDENTICALLY by both
 * variants.  That is deliberate: it proves the two binaries really are the
 * same source under different flags, and that the variant marker only ADDS
 * cases rather than replacing the body wholesale.
 *
 * WHAT THE TWO TARGETS MUST BE, AND WHY THE OBVIOUS ARRANGEMENT DOES NOT WORK
 *
 *   test_err_guards         this source + <top>/err.c, compiled -UNDEBUG
 *   test_err_guards_ndebug  this source + <top>/err.c, compiled
 *                           -DNDEBUG -DLIBPROV_TEST_NDEBUG_VARIANT
 *
 * Note what has to be in each source list: err.c itself, compiled AFRESH into
 * each target, and each target's flags -- including the -UNDEBUG on the
 * default one -- have to apply to that compilation.  That is not tidiness, it
 * is the only thing that makes the NDEBUG variant real.  assert() expands
 * according to the NDEBUG state of the translation unit that CONTAINS it, and
 * the calls that matter here are inside err.c.  The libprov library compiles
 * err.c exactly once, without NDEBUG, so defining NDEBUG on a test target that
 * merely LINKS that archive changes nothing about the object already in it:
 * such an "NDEBUG variant" would still abort, and every NULL-return assertion
 * in it would be a fiction rather than a test.  Recompiling err.c with each
 * target's own flags is what puts the guard state under this file's control.
 *
 * Reading err.c is not modifying it.  Compiling it into a test target leaves
 * err.c byte-for-byte untouched, so the arrangement is fully compatible with
 * the constraint that no non-test source may be modified.
 *
 * Linking stays unambiguous even though libprov is still linked for num.c's
 * sake: a definition in an object file named on the command line satisfies the
 * reference before the archive is searched, so the corresponding library
 * member is never extracted and each binary must hold exactly one
 * proverr_new_handle().  Two properties are worth checking with `nm` after any
 * change to the build: exactly one definition of that symbol per binary, and
 * no reference to __assert_fail in the ndebug binary while the default one has
 * at least one.  If either stops holding, the NDEBUG variant has silently
 * become a duplicate of the default one.
 *
 * WHY THE SELECTOR BELOW IS LIBPROV_TEST_NDEBUG_VARIANT AND NOT NDEBUG
 *
 * Because NDEBUG is not this suite's to own.  Configuring with
 * -DCMAKE_BUILD_TYPE=Release adds -DNDEBUG to every target in the project, so
 * a source that branched on NDEBUG would flip the DEFAULT target's body too --
 * and that target would then assert graceful NULL returns while its own
 * -UNDEBUG kept err.c's assertions live, turning a passing pair of tests into
 * six aborts for no reason a reader could see.  The dedicated marker is set by
 * exactly one target and by nothing else, so the two bodies stay pinned to the
 * two builds whatever CMAKE_BUILD_TYPE is in force.  -UNDEBUG on the default
 * target is the other half of that guarantee: it keeps err.c's assertions live
 * there even under Release.
 *
 * Do not "simplify" either half away.  Dropping the recompilation of err.c, or
 * swapping the marker for NDEBUG, restores a version of this file that looks
 * correct, compiles, passes, and tests nothing.
 *
 * WHICH PATHS EACH VARIANT MAKES REACHABLE (err.c line by line)
 *
 *   err.c:26      assert(core != NULL);
 *   err.c:27      assert(dispatch != NULL);
 *   err.c:29-32   #ifndef DEBUG
 *                   if (core == NULL || dispatch == NULL) return NULL;
 *                 #endif
 *   err.c:34-45   dispatch-resolution loop; stops at the function_id == 0
 *                 sentinel, and its switch has no default label
 *   err.c:47      assert(c_new_error != NULL);
 *   err.c:48      assert(c_set_error_debug != NULL);
 *   err.c:49      assert(c_vset_error != NULL);
 *   err.c:51-54   #ifdef NDEBUG
 *                   if (c_new_error == NULL || c_set_error_debug == NULL
 *                       || c_vset_error == NULL) return NULL;
 *                 #endif
 *   err.c:56      handle = malloc(sizeof(*handle));
 *
 * Default variant (-UNDEBUG; DEBUG is never defined as a preprocessor macro
 * anywhere in this project -- see the Class C note at the foot of this file):
 *   - A NULL core or a NULL dispatch aborts at err.c:26 / err.c:27.  The early
 *     return at err.c:29-32 is compiled IN, because it is guarded on DEBUG
 *     rather than on NDEBUG, but it is DOMINATED by those two assertions and
 *     so cannot be reached.  That is a named exclusion, not a coverage gap.
 *   - Any table that leaves a required callback unresolved aborts at err.c:47,
 *     :48 or :49.  The early return at err.c:51-54 is compiled OUT.
 *   - Hence NO NULL-return path is reachable in this variant at all.  Its job
 *     is to assert the paths that do NOT abort, and to document the ones that
 *     do; the positive abort assertions belong to tests/test_err_death.c,
 *     which forks so that an expected SIGABRT is an assertion rather than a
 *     dead test runner.
 *
 * NDEBUG variant (-DNDEBUG plus the marker):
 *   - All five assertions vanish.
 *   - The early return at err.c:29-32 is still compiled in, and is now
 *     REACHABLE: it is the mechanism that returns NULL for a NULL core and for
 *     a NULL dispatch.
 *   - The early return at err.c:51-54 is now compiled IN, and is the mechanism
 *     that returns NULL for the empty table and for each table missing exactly
 *     one required callback.
 *   - Hence all six graceful NULL returns are reachable here, and all six are
 *     asserted below.
 *
 * THE HANDLE IS OPAQUE.  struct proverr_functions_st is defined only inside
 * err.c (err.c:7-12); include/prov/err.h:58 merely forward-declares it.  No
 * test can read a member, so "the handle is well formed" is never a structural
 * claim here -- it is established BEHAVIOURALLY, by raising through the handle
 * and checking what the recording stubs in tests/mock_core.h saw.  A handle
 * that resolved the wrong callback, or stored the wrong core pointer, fails
 * those checks even though it is non-NULL.
 *
 * The local "int ret = 1, test;" is the project's assertion idiom: every
 * assertion macro assigns to the `test` VISIBLE AT ITS CALL SITE, which is
 * what lets each function accumulate a verdict of its own.  Renaming it would
 * move those assignments to the file-scope objects testutil.h refreshes from
 * its counters, and every "ret &= test" here would then read a value it did
 * not compute.
 *
 * Nothing here calls into libcrypto.  The core handle, the callbacks and the
 * dispatch tables all come from tests/mock_core.h, and no provider is
 * initialised.  <openssl/params.h> is not included by this file, but prov/err.h
 * reaches it transitively by way of <openssl/core_dispatch.h> and
 * <openssl/indicator.h> -- the project header's own include graph.  It only
 * declares the OSSL_PARAM_ families, which are libcrypto functions; not one of
 * them is called, here or anywhere in the suite.
 */

#include "testutil.h"
#include "mock_core.h"
#include "prov/err.h"

#include <stddef.h>
#include <stdio.h>

/*
 * A human-readable name for the variant in force, printed once by main() so a
 * `ctest -V` log says which contract the following lines belong to.
 * Informational only: the verdict comes from the assertion counters.
 */
#ifdef LIBPROV_TEST_NDEBUG_VARIANT
# define GUARD_VARIANT_NAME \
  "NDEBUG (assertions removed, err.c:29-32 and err.c:51-54 reachable)"
#else
# define GUARD_VARIANT_NAME \
  "default (assertions live at err.c:26,27,47,48,49; no NULL return reachable)"
#endif

/*
 * The reason code every raise below carries.  Deliberately not 0 and not 1:
 * err.c:102 forwards it verbatim to the stub, so a distinctive value turns
 * "the reason arrived" into a falsifiable claim rather than something a zeroed
 * observation struct would satisfy by accident.  The extreme values 0 and
 * UINT32_MAX are the business of tests/test_err_raise.c, which owns the
 * forwarding contract; here the reason is checked only to confirm that a
 * handle built from a given table really is wired to the recording stubs.
 */
#define GUARD_REASON 0x0000A5A5u

#define GUARD_LABEL_MAX 192

/*
 * Compose "<case>: <property>" into caller-owned storage and return it, so
 * that one shared checker can emit a distinct, self-describing label for every
 * value it inspects.  Given a nonzero capacity snprintf() truncates rather
 * than overruns and writes a terminating null, and every caller here passes
 * sizeof of a GUARD_LABEL_MAX array; the format string is a literal, so no
 * caller can turn a label into a conversion specification.
 *
 * The trade-off: because the assertions live in the shared checkers, a failing
 * line carries the checker's source location rather than the calling case's.
 * The label is what disambiguates, which is why every call site passes one
 * naming the case.
 */
static const char *guard_label(char *buffer, size_t capacity,
                               const char *label, const char *property)
{
  snprintf(buffer, capacity, "%s: %s", label, property);
  return buffer;
}

/*
 * "No callback ran."  The negative side-effect invariant that keeps every
 * NULL-returning and no-op case in this file out of smoke-test territory: it
 * is not enough that proverr_new_handle() returned NULL, it must also have
 * called nothing on the way there, and a handle that was never built cannot
 * have raised anything.
 *
 * Six separate value inspections, because they fail independently.  The four
 * counters catch a stub that ran; seq_len catches a stub that ran without
 * bumping its counter; and new_error_core catches one that recorded a core
 * pointer without bumping either.  Call mock_core_reset() before the code
 * under test, never after, or this checker is asserting about a cleared
 * struct.
 */
static int guard_no_callbacks_ran(const char *label)
{
  int ret = 1, test;
  char text[GUARD_LABEL_MAX];

  TEST_ASSERT_UINT_EQ(guard_label(text, sizeof(text), label,
                                  "new_error calls"),
                      mock_core_obs.new_error_calls, 0UL);
  ret &= test;

  TEST_ASSERT_UINT_EQ(guard_label(text, sizeof(text), label,
                                  "alt_new_error calls"),
                      mock_core_obs.alt_new_error_calls, 0UL);
  ret &= test;

  TEST_ASSERT_UINT_EQ(guard_label(text, sizeof(text), label,
                                  "set_error_debug calls"),
                      mock_core_obs.set_error_debug_calls, 0UL);
  ret &= test;

  TEST_ASSERT_UINT_EQ(guard_label(text, sizeof(text), label,
                                  "vset_error calls"),
                      mock_core_obs.vset_error_calls, 0UL);
  ret &= test;

  TEST_ASSERT_SIZE_EQ(guard_label(text, sizeof(text), label,
                                  "recorded sequence length"),
                      mock_core_obs.seq_len, (size_t)0);
  ret &= test;

  TEST_ASSERT_PTR_NULL(guard_label(text, sizeof(text), label,
                                   "no core pointer recorded"),
                       mock_core_obs.new_error_core);
  ret &= test;

  return ret;
}

/*
 * Raise once through `handle` and assert everything the raise should have
 * produced.  This is how a non-NULL handle is proved to be a WORKING handle:
 * because struct proverr_functions_st is opaque (err.c:7-12), the only way to
 * learn which callbacks a table resolved to, and which core pointer was
 * stored, is to make the handle use them.
 *
 * ERR_raise() expands to the comma expression at include/prov/err.h:49-52, so
 * one statement drives all three forwarding functions in a fixed order:
 * proverr_new_error() (err.c:87), then proverr_set_error_debug() (err.c:93),
 * then proverr_set_error() (err.c:102).  The recorded ordinals are what make
 * that order observable; three call counts of one could not distinguish an
 * order.
 *
 * The core pointer is asserted at all three callbacks by IDENTITY rather than
 * by value, because err.c:57 stores the pointer and err.c:87, :93 and :102
 * forward it: pass-through is the contract, and identity is the only assertion
 * that tests it.  The alternate new_error stub is the fixtures' marker for "a
 * callback that must never have been resolved", so its call count is asserted
 * zero on every path.
 *
 * `handle` is const-qualified because nothing here writes through it, and that
 * costs a caller nothing: the whole public surface it is forwarded to takes a
 * "const struct proverr_functions_st *" (include/prov/err.h:66-70), and the
 * conversion from the unqualified pointer proverr_new_handle() returns is
 * implicit, so no call site needs a cast.
 */
static int guard_raise_and_check(const char *label,
                                 const struct proverr_functions_st *handle,
                                 const OSSL_CORE_HANDLE *core)
{
  int ret = 1, test;
  char text[GUARD_LABEL_MAX];

  ERR_raise(handle, GUARD_REASON);

  TEST_ASSERT_UINT_EQ(guard_label(text, sizeof(text), label,
                                  "new_error called once"),
                      mock_core_obs.new_error_calls, 1UL);
  ret &= test;

  TEST_ASSERT_UINT_EQ(guard_label(text, sizeof(text), label,
                                  "set_error_debug called once"),
                      mock_core_obs.set_error_debug_calls, 1UL);
  ret &= test;

  TEST_ASSERT_UINT_EQ(guard_label(text, sizeof(text), label,
                                  "vset_error called once"),
                      mock_core_obs.vset_error_calls, 1UL);
  ret &= test;

  TEST_ASSERT_UINT_EQ(guard_label(text, sizeof(text), label,
                                  "alt_new_error never called"),
                      mock_core_obs.alt_new_error_calls, 0UL);
  ret &= test;

  TEST_ASSERT_SIZE_EQ(guard_label(text, sizeof(text), label,
                                  "three calls recorded"),
                      mock_core_obs.seq_len, (size_t)3);
  ret &= test;

  /*
   * seq is a fixed MOCK_CORE_SEQ_MAX-element array that mock_core_reset()
   * zeroes, so indices 0 to 2 are in bounds and defined whatever seq_len came
   * out as; a short sequence shows up as an ordinal of 0 rather than as a read
   * past the end.
   */
  TEST_ASSERT_INT_EQ(guard_label(text, sizeof(text), label,
                                 "call 1 is new_error"),
                     mock_core_obs.seq[0], MOCK_CORE_ORD_NEW_ERROR);
  ret &= test;

  TEST_ASSERT_INT_EQ(guard_label(text, sizeof(text), label,
                                 "call 2 is set_error_debug"),
                     mock_core_obs.seq[1], MOCK_CORE_ORD_SET_ERROR_DEBUG);
  ret &= test;

  TEST_ASSERT_INT_EQ(guard_label(text, sizeof(text), label,
                                 "call 3 is vset_error"),
                     mock_core_obs.seq[2], MOCK_CORE_ORD_VSET_ERROR);
  ret &= test;

  TEST_ASSERT_UINT_EQ(guard_label(text, sizeof(text), label,
                                  "no recorded call dropped"),
                      mock_core_obs.seq_dropped, 0UL);
  ret &= test;

  TEST_ASSERT_PTR_EQ(guard_label(text, sizeof(text), label,
                                 "new_error got the same core"),
                     mock_core_obs.new_error_core, core);
  ret &= test;

  TEST_ASSERT_PTR_EQ(guard_label(text, sizeof(text), label,
                                 "set_error_debug got the same core"),
                     mock_core_obs.set_error_debug_core, core);
  ret &= test;

  TEST_ASSERT_PTR_EQ(guard_label(text, sizeof(text), label,
                                 "vset_error got the same core"),
                     mock_core_obs.vset_error_core, core);
  ret &= test;

  TEST_ASSERT_UINT_EQ(guard_label(text, sizeof(text), label,
                                  "reason forwarded verbatim"),
                      mock_core_obs.reason, GUARD_REASON);
  ret &= test;

  TEST_ASSERT_PTR_NULL(guard_label(text, sizeof(text), label,
                                   "ERR_raise supplies a NULL format"),
                       mock_core_obs.fmt_ptr);
  ret &= test;

  return ret;
}

/*
 * The full life cycle of a handle built from a table that resolves all three
 * required callbacks: construct it, prove construction alone called nothing,
 * raise through it, prove the raise did exactly what it should, prove freeing
 * it called nothing either, and free it.
 *
 * Shared by both variants on purpose.  It carries the case that the default
 * and NDEBUG builds assert identically, and in the default build it is also
 * how each dispatch-resolution fixture is exercised -- the four tables differ
 * only in the shape err.c has to cope with, and all four must end up
 * behaving exactly like the complete, in-order one.  Some of that overlaps
 * tests/test_err_handle.c, which is intended: without real value assertions
 * of its own the default variant would be an empty shell, and an empty shell
 * is the one thing a suite built to catch plausible bugs must not contain.
 *
 * mock_core_reset() runs FIRST, so a case that fails early cannot leak
 * observations into the next one, and every case starts from the documented
 * zero state whatever ran before it.  Whatever was allocated is released on
 * every path: the early return is taken only when there is nothing to free, so
 * a mismatch here reports a mismatch and not also a leak.
 */
static int guard_exercise_resolved_table(const char *label,
                                         const OSSL_DISPATCH *dispatch)
{
  int ret = 1, test;
  char text[GUARD_LABEL_MAX];
  struct proverr_functions_st *handle;
  unsigned long new_error_calls_before_free;
  unsigned long set_error_debug_calls_before_free;
  unsigned long vset_error_calls_before_free;

  mock_core_reset();

  handle = proverr_new_handle(&mock_core_primary, dispatch);

  TEST_ASSERT_PTR_NOT_NULL(guard_label(text, sizeof(text), label,
                                       "handle created"), handle);
  ret &= test;

  /*
   * Building a handle resolves callbacks and copies pointers (err.c:34-45,
   * err.c:56-61); it must not CALL anything.  Asserted before the raise, so
   * the counts the raise then checks are known to have started at zero.
   */
  ret &= guard_no_callbacks_ran(guard_label(text, sizeof(text), label,
                                            "construction alone"));

  if (handle == NULL) {
    /*
     * Returning early keeps a failed construction from becoming a NULL
     * dereference inside ERR_raise().  The verdict is already 0 from the
     * assertion above, so nothing is being excused here -- the case has
     * failed and simply stops adding noise.
     */
    return ret;
  }

  ret &= guard_raise_and_check(label, handle, &mock_core_primary);

  new_error_calls_before_free = mock_core_obs.new_error_calls;
  set_error_debug_calls_before_free = mock_core_obs.set_error_debug_calls;
  vset_error_calls_before_free = mock_core_obs.vset_error_calls;

  proverr_free_handle(handle);

  /*
   * err.c:82 frees the handle and nothing else.  Comparing the counters
   * across the call proves it did not, for instance, report anything through
   * the very callbacks it was about to discard.
   */
  TEST_ASSERT_UINT_EQ(guard_label(text, sizeof(text), label,
                                  "free called no new_error"),
                      mock_core_obs.new_error_calls,
                      new_error_calls_before_free);
  ret &= test;

  TEST_ASSERT_UINT_EQ(guard_label(text, sizeof(text), label,
                                  "free called no set_error_debug"),
                      mock_core_obs.set_error_debug_calls,
                      set_error_debug_calls_before_free);
  ret &= test;

  TEST_ASSERT_UINT_EQ(guard_label(text, sizeof(text), label,
                                  "free called no vset_error"),
                      mock_core_obs.vset_error_calls,
                      vset_error_calls_before_free);
  ret &= test;

  return ret;
}

/*
 * The case both variants assert, identically.  In the NDEBUG variant it
 * carries an extra job: six NULL returns would be worthless if the seventh
 * input -- the valid one -- had also started returning NULL, and a suite that
 * only asserted the NULLs could not tell the two apart.
 */
static int test_common_happy_path(void)
{
  return guard_exercise_resolved_table("common: complete in-order table",
                                       mock_dispatch_complete);
}

#ifdef LIBPROV_TEST_NDEBUG_VARIANT

/*
 * NDEBUG VARIANT -- the six graceful NULL returns.
 *
 * With NDEBUG defined for err.c's own translation unit, the assertions at
 * err.c:26, :27, :47, :48 and :49 expand to nothing and both guarded early
 * returns are live.  Every invalid input below therefore has a defined,
 * observable answer, which is exactly what a release build of a provider
 * depends on: an assertion that has been compiled out must not leave a
 * dereference behind it.
 *
 * The same six inputs abort in the default variant, so none of them may be
 * called from the #else branch of this file.
 */

/*
 * One invalid input, one verdict: exactly NULL, and nothing called.
 *
 * The second half is what stops these being smoke tests inverted.  "Returned
 * NULL" alone would also be satisfied by an implementation that raised an
 * error through a half-built handle first, or that resolved and invoked a
 * callback before noticing the input was unusable; requiring silence as well
 * pins the contract to "rejected, with no side effect".
 *
 * `core` is a parameter rather than hard-wired because one of the six cases is
 * precisely a NULL core, and a checker that could not express that would need
 * a second copy of itself.
 */
static int guard_expect_graceful_null(const char *label,
                                      const OSSL_CORE_HANDLE *core,
                                      const OSSL_DISPATCH *dispatch)
{
  int ret = 1, test;
  char text[GUARD_LABEL_MAX];
  struct proverr_functions_st *handle;

  mock_core_reset();

  handle = proverr_new_handle(core, dispatch);

  TEST_ASSERT_PTR_NULL(guard_label(text, sizeof(text), label,
                                   "handle is NULL"), handle);
  ret &= test;

  ret &= guard_no_callbacks_ran(label);

  /*
   * Unconditional, and correct even for the NULL this case expects: err.c:82
   * frees whatever it is given and free(NULL) is defined to do nothing.  It is
   * here so that a REGRESSION -- an implementation that started returning a
   * handle for an invalid input -- is reported by the assertion above rather
   * than compounded by a leak the assertion cannot see.
   */
  proverr_free_handle(handle);

  return ret;
}

/* A NULL core pointer.  Rejected by err.c:29-32 once err.c:26 is gone. */
static int test_ndebug_null_core(void)
{
  return guard_expect_graceful_null("ndebug: NULL core", NULL,
                                    mock_dispatch_complete);
}

/*
 * A NULL dispatch pointer.  Rejected by err.c:29-32 once err.c:27 is gone --
 * and it has to be, because err.c:34 would otherwise dereference it.
 */
static int test_ndebug_null_dispatch(void)
{
  return guard_expect_graceful_null("ndebug: NULL dispatch",
                                    &mock_core_primary, NULL);
}

/*
 * A well-formed but empty table: just the { 0, NULL } sentinel.  Distinct from
 * a NULL dispatch pointer, and it has to travel further to be rejected --
 * err.c:34 exits immediately, all three callbacks stay NULL, and err.c:51-54
 * is what turns that into a NULL return.
 */
static int test_ndebug_empty_table(void)
{
  return guard_expect_graceful_null("ndebug: empty table",
                                    &mock_core_primary,
                                    mock_dispatch_empty);
}

/*
 * Everything except OSSL_FUNC_CORE_NEW_ERROR, isolating the first disjunct of
 * err.c:51-54 -- the condition err.c:47 asserts in a default build.  Two
 * callbacks resolving correctly is not enough.
 */
static int test_ndebug_missing_new_error(void)
{
  return guard_expect_graceful_null("ndebug: table missing new_error",
                                    &mock_core_primary,
                                    mock_dispatch_no_new_error);
}

/*
 * Everything except OSSL_FUNC_CORE_SET_ERROR_DEBUG, isolating the second
 * disjunct of err.c:51-54 (err.c:48).  Testing all three separately is what
 * makes the disjunction itself falsifiable: an implementation that had
 * written && instead of || would still reject the empty table, and would be
 * caught only by a case where exactly one callback is missing.
 */
static int test_ndebug_missing_set_error_debug(void)
{
  return guard_expect_graceful_null("ndebug: table missing set_error_debug",
                                    &mock_core_primary,
                                    mock_dispatch_no_set_error_debug);
}

/*
 * Everything except OSSL_FUNC_CORE_VSET_ERROR, isolating the third disjunct of
 * err.c:51-54 (err.c:49).
 */
static int test_ndebug_missing_vset_error(void)
{
  return guard_expect_graceful_null("ndebug: table missing vset_error",
                                    &mock_core_primary,
                                    mock_dispatch_no_vset_error);
}

#else                           /* !LIBPROV_TEST_NDEBUG_VARIANT */

/*
 * DEFAULT VARIANT -- the paths that do NOT abort.
 *
 * Six inputs to proverr_new_handle() terminate this build with SIGABRT, and
 * none of them may be called from here: an abort inside the test process is
 * not a failing assertion, it is a dead test runner with no verdict at all.
 *
 *   proverr_new_handle(NULL, table)               aborts at err.c:26
 *   proverr_new_handle(&core, NULL)               aborts at err.c:27
 *   proverr_new_handle(&core, empty)              aborts at err.c:47
 *   proverr_new_handle(&core, no_new_error)       aborts at err.c:47
 *   proverr_new_handle(&core, no_set_error_debug) aborts at err.c:48
 *   proverr_new_handle(&core, no_vset_error)      aborts at err.c:49
 *
 * Both halves of that contract are asserted elsewhere: that each one really
 * does abort, with SIGABRT specifically rather than by any other kind of
 * failure, in tests/test_err_death.c, which forks a child per case and
 * inspects WIFSIGNALED / WTERMSIG in the parent; and that each one returns
 * NULL instead once NDEBUG has removed the assertions, in the
 * test_err_guards_ndebug target built from the #ifdef branch above.
 *
 * This branch is therefore left to assert what a default build can observe:
 * that a table resolving all three callbacks produces a working handle
 * whatever shape it arrives in, and that the two entry points which tolerate
 * NULL really do.
 */

/*
 * err.c's resolution loop (err.c:34-45) makes four promises, and every one of
 * them is silent -- no return value, no diagnostic, nothing a compiler could
 * check.  A provider's dispatch table comes from the core, so a loop that
 * mis-scans it fails at integration time in a way nothing in this repository
 * would otherwise catch.
 *
 * Each fixture below is the same complete set of three callbacks wrapped in
 * one awkward shape, so each must behave EXACTLY like the in-order table that
 * test_common_happy_path() already asserted:
 *
 *   shuffled        order independence.  Nothing promises a provider an
 *                   ordered table; ids arrive here as 7, 5, 6.
 *   unknown ids     tolerance.  The switch at err.c:35-45 has no default
 *                   label, so an unrecognised id must be skipped rather than
 *                   rejected.  Ids 8 and 9 are real adjacent core functions
 *                   and 9999 is outside the reserved range, and all three are
 *                   bound to the ALTERNATE new_error stub -- so "tolerated"
 *                   is not inferred from a non-NULL handle, it is proved by
 *                   that stub never running.
 *   duplicate ids   last occurrence wins.  Two entries claim
 *                   OSSL_FUNC_CORE_NEW_ERROR, the alternate stub first and
 *                   the primary last, and err.c:37 overwrites rather than
 *                   keeping the first.  Which of two equally valid callbacks
 *                   survived is unobservable except by calling it.
 *   after sentinel  the scan stops.  A fourth entry sits beyond { 0, NULL },
 *                   bound to the alternate stub, so a loop that tested the
 *                   sentinel one entry too late would resolve new_error to
 *                   it.
 *
 * The "alternate stub never ran" half of the last three is asserted inside
 * guard_raise_and_check(), which requires alt_new_error_calls to be zero on
 * every raise.
 */
static int test_default_dispatch_resolution(void)
{
  int ret = 1;

  ret &= guard_exercise_resolved_table("default: shuffled table",
                                       mock_dispatch_shuffled);
  ret &= guard_exercise_resolved_table("default: table with unknown ids",
                                       mock_dispatch_unknown_ids);
  ret &= guard_exercise_resolved_table("default: table with duplicate ids",
                                       mock_dispatch_duplicate_ids);
  ret &= guard_exercise_resolved_table("default: entries after the sentinel",
                                       mock_dispatch_after_sentinel);

  return ret;
}

/*
 * The two entry points that accept NULL in EVERY build, assertions or not.
 *
 * proverr_dup_handle() tests its argument with an ordinary condition rather
 * than an assertion -- err.c:70 reads "if (src != NULL && ...)" and there is
 * no assert(src != NULL) above it -- so a NULL source is a supported input
 * here and not an aborting one.  proverr_free_handle() is a bare free()
 * (err.c:82), and free(NULL) is defined to do nothing.  Both are therefore
 * safe to call from this branch, and both are worth pinning: they are the
 * cheapest assertions in the file and the most expensive to get wrong.
 *
 * Each is checked for silence as well as for its return value.  A duplication
 * that failed must not have raised anything through the handle it declined to
 * copy, and freeing must not report through the callbacks it is discarding.
 */
static int test_default_null_safe_entry_points(void)
{
  int ret = 1, test;
  struct proverr_functions_st *duplicate;

  mock_core_reset();
  duplicate = proverr_dup_handle(NULL);
  TEST_ASSERT_PTR_NULL("default: dup_handle(NULL) returns NULL", duplicate);
  ret &= test;
  ret &= guard_no_callbacks_ran("default: dup_handle(NULL)");
  /*
   * Unconditional and harmless when the expectation held, and the same
   * regression guard as in guard_expect_graceful_null(): if dup_handle() ever
   * starts allocating for a NULL source, the assertion above reports it and
   * this keeps the run leak-free while it does.
   */
  proverr_free_handle(duplicate);

  mock_core_reset();
  proverr_free_handle(NULL);
  ret &= guard_no_callbacks_ran("default: free_handle(NULL)");

  return ret;
}

#endif                          /* LIBPROV_TEST_NDEBUG_VARIANT */

/*
 * CLASS C -- GENUINE AMBIGUITY.  DELIBERATE NON-ASSERTION.  NOT A GAP.
 *
 * The observation: err.c guards its two early returns with DIFFERENT macros.
 * The first, at err.c:29-32, is wrapped in "#ifndef DEBUG"; the second, at
 * err.c:51-54, in "#ifdef NDEBUG".  NDEBUG is the standard macro <assert.h>
 * itself keys on.  DEBUG is a project-specific name that is never defined as a
 * preprocessor macro anywhere here: err.c:29 is the only place in any C source
 * or header that mentions it, and nothing in CMakeLists.txt or cmake/ passes
 * -DDEBUG.  (cmake/provider.cmake does use the token in MESSAGE(DEBUG ...)
 * calls, but that is CMake's own log-level keyword and has no bearing on the C
 * preprocessor.)
 *
 * Two readings are defensible, and nothing in err.c, include/prov/err.h or the
 * project's documentation settles which was meant:
 *
 *   (a) The asymmetry is INTENTIONAL.  err.c:29-32 is a caller-error backstop
 *       the author wanted present in ordinary builds and removable only by
 *       opting in to a project-specific DEBUG mode, one where an abort is
 *       preferred to a silent NULL.  err.c:51-54 is a release-only safety net
 *       that exists purely to replace assertions NDEBUG removed, so keying it
 *       to NDEBUG is precisely right.  Both spellings are then correct.
 *   (b) It is a TYPO.  Both blocks are recovery paths for the same class of
 *       invalid input, they sit twenty-two lines apart in the same function,
 *       and one says DEBUG where the other says NDEBUG.  They should agree,
 *       and the odd one out is a slip.
 *
 * THIS SUITE MAKES NO ASSERTION ABOUT WHICH MACRO SHOULD HAVE BEEN USED.  It
 * asserts only what each build variant makes REACHABLE, which is a question of
 * fact rather than of intent:
 *
 *                              err.c:29-32                err.c:51-54
 *   default build     compiled IN, UNREACHABLE    compiled OUT
 *   (NDEBUG unset)    -- dominated by the         -- the assertions at
 *                     assertions at err.c:26      err.c:47-49 abort first
 *                     and err.c:27, which abort   and it is not even
 *                     before it can run           present in the object
 *
 *   NDEBUG build      compiled IN, REACHABLE      compiled IN, REACHABLE
 *                     -- the assertions are       -- the assertions are
 *                     gone, so this block is      gone, so this block is
 *                     what returns NULL for a     what returns NULL for the
 *                     NULL core or a NULL         empty table and for each
 *                     dispatch pointer            single-missing-callback
 *                                                 table
 *
 * Read that table carefully: err.c:29-32 is compiled IN under BOTH variants,
 * because its guard is DEBUG and DEBUG is never defined here.  What changes
 * between the variants is not whether it is present but whether it can be
 * reached.  "Compiled out under NDEBUG" is the exact opposite of the truth and
 * would mislead the next reader into thinking the first two NULL returns come
 * from somewhere else.
 *
 * One consequence of the asymmetry, recorded as an observation and NOT as an
 * assertion: a build defining BOTH DEBUG and NDEBUG would remove the
 * assertions at err.c:26-27 and the block at err.c:29-32 together, leaving a
 * NULL dispatch pointer to reach err.c:34 and be dereferenced.  No target in
 * this suite is configured that way, and whether that combination ought to be
 * rejected is exactly what readings (a) and (b) disagree about.
 *
 * DO NOT "COMPLETE" THIS by asserting whatever the code currently emits: an
 * assertion here would enshrine one reading as the contract on no authority
 * but the implementation's.  DO NOT "FIX" err.c either -- source changes are
 * permitted only to repair a genuine bug, no bug was found in err.c, and an
 * asymmetry with a defensible intentional reading is not one.
 */

int main(void)
{
  int ret = 1;
  int status;

  /*
   * Informational only, and never the sole output of a run: it names which of
   * the two contracts the assertion lines below belong to, so a `ctest -V` log
   * for one variant cannot be confused for the other.
   */
  printf("test_err_guards: variant = %s\n", GUARD_VARIANT_NAME);

  ret &= test_common_happy_path();

#ifdef LIBPROV_TEST_NDEBUG_VARIANT
  ret &= test_ndebug_null_core();
  ret &= test_ndebug_null_dispatch();
  ret &= test_ndebug_empty_table();
  ret &= test_ndebug_missing_new_error();
  ret &= test_ndebug_missing_set_error_debug();
  ret &= test_ndebug_missing_vset_error();
#else
  ret &= test_default_dispatch_resolution();
  ret &= test_default_null_safe_entry_points();
#endif

  /*
   * TEST_REPORT() prints the one-line summary and yields the status testutil.h
   * derives from its own counters: non-zero if anything mismatched OR if
   * nothing was asserted at all.  That second clause is what makes a variant
   * whose body compiled away to nothing FAIL rather than pass silently, and it
   * is why the exit status is taken from the counters rather than from having
   * reached the end of main().
   *
   * The accumulated `ret` is folded in as well, so the status is non-zero if
   * EITHER the counters or the per-case verdicts say so.  Belt and braces on
   * purpose: the two are computed independently, and a run in which they
   * disagreed would be a defect in the harness that should fail loudly rather
   * than be resolved in favour of whichever one said "pass".
   */
  status = TEST_REPORT("test_err_guards");

  return status != 0 || ret != 1 ? 1 : 0;
}
