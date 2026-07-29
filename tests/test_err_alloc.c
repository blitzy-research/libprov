/* CC0 license applied, see LICENSE */

/*
 * err.c's out-of-memory contract, proved with deterministic
 * allocation-failure injection.
 *
 * WHY THIS FILE EXISTS.  err.c allocates in exactly two places: malloc at
 * err.c:56 inside proverr_new_handle(), and malloc at err.c:71 inside
 * proverr_dup_handle().  Both are written so that a failed allocation yields
 * NULL -- err.c:56 leaves `handle` at the NULL initialiser of err.c:24 and
 * falls through to `return handle;` at err.c:62, and err.c:71 leaves `dst` at
 * the NULL initialiser of err.c:68 and falls through to `return dst;` at
 * err.c:77.  Neither branch is reachable from any INPUT, so without fault
 * injection both are invisible to a test suite, and an out-of-memory path
 * that is never exercised is precisely where a missing NULL check becomes a
 * NULL dereference in production.  This file makes both branches reachable
 * and pins what they return.  It repairs nothing: no defect was found in
 * err.c, both allocation sites already behave, and modifying a non-test
 * source without a genuine defect is forbidden.
 *
 * NO USER-SPECIFIED RULES EXIST for this project -- the rules facility
 * reports none -- so nothing here is written to satisfy one.  The binding
 * constraints are the ones from the request itself: no non-test source may be
 * modified without a genuine defect; no test may merely check that code runs
 * without error; OpenSSL types must be constructed or mocked rather than
 * pulled from a running provider or from libcrypto; every test must pass
 * against the code as it stands; and every test must run independently and in
 * parallel.  Each is honoured below and the honouring is pointed out where it
 * happens.
 *
 * HOW THIS TARGET IS BUILT.  The test registration links the libprov LIBRARY
 * and adds one link option, "-Wl,--wrap=malloc"; it does NOT compile a
 * private copy of err.c.  That works because --wrap operates at LINK time on
 * undefined references: err.c.o inside libprov.a refers to `malloc`, so the
 * linker rewrites those references -- err.c:56 and err.c:71 included -- to
 * __wrap_malloc below without err.c being recompiled or even aware.  --wrap
 * is a GNU-ld feature, which is why the registration is feature-guarded: on a
 * host whose linker lacks it this target is NOT REGISTERED AT ALL, rather
 * than registered and skipped or registered and allowed to fail, so
 * configuration still succeeds and every other target runs normally.
 *
 * THE LINK OPTION CANNOT GO MISSING UNNOTICED, which matters because every
 * assertion here would turn vacuous if it did -- an unwrapped malloc never
 * fails on a machine with memory to spare, so each "returns NULL" would simply
 * stop being true and each "succeeds" would pass for no reason.  It cannot
 * happen: __real_malloc is a name only the linker's --wrap creates, so a build
 * of this file without the option fails to LINK with an undefined reference to
 * it rather than producing a binary that quietly proves nothing.  Verified by
 * omitting the option deliberately.
 *
 * NO ABORTING INPUT LIVES HERE.  This target is built with the project's
 * DEFAULT flags, so the five assert() calls in err.c are live: err.c:26 and
 * err.c:27 abort on a NULL core or a NULL dispatch table, and err.c:47 to
 * err.c:49 abort on any table that fails to supply all three callbacks.  Every
 * call below therefore passes &mock_core_primary together with
 * mock_dispatch_complete -- the one table that resolves all three -- and no
 * other table is touched.  Aborting inputs, and the graceful NULL returns
 * their #ifdef NDEBUG counterparts at err.c:51-54 produce, belong to
 * test_err_death.c and test_err_guards.c; duplicating them here would abort
 * this process and take the rest of the cases with it.
 *
 * THE COUNTDOWN INTERPOSER.  __wrap_malloc() fails the next N allocations and
 * then delegates to __real_malloc(), the original that the linker supplies.
 * A countdown rather than a boolean because a case has to be able to say
 * "fail exactly the next one" and then observe that the next-but-one
 * succeeded, which is what separates a real out-of-memory return from an
 * interposer that got stuck.  The countdown, both of its counters and all
 * three helpers have internal linkage and stay in THIS translation unit:
 * allocator interposition perturbs a whole process, so promoting it into
 * tests/testutil.h or tests/mock_core.h would silently change how every
 * sibling target allocates.  Confining it to one executable is what keeps the
 * suite safe to run with `ctest -j N`.
 *
 * <stdlib.h> IS MANDATORY, not stylistic.  With an interposer in the picture,
 * an implicit declaration of malloc collides with the compiler's built-in and
 * is diagnosed as an incompatible declaration rather than merely warned
 * about, so the include below is load-bearing.
 *
 * ARM LATE, DISARM EARLY.  Anything else in the process that allocates would
 * consume the countdown and make the outcome depend on timing rather than on
 * err.c.  stdio is the realistic offender: it buffers on first use.  Two
 * measures remove the hazard.  main() prints and flushes once BEFORE any case
 * runs, so the buffer already exists; and every case arms IMMEDIATELY before
 * the call under test and disarms IMMEDIATELY after, storing the values to be
 * asserted first and printing nothing at all in between -- which is also why
 * the assertions, all of which print, are written after the disarm rather
 * than around the call.  Measured on this toolchain, glibc's own internal
 * allocations bypass __wrap_malloc entirely, because --wrap only rewrites
 * references in the objects being linked and not calls made inside libc.so;
 * that is a property of one C library, though, not a guarantee, so the
 * discipline is kept regardless and every exact-count assertion is confined
 * to the armed window, which contains one library call and nothing else.
 *
 * THE SAME FLUSHES EARN THEIR KEEP TWICE OVER.  This file exists to drive
 * err.c into failure modes, so a fault somewhere in the run is a realistic
 * outcome -- and stdout redirected to a file or a pipe, which is how CTest
 * runs it, is FULLY buffered, so a fault would discard everything stdio had
 * not yet written and take the diagnosis with it.  Every point where this file
 * is about to hand a handle back to the library -- each armed window, and each
 * raise -- is therefore preceded by a flush, and each case flushes again when
 * it ends.  Evidence loss is thereby bounded to the case that faulted, which
 * was measured: a deliberately broken duplication reported one clean failure
 * line where the unflushed version reported only a signal.
 *
 * THE HANDLE IS OPAQUE.  struct proverr_functions_st is defined only at
 * err.c:7-12; include/prov/err.h:58 merely forward-declares it, so no member
 * can be read from here and no assertion may try.  "The source handle
 * survived a failed duplication" is therefore proved BEHAVIOURALLY: a raise
 * through it must still reach all three recording stubs, in order, carrying
 * the very core pointer the handle was built with.  Pointer identity, not
 * value equality, is the right claim there, because err.c:57 stores the
 * pointer and err.c:87, err.c:93 and err.c:102 forward it unchanged.
 *
 * NOTHING HERE IS A SMOKE TEST.  Every case asserts a specific value:
 * exactly NULL, exactly non-NULL, distinctness of two pointers, exact
 * invocation counts, the exact recorded call order, and the exact number of
 * allocations the interposer saw.  The process exit status is derived from
 * the assertion counters in tests/testutil.h, so reaching the end of main()
 * cannot manufacture a pass.  Failure paths carry positive assertions too:
 * on every forced failure the negative side-effect invariant -- that not one
 * callback ran -- is asserted rather than assumed.
 *
 * NO LIBCRYPTO AND NO RUNNING PROVIDER.  The core handle, the stubs and the
 * dispatch table all come from tests/mock_core.h, which builds them by hand;
 * <openssl/params.h> is never included and no libcrypto entry point is ever
 * called.  The accessors err.c uses to unpack a dispatch entry expand to
 * static inline definitions, so nothing has to be linked for them either: a
 * linked test binary depends on the vDSO, libc and the loader alone.
 *
 * ON SANITIZERS.  AddressSanitizer supplies its own malloc, so the
 * interaction with --wrap has to be verified rather than assumed on any given
 * toolchain.  It is verified: under -fsanitize=address,undefined the linker
 * still rewrites err.c's references to __wrap_malloc, __real_malloc still
 * resolves to the (now ASan-provided) allocator, and every assertion below
 * holds unchanged with no leak reported for the handles allocated here.  Were
 * that ever to stop being true on some other toolchain, the non-sanitized run
 * is the authoritative one and no assertion here may be weakened to make a
 * sanitized build pass.
 */

/*
 * "prov/err.h" is included EXPLICITLY even though tests/mock_core.h already
 * pulls it in: this file calls proverr_new_handle(), proverr_dup_handle(),
 * proverr_free_handle() and ERR_raise() directly, so it declares its own
 * dependency on the header under test rather than inheriting one.  The header
 * has no include guard -- by design, since it declares functions and defines
 * macros idempotently -- so a build that adds -Wredundant-decls, an option in
 * neither -Wall nor -Wextra nor -pedantic, reports the second set of
 * declarations.  That is a property of include/prov/err.h, reproducible from
 * two #include lines and no test code at all, and include/prov/err.h may not
 * be modified from here; do not "fix" it by deleting the include below, which
 * would only hide this file's dependency behind another header's.
 */
#include "testutil.h"
#include "mock_core.h"
#include "prov/err.h"
#include <stdlib.h>             /* MANDATORY: see the note above */
#include <stddef.h>
#include <stdio.h>              /* printf/fflush for the stdio warm-up */

/*
 * ---------------------------------------------------------------------------
 * The interposer.
 * ---------------------------------------------------------------------------
 */

/*
 * Supplied by the linker in response to "-Wl,--wrap=malloc"; it is not
 * declared by any header, so the declaration has to be written out here, and
 * with exactly malloc's own signature: __real_malloc IS malloc under another
 * name, and a mismatched declaration would be undefined behaviour rather than
 * a diagnostic.  __wrap_malloc is declared before it is defined so the
 * definition is checked against a prototype; it must have EXTERNAL linkage,
 * because the linker binds it by symbol name and a static definition would
 * leave the rewritten references unresolved.
 */
void *__real_malloc(size_t size);
void *__wrap_malloc(size_t size);

/*
 * How many of the next allocations to fail.  Zero -- the initial state, and
 * the state every case is left in -- means pure pass-through.
 */
static unsigned long alloc_fail_countdown = 0;

/*
 * Every entry into the interposer, and every entry that returned NULL because
 * the countdown was armed.  Cases read these as DELTAS across the armed
 * window, which is what turns "proverr_new_handle() returned NULL" into "the
 * interposer intercepted exactly one allocation and failed it, and that is
 * why proverr_new_handle() returned NULL".  Without them a NULL return could
 * be passing for an entirely different reason -- a linker that silently
 * dropped the --wrap, say -- and the case would never notice.
 */
static unsigned long alloc_intercepted = 0;
static unsigned long alloc_forced = 0;

void *__wrap_malloc(size_t size)
{
  alloc_intercepted++;

  if (alloc_fail_countdown > 0) {
    alloc_fail_countdown--;
    alloc_forced++;
    return NULL;
  }

  return __real_malloc(size);
}

/*
 * Fail the next `count` allocations.  Call IMMEDIATELY before the call under
 * test, with nothing that prints in between.
 */
static void arm_alloc_failures(unsigned long count)
{
  alloc_fail_countdown = count;
}

/*
 * Return to pass-through.  Called at the end of every armed window, including
 * the windows where the countdown is expected to have been consumed already,
 * so that no leftover arming can reach a later case in this executable or
 * make one case's outcome depend on another's.
 */
static void disarm_alloc_failures(void)
{
  alloc_fail_countdown = 0;
}

/*
 * What is left of the countdown.  Read BEFORE disarming: a case that armed
 * one failure and finds nothing pending has proved the allocation it was
 * aiming at really happened.
 */
static unsigned long alloc_failures_pending(void)
{
  return alloc_fail_countdown;
}

/*
 * ---------------------------------------------------------------------------
 * Shared assertion helpers.
 * ---------------------------------------------------------------------------
 */

/*
 * Compose "<case>: <what>" into caller-supplied storage.  The two helpers
 * below are each used from several cases, and a fixed label would leave a
 * CTest log unable to say which case failed; the __FILE__ and __LINE__ on a
 * failing line point at the helper, so the label is what has to carry the
 * case identity.  snprintf() truncates rather than overruns and cannot
 * truncate at these lengths anyway, and it never runs inside an armed window.
 */
static const char *label_for(char *buffer, size_t capacity,
                             const char *casename, const char *what)
{
  snprintf(buffer, capacity, "%s: %s", casename, what);
  return buffer;
}

/*
 * "Not one callback ran."  err.c's two allocating functions only RESOLVE and
 * STORE callbacks -- the scan at err.c:34-45, the stores at err.c:56-61 and
 * the copies at err.c:72-75 -- and neither ever calls one.  Zero invocations
 * is therefore the negative side-effect invariant of a forced failure, where
 * nothing at all should have happened, and equally of a SUCCESS, where
 * resolving a callback must not be mistaken for invoking it.  All four
 * counters are checked, the alternate new_error stub included, so a
 * misresolved table cannot hide behind a zero on the primary; seq_len covers
 * the recorder itself, and seq_dropped proves the recorder did not overflow
 * and quietly lose evidence.
 */
static int assert_no_callbacks(const char *casename)
{
  char label[160];
  int ok = 1;

  TEST_ASSERT_UINT_EQ(label_for(label, sizeof(label), casename,
                                "new_error was not called"),
                      mock_core_obs.new_error_calls, 0UL);
  ok &= test;

  TEST_ASSERT_UINT_EQ(label_for(label, sizeof(label), casename,
                                "alt_new_error was not called"),
                      mock_core_obs.alt_new_error_calls, 0UL);
  ok &= test;

  TEST_ASSERT_UINT_EQ(label_for(label, sizeof(label), casename,
                                "set_error_debug was not called"),
                      mock_core_obs.set_error_debug_calls, 0UL);
  ok &= test;

  TEST_ASSERT_UINT_EQ(label_for(label, sizeof(label), casename,
                                "vset_error was not called"),
                      mock_core_obs.vset_error_calls, 0UL);
  ok &= test;

  TEST_ASSERT_SIZE_EQ(label_for(label, sizeof(label), casename,
                                "call sequence is empty"),
                      mock_core_obs.seq_len, (size_t)0);
  ok &= test;

  TEST_ASSERT_UINT_EQ(label_for(label, sizeof(label), casename,
                                "recorder dropped nothing"),
                      mock_core_obs.seq_dropped, 0UL);
  ok &= test;

  return ok;
}

/*
 * "A raise through this handle reached all three stubs, in order, carrying the
 * core the handle was built with."  This is the behavioural stand-in for
 * reading the handle's members, which the opacity noted at the top of the file
 * rules out, and it is the only way to say that a handle is intact rather than
 * merely non-NULL.
 *
 * The claim is deliberately over-determined: the recorded ORDER pins the
 * comma-expression contract of include/prov/err.h:49-52, the three counts pin
 * "exactly once each" so a duplicated forward would fail, the three core
 * pointers pin the pass-through of err.c:87, err.c:93 and err.c:102 by
 * IDENTITY, the reason pins the value err.c:102 forwards, and fmt is NULL
 * because ERR_raise() supplies NULL for it at include/prov/err.h:47.  A raise
 * that lost any one of those would still "run without error", which is exactly
 * the kind of pass this suite is not allowed to award.
 *
 * Reading seq[1] and seq[2] is in bounds whatever happened: mock_core_reset()
 * zeroes the whole 32-entry recorder, so a short sequence reports the ordinal
 * 0 -- an ordinal no stub uses -- instead of reading uninitialised storage.
 */
static int assert_raise_observed(const char *casename,
                                 const OSSL_CORE_HANDLE *expected_core,
                                 uint32_t expected_reason)
{
  char label[160];
  int ok = 1;

  TEST_ASSERT_SIZE_EQ(label_for(label, sizeof(label), casename,
                                "three stubs ran"),
                      mock_core_obs.seq_len, (size_t)3);
  ok &= test;

  TEST_ASSERT_INT_EQ(label_for(label, sizeof(label), casename,
                               "first stub was new_error"),
                     mock_core_obs.seq[0], MOCK_CORE_ORD_NEW_ERROR);
  ok &= test;

  TEST_ASSERT_INT_EQ(label_for(label, sizeof(label), casename,
                               "second stub was set_error_debug"),
                     mock_core_obs.seq[1], MOCK_CORE_ORD_SET_ERROR_DEBUG);
  ok &= test;

  TEST_ASSERT_INT_EQ(label_for(label, sizeof(label), casename,
                               "third stub was vset_error"),
                     mock_core_obs.seq[2], MOCK_CORE_ORD_VSET_ERROR);
  ok &= test;

  TEST_ASSERT_UINT_EQ(label_for(label, sizeof(label), casename,
                                "new_error ran exactly once"),
                      mock_core_obs.new_error_calls, 1UL);
  ok &= test;

  TEST_ASSERT_UINT_EQ(label_for(label, sizeof(label), casename,
                                "set_error_debug ran exactly once"),
                      mock_core_obs.set_error_debug_calls, 1UL);
  ok &= test;

  TEST_ASSERT_UINT_EQ(label_for(label, sizeof(label), casename,
                                "vset_error ran exactly once"),
                      mock_core_obs.vset_error_calls, 1UL);
  ok &= test;

  TEST_ASSERT_UINT_EQ(label_for(label, sizeof(label), casename,
                                "alt_new_error never ran"),
                      mock_core_obs.alt_new_error_calls, 0UL);
  ok &= test;

  TEST_ASSERT_PTR_EQ(label_for(label, sizeof(label), casename,
                               "new_error got the stored core"),
                     mock_core_obs.new_error_core, expected_core);
  ok &= test;

  TEST_ASSERT_PTR_EQ(label_for(label, sizeof(label), casename,
                               "set_error_debug got the stored core"),
                     mock_core_obs.set_error_debug_core, expected_core);
  ok &= test;

  TEST_ASSERT_PTR_EQ(label_for(label, sizeof(label), casename,
                               "vset_error got the stored core"),
                     mock_core_obs.vset_error_core, expected_core);
  ok &= test;

  TEST_ASSERT_UINT_EQ(label_for(label, sizeof(label), casename,
                                "vset_error got the raised reason"),
                      mock_core_obs.reason, expected_reason);
  ok &= test;

  TEST_ASSERT_PTR_NULL(label_for(label, sizeof(label), casename,
                                 "ERR_raise supplied a NULL format"),
                       mock_core_obs.fmt_ptr);
  ok &= test;

  TEST_ASSERT_UINT_EQ(label_for(label, sizeof(label), casename,
                                "recorder dropped nothing"),
                      mock_core_obs.seq_dropped, 0UL);
  ok &= test;

  return ok;
}

/*
 * ---------------------------------------------------------------------------
 * A-1, A-2: the malloc at err.c:56, failed and then allowed to succeed.
 * ---------------------------------------------------------------------------
 *
 * Self-contained on purpose.  The failure case needs a handle only as a
 * RESULT, and the recovery case produces one, so nothing has to be carried in
 * from another case or handed out to one: each case resets the observation
 * state itself, owns whatever it allocates, frees it, and leaves the allocator
 * disarmed.  Independence is then structural rather than a convention the next
 * reader has to trust, which is what makes the whole file safe under
 * `ctest -j N` and safe to run a single case at a time.
 */
static int test_new_handle_alloc_failure(void)
{
  struct proverr_functions_st *handle;
  unsigned long intercepted_before;
  unsigned long forced_before;
  unsigned long pending_after;
  int ok = 1;

  /*
   * A-1.  Fail the one allocation proverr_new_handle() makes and the function
   * must yield NULL: err.c:56 leaves `handle` at the err.c:24 initialiser and
   * err.c:62 returns it.  The core and the table are both valid, so none of
   * the assertions at err.c:26, err.c:27 or err.c:47-49 is in play and this
   * really is the allocation branch and not an aborting input in disguise.
   */
  mock_core_reset();
  intercepted_before = alloc_intercepted;
  forced_before = alloc_forced;

  /* Settle stdio before arming; nothing prints until after the disarm. */
  fflush(stdout);

  arm_alloc_failures(1);
  handle = proverr_new_handle(&mock_core_primary, mock_dispatch_complete);
  pending_after = alloc_failures_pending();
  disarm_alloc_failures();

  TEST_ASSERT_PTR_NULL("A-1 new_handle returns NULL when err.c:56 fails",
                       handle);
  ok &= test;

  /*
   * The three assertions that stop A-1 from passing for the wrong reason.  One
   * allocation was seen, it was the one that was failed, and the countdown was
   * fully consumed -- so proverr_new_handle() really did reach err.c:56 and
   * really did get NULL back, rather than the interposer having been dropped
   * by the linker or the countdown having been eaten by something else.
   */
  TEST_ASSERT_UINT_EQ("A-1 exactly one allocation was intercepted",
                      alloc_intercepted - intercepted_before, 1UL);
  ok &= test;

  TEST_ASSERT_UINT_EQ("A-1 exactly one allocation was forced to fail",
                      alloc_forced - forced_before, 1UL);
  ok &= test;

  TEST_ASSERT_UINT_EQ("A-1 the armed countdown was fully consumed",
                      pending_after, 0UL);
  ok &= test;

  ok &= assert_no_callbacks("A-1");

  /*
   * A-2.  With the allocator restored the very same call must succeed, which
   * is what proves the interposer is a switch and not a one-way door: an
   * interposer that stayed poisoned would make every later case vacuous, and
   * A-3's NULL in particular would then mean nothing at all.
   */
  mock_core_reset();
  intercepted_before = alloc_intercepted;
  forced_before = alloc_forced;

  fflush(stdout);

  handle = proverr_new_handle(&mock_core_primary, mock_dispatch_complete);
  pending_after = alloc_failures_pending();

  TEST_ASSERT_PTR_NOT_NULL("A-2 new_handle succeeds once the allocator is"
                           " restored", handle);
  ok &= test;

  TEST_ASSERT_UINT_EQ("A-2 exactly one allocation was intercepted",
                      alloc_intercepted - intercepted_before, 1UL);
  ok &= test;

  TEST_ASSERT_UINT_EQ("A-2 no allocation was forced to fail",
                      alloc_forced - forced_before, 0UL);
  ok &= test;

  TEST_ASSERT_UINT_EQ("A-2 the allocator was left disarmed", pending_after,
                      0UL);
  ok &= test;

  /*
   * Resolving the three callbacks (err.c:34-45) and storing them
   * (err.c:56-61) must not INVOKE any of them.  Cheap to assert, and a
   * constructor that raised an error of its own would be a real defect.
   */
  ok &= assert_no_callbacks("A-2");

  proverr_free_handle(handle);

  fflush(stdout);

  return ok;
}

/*
 * ---------------------------------------------------------------------------
 * A-3 to A-7: the malloc at err.c:71, and what a failed duplication must NOT
 * do to its source.
 * ---------------------------------------------------------------------------
 *
 * proverr_dup_handle() is a shallow copy behind a short-circuit guard
 * (err.c:69-78): `src != NULL && (dst = malloc(...)) != NULL` means the
 * allocation is only attempted for a non-NULL source, and the four member
 * copies at err.c:72-75 happen only once that allocation has succeeded.  So a
 * forced failure must return NULL, must leave the source completely alone --
 * there is nothing in the function that could touch it, and this is where that
 * is proved rather than asserted by inspection -- and must not stop a later
 * duplication from working.
 */
static int test_dup_handle_alloc_failure(void)
{
  struct proverr_functions_st *source;
  struct proverr_functions_st *copy;
  unsigned long intercepted_before;
  unsigned long forced_before;
  unsigned long pending_after;
  int ok = 1;

  /*
   * The source handle, built with the allocator in pass-through.  Asserted
   * non-NULL rather than assumed: every case below reads through it, so a
   * silent NULL here would turn the whole function into undefined behaviour
   * instead of a failure.
   */
  mock_core_reset();
  source = proverr_new_handle(&mock_core_primary, mock_dispatch_complete);

  TEST_ASSERT_PTR_NOT_NULL("A-3 source handle for the duplication cases",
                           source);
  ok &= test;

  if (source == NULL)
    return 0;

  /*
   * A-3.  Fail the one allocation proverr_dup_handle() makes and it must yield
   * NULL: err.c:71 leaves `dst` at the err.c:68 initialiser and err.c:77
   * returns it.
   */
  mock_core_reset();
  intercepted_before = alloc_intercepted;
  forced_before = alloc_forced;

  fflush(stdout);

  arm_alloc_failures(1);
  copy = proverr_dup_handle(source);
  pending_after = alloc_failures_pending();
  disarm_alloc_failures();

  TEST_ASSERT_PTR_NULL("A-3 dup_handle returns NULL when err.c:71 fails",
                       copy);
  ok &= test;

  TEST_ASSERT_UINT_EQ("A-3 exactly one allocation was intercepted",
                      alloc_intercepted - intercepted_before, 1UL);
  ok &= test;

  TEST_ASSERT_UINT_EQ("A-3 exactly one allocation was forced to fail",
                      alloc_forced - forced_before, 1UL);
  ok &= test;

  TEST_ASSERT_UINT_EQ("A-3 the armed countdown was fully consumed",
                      pending_after, 0UL);
  ok &= test;

  ok &= assert_no_callbacks("A-3");

  /*
   * A-4.  The source must be exactly as usable as it was before the failed
   * duplication.  Behavioural by necessity, per the opacity note at the top of
   * the file: a raise has to reach all three stubs, in order, carrying the
   * pointer to mock_core_primary that err.c:57 stored when the handle was
   * built.  A dup_handle() that wrote through its argument before allocating,
   * or that swapped the source's callbacks for the copy's, would fail here.
   */
  mock_core_reset();
  fflush(stdout);
  ERR_raise(source, 5u);

  ok &= assert_raise_observed("A-4 source survives a failed dup",
                              &mock_core_primary, 5u);

  /*
   * A-5.  With the allocator restored the duplication must succeed and must
   * hand back a DISTINCT object: err.c:71 allocates fresh storage, so a
   * dup_handle() that returned its own argument -- or cached one copy and
   * handed it out twice -- would give the caller an aliased handle and a
   * double free the first time both were released.
   */
  mock_core_reset();
  intercepted_before = alloc_intercepted;
  forced_before = alloc_forced;

  fflush(stdout);

  copy = proverr_dup_handle(source);
  pending_after = alloc_failures_pending();

  TEST_ASSERT_PTR_NOT_NULL("A-5 dup_handle succeeds once the allocator is"
                           " restored", copy);
  ok &= test;

  TEST_ASSERT_PTR_NE("A-5 the copy is a distinct object from its source", copy,
                     source);
  ok &= test;

  TEST_ASSERT_UINT_EQ("A-5 exactly one allocation was intercepted",
                      alloc_intercepted - intercepted_before, 1UL);
  ok &= test;

  TEST_ASSERT_UINT_EQ("A-5 no allocation was forced to fail",
                      alloc_forced - forced_before, 0UL);
  ok &= test;

  TEST_ASSERT_UINT_EQ("A-5 the allocator was left disarmed", pending_after,
                      0UL);
  ok &= test;

  ok &= assert_no_callbacks("A-5");

  /*
   * A-6 and A-7 are gated on the distinctness A-5 has just asserted, not
   * merely on the copy being non-NULL, and the guard is load-bearing rather
   * than decorative: A-7 frees the copy and then raises through the source,
   * which is defined only if the two really are separate objects.  Against a
   * library that aliased them the ungated version would free the source and
   * read it back -- and the resulting fault would discard whatever stdout had
   * buffered, hiding A-5's own self-diagnosing line, which is the diagnosis.
   * Verified: with this guard, a dup_handle() that returns its argument is
   * reported by exactly one clean failure line instead of a signal.
   */
  if (copy != NULL && copy != source) {
    /*
     * A-6.  The shallow copy at err.c:72-75 carried the wiring, not just the
     * storage: a raise through the copy must reach the same three stubs with
     * the same core pointer.  A different reason from A-4's, so a stale
     * observation cannot masquerade as a fresh one.
     */
    mock_core_reset();
    fflush(stdout);
    ERR_raise(copy, 6u);

    ok &= assert_raise_observed("A-6 raise through the copy",
                                &mock_core_primary, 6u);

    /*
     * A-7.  Independent lifetimes.  Freeing the copy (err.c:80-83) must not
     * disturb the source, which it cannot if the copy really was distinct
     * storage -- and if it were not, this raise would be reading freed memory,
     * which is why the case is worth its two lines.  A third distinct reason.
     */
    proverr_free_handle(copy);

    mock_core_reset();
    fflush(stdout);
    ERR_raise(source, 7u);

    ok &= assert_raise_observed("A-7 source outlives the freed copy",
                                &mock_core_primary, 7u);
  }

  proverr_free_handle(source);

  fflush(stdout);

  return ok;
}

/*
 * ---------------------------------------------------------------------------
 * A-8: the countdown decrements exactly once per intercepted allocation.
 * ---------------------------------------------------------------------------
 *
 * Everything above rests on the arming being PRECISE: "fail the next one" has
 * to mean the next one and not "fail from now on".  Arming two failures and
 * making three identical calls settles it in one shot.  If the arming were
 * sticky the third call would also return NULL; if the countdown decremented
 * more than once per allocation the second call would already have succeeded.
 * Only a countdown that decrements exactly once per intercepted allocation
 * produces NULL, NULL, non-NULL.
 */
static int test_countdown_precision(void)
{
  struct proverr_functions_st *first;
  struct proverr_functions_st *second;
  struct proverr_functions_st *third;
  unsigned long intercepted_before;
  unsigned long forced_before;
  unsigned long pending_after_two;
  int ok = 1;

  mock_core_reset();
  intercepted_before = alloc_intercepted;
  forced_before = alloc_forced;

  fflush(stdout);

  arm_alloc_failures(2);
  first = proverr_new_handle(&mock_core_primary, mock_dispatch_complete);
  second = proverr_new_handle(&mock_core_primary, mock_dispatch_complete);
  pending_after_two = alloc_failures_pending();
  third = proverr_new_handle(&mock_core_primary, mock_dispatch_complete);
  disarm_alloc_failures();

  TEST_ASSERT_PTR_NULL("A-8 the first of two armed failures returns NULL",
                       first);
  ok &= test;

  TEST_ASSERT_PTR_NULL("A-8 the second of two armed failures returns NULL",
                       second);
  ok &= test;

  TEST_ASSERT_UINT_EQ("A-8 both armed failures were consumed by two calls",
                      pending_after_two, 0UL);
  ok &= test;

  TEST_ASSERT_PTR_NOT_NULL("A-8 the third call succeeds, so the arming was not"
                           " sticky", third);
  ok &= test;

  TEST_ASSERT_UINT_EQ("A-8 three calls intercepted three allocations",
                      alloc_intercepted - intercepted_before, 3UL);
  ok &= test;

  TEST_ASSERT_UINT_EQ("A-8 exactly two allocations were forced to fail",
                      alloc_forced - forced_before, 2UL);
  ok &= test;

  ok &= assert_no_callbacks("A-8");

  proverr_free_handle(third);

  fflush(stdout);

  return ok;
}

int main(void)
{
  int cases = 1;
  int status;

  /*
   * The stdio warm-up.  Printing and flushing once here, before any case can
   * arm the countdown, means the buffers stdio allocates on first use are
   * already in place; see the "arm late, disarm early" note at the top of the
   * file for why a buffer allocated at the wrong moment would make this suite
   * non-deterministic.
   */
  printf("test_err_alloc: err.c out-of-memory contract"
         " -- malloc at err.c:56 and err.c:71\n");
  fflush(stdout);

  cases &= test_new_handle_alloc_failure();
  cases &= test_dup_handle_alloc_failure();
  cases &= test_countdown_precision();

  /*
   * The engagement diagnostic.  Deliberately a "greater than zero" and never a
   * primary assertion: an exact total would be brittle, since it would depend
   * on which allocations a given C library happens to route through the
   * rewritten references.  The per-case delta assertions are where precision
   * lives.  What this one adds is a single unmistakable line in the log when
   * the interposer was never entered at all -- a linker that quietly ignored
   * --wrap, say -- so that failure is diagnosed rather than merely observed as
   * a pile of unexpected non-NULL returns.  The totals are printed first
   * because TEST_ASSERT() can only echo the source text of its expression, and
   * whoever is reading this log after a link-configuration accident wants the
   * numbers themselves.
   */
  printf("interposer totals: %lu allocations intercepted, %lu forced to"
         " fail\n", alloc_intercepted, alloc_forced);
  TEST_ASSERT(alloc_intercepted > 0UL);
  cases &= test;

  /*
   * The allocator must be in pass-through when this executable ends, exactly
   * as it was when it started.  There is no later case to protect here, so
   * this asserts the file's own hygiene rule -- every arm is matched by a
   * disarm -- as a value rather than leaving it to a reader's grep.
   */
  TEST_ASSERT_UINT_EQ("the allocator was left in pass-through",
                      alloc_failures_pending(), 0UL);
  cases &= test;

  /*
   * The exit status.  TEST_REPORT() derives it from the assertion counters, so
   * a run that asserted nothing fails and reaching this line cannot
   * manufacture a pass; `cases` is folded in as well so that a case which
   * returned failure without recording a mismatch could not slip through
   * either.  Neither is redundant, and the stricter of the two always wins.
   */
  status = TEST_REPORT("test_err_alloc");

  return status != 0 || cases == 0 ? 1 : 0;
}

