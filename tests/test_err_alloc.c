/* CC0 license applied, see LICENSE */

/*
 * err.c's out-of-memory contract, proved with deterministic allocation-failure
 * injection.
 *
 * WHY THIS FILE EXISTS.  err.c allocates in exactly two places: malloc at
 * err.c:56 inside proverr_new_handle(), and malloc at err.c:71 inside
 * proverr_dup_handle().  Both are written so that a failed allocation yields
 * NULL -- err.c:56 leaves `handle` at the NULL initialiser of err.c:24 and
 * falls through to `return handle;` at err.c:62, and err.c:71 leaves `dst` at
 * the NULL initialiser of err.c:68 and falls through to `return dst;` at
 * err.c:77.  Neither branch is reachable from any INPUT, so without fault
 * injection both are invisible to a test suite -- and an out-of-memory path
 * that is never exercised is precisely where a missing NULL check becomes a
 * NULL dereference in production.  This file makes both branches reachable and
 * pins what they return.  It repairs nothing: no defect was found in err.c,
 * and modifying a non-test source without a genuine defect is forbidden.
 *
 * WHY THE free IS WRAPPED TOO, and why that is not scope creep.  err.c:82 is a
 * bare free(handle), and a bare free is INVISIBLE: nothing a caller can
 * observe distinguishes proverr_free_handle() from a function that does
 * nothing whatsoever.  Without interposition, replacing that body with a no-op
 * leaves every callback-silence check, every duplicate-lifetime flow and every
 * other target in the suite passing while a live handle is never released --
 * which makes "the valid-handle half" of any free test a no-crash surrogate
 * rather than an assertion.  --wrap=free closes that hole by turning the freed
 * POINTER, the call COUNT and the balance between allocations and releases
 * into values this file can compare, so A-9 to A-12 below assert deallocation
 * positively.  err.c:82 is a real call site in the code under test, which is
 * what separates this from wrapping for its own sake: calloc and realloc stay
 * unwrapped precisely because err.c never calls them.
 *
 * HOW THIS TARGET IS BUILT.  The test registration links the libprov LIBRARY
 * and adds two link options, "-Wl,--wrap=malloc" and "-Wl,--wrap=free"; it
 * does NOT compile a private copy of err.c.  That works because --wrap
 * operates at LINK time on undefined references: err.c.o inside libprov.a
 * refers to `malloc` and to `free`, so the linker rewrites those references --
 * err.c:56, err.c:71 and err.c:82 included -- to the __wrap_ functions below
 * without err.c being recompiled or even aware.  --wrap is a GNU-ld feature,
 * which is why the registration is feature-guarded: on a host whose linker
 * lacks it this target is NOT REGISTERED AT ALL, rather than registered and
 * skipped or registered and allowed to fail, so configuration still succeeds
 * and every other target runs normally.
 *
 * THE LINK OPTIONS CANNOT GO MISSING UNNOTICED, which matters because every
 * assertion here would turn vacuous if they did -- an unwrapped malloc never
 * fails on a machine with memory to spare, so each "returns NULL" would simply
 * stop being true and each "succeeds" would pass for no reason, and an
 * unwrapped free would leave the release counters at zero so every
 * deallocation claim would silently stop being checked.  It cannot happen:
 * __real_malloc and __real_free are names only the linker's --wrap creates, so
 * a build of this file without the options fails to LINK with an undefined
 * reference to them rather than producing a binary that quietly proves
 * nothing.
 *
 * NO ABORTING INPUT LIVES HERE.  This target must be built with the project's
 * DEFAULT flags, which leaves the five assert() calls in err.c live: err.c:26
 * and err.c:27 abort on a NULL core or a NULL dispatch table, and err.c:47 to
 * err.c:49 abort on any table that fails to supply all three callbacks.  Every
 * call below therefore passes &mock_core_primary together with
 * mock_dispatch_complete -- the one table that resolves all three -- and no
 * other table is touched.  Aborting inputs, and the graceful NULL returns
 * their #ifdef NDEBUG counterparts at err.c:51-54 produce, belong to
 * test_err_death.c and test_err_guards.c; duplicating them here would abort
 * this process and take the rest of the cases with it.
 *
 * THE COUNTDOWN INTERPOSER.  __wrap_malloc() fails the next N allocations and
 * then delegates to __real_malloc(), the original the linker supplies.  A
 * countdown rather than a boolean because a case has to be able to say "fail
 * exactly the next one" and then observe that the next-but-one succeeded,
 * which is what separates a real out-of-memory return from an interposer that
 * got stuck.  The countdown, both of its counters and all three helpers have
 * internal linkage and stay in THIS translation unit: allocator interposition
 * perturbs a whole process, so promoting it into tests/testutil.h or
 * tests/mock_core.h would silently change how every sibling target allocates.
 * Confining it to one executable is what keeps the suite safe under `ctest -j
 * N`.
 *
 * <stdlib.h> IS MANDATORY, not stylistic.  With an interposer in the picture,
 * an implicit declaration of malloc collides with the compiler's built-in and
 * is diagnosed as an incompatible declaration rather than merely warned about.
 *
 * ARM LATE, DISARM EARLY.  Anything else in the process that allocates would
 * consume the countdown and make the outcome depend on timing rather than on
 * err.c.  stdio is the realistic offender, because it buffers on first use, so
 * main() prints and flushes once BEFORE any case runs to reduce that
 * interference.  The determinism itself comes from the WINDOW, not from the
 * warm-up: every case arms IMMEDIATELY before the call under test and disarms
 * IMMEDIATELY after, storing the values to be asserted first and printing
 * nothing at all in between -- which is also why the assertions, all of which
 * print, are written after the disarm rather than around the call.  Whether a
 * C library's own internal allocations reach __wrap_malloc is a property of
 * that library and not a guarantee (--wrap rewrites references only in the
 * objects being linked, not calls made inside libc), so the discipline is kept
 * regardless and every exact-count assertion is confined to the armed window,
 * which contains one library call and nothing else.
 *
 * THE SAME FLUSHES EARN THEIR KEEP TWICE OVER.  This file exists to drive
 * err.c into failure modes, so a fault somewhere in the run is a realistic
 * outcome -- and stdout redirected to a file or a pipe, which is how CTest
 * runs it, is FULLY buffered, so a fault would discard everything stdio had
 * not yet written and take the diagnosis with it.  Every point where this file
 * is about to hand a handle back to the library -- each armed window, and each
 * raise -- is therefore preceded by a flush, and each case flushes again when
 * it ends, which bounds evidence loss to the case that faulted.
 *
 * THE HANDLE IS OPAQUE.  struct proverr_functions_st is defined only at
 * err.c:7-12; include/prov/err.h:58 merely forward-declares it, so no member
 * can be read from here and no assertion may try.  "The source handle survived
 * a failed duplication" is therefore proved BEHAVIOURALLY: a raise through it
 * must still reach all three recording stubs, in order, carrying the very core
 * pointer the handle was built with.  Pointer identity, not value equality, is
 * the right claim there, because err.c:57 stores the pointer and err.c:87,
 * err.c:93 and err.c:102 forward it unchanged.
 *
 * NOTHING HERE IS A SMOKE TEST.  Every case asserts a specific value: exactly
 * NULL, exactly non-NULL, distinctness of two pointers, exact invocation
 * counts, the exact recorded call order, and the exact number of allocations
 * the interposer saw.  The process exit status is derived from the assertion
 * counters in tests/testutil.h, so reaching the end of main() cannot
 * manufacture a pass.  Failure paths carry positive assertions too: on every
 * forced failure the negative side-effect invariant -- that not one callback
 * ran -- is asserted rather than assumed.
 *
 * NO LIBCRYPTO AND NO RUNNING PROVIDER.  The core handle, the stubs and the
 * dispatch table all come from tests/mock_core.h, which builds them by hand;
 * <openssl/params.h> is never included and no libcrypto entry point is ever
 * called.  The accessors err.c uses to unpack a dispatch entry expand to
 * static inline definitions, so nothing has to be linked for them either.
 *
 * ON SANITIZERS.  AddressSanitizer supplies its own malloc, so the interaction
 * with --wrap has to be verified rather than assumed on any given toolchain:
 * the linker must still rewrite err.c's references to __wrap_malloc and
 * __real_malloc must still resolve to the sanitizer-provided allocator.  Where
 * that does not hold, the non-sanitized run is the authoritative one and no
 * assertion here may be weakened to make a sanitized build pass.
 */

#include "testutil.h"
#include "mock_core.h"
#include "prov/err.h"
#include <stdlib.h>             /* MANDATORY: see the note above */
#include <stddef.h>
#include <stdio.h>

/*
 * Supplied by the linker in response to "-Wl,--wrap=malloc" and
 * "-Wl,--wrap=free"; neither is declared by any header, so the declarations
 * have to be written out here, and with exactly the signatures of the
 * functions they stand in for: __real_malloc IS malloc under another name and
 * __real_free IS free, so a mismatched declaration would be undefined
 * behaviour rather than a diagnostic.  Each __wrap_ function is declared
 * before it is defined so the definition is checked against a prototype; both
 * must have EXTERNAL linkage, because the linker binds them by symbol name and
 * a static definition would leave the rewritten references unresolved.
 */
void *__real_malloc(size_t size);
void *__wrap_malloc(size_t size);
void __real_free(void *ptr);
void __wrap_free(void *ptr);

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

/*
 * Blocks the interposer actually handed back, counted only when
 * __real_malloc() returned non-NULL.  This is deliberately NOT derived as
 * `alloc_intercepted - alloc_forced`: that expression assumes the real
 * allocator never fails on its own, and an assumption is exactly what a
 * balance assertion must not rest on.  Counted directly, the figure is right
 * whether the NULL came from the countdown or from the system.
 */
static unsigned long alloc_supplied = 0;

/*
 * Deallocation observation state, and the whole reason free is wrapped.
 * err.c:82 is a bare free(handle) whose effect no caller can see, so these
 * three are the only place its occurrence becomes a value:
 *
 *   free_calls        every entry into the interposer, NULL argument included,
 *                     because err.c:80-83 has no NULL guard and the call is
 *                     therefore unconditional -- a fact worth pinning rather
 *                     than assuming;
 *   free_calls_null   the subset whose argument was NULL, which is what lets
 *                     the balance below ignore them without losing them;
 *   last_freed        the most recent argument, so a case can assert that the
 *                     pointer released was the very handle it passed in and
 *                     not some other block.  Held as const void * because it
 *                     is only ever compared, never dereferenced -- the block
 *                     is gone by the time any assertion reads it.
 */
static unsigned long free_calls = 0;
static unsigned long free_calls_null = 0;
static const void *last_freed = NULL;

void *__wrap_malloc(size_t size)
{
  void *block;

  alloc_intercepted++;

  if (alloc_fail_countdown > 0) {
    alloc_fail_countdown--;
    alloc_forced++;
    return NULL;
  }

  block = __real_malloc(size);
  if (block != NULL)
    alloc_supplied++;

  return block;
}

void __wrap_free(void *ptr)
{
  free_calls++;
  last_freed = ptr;

  if (ptr == NULL)
    free_calls_null++;

  /*
   * Delegate unconditionally.  free(NULL) is defined to do nothing, so there
   * is no need to filter it out, and filtering it out would mean the
   * interposer stopped being a faithful stand-in for the function it replaces.
   */
  __real_free(ptr);
}

/*
 * Blocks the interposer supplied and has not seen released again.  Signed on
 * purpose: an over-release would silently wrap an unsigned counter round to a
 * huge number that still compares unequal to zero but says nothing useful,
 * whereas a negative figure names the fault directly in the failure line.
 *
 * The figure is exact for this executable because --wrap rewrites only the
 * references inside the objects being linked -- this file and the err.c inside
 * libprov.a -- so libc's own internal allocations (the stdio buffer, for one)
 * never enter either interposer and cannot skew the count.
 */
static long alloc_outstanding(void)
{
  return (long)alloc_supplied - (long)(free_calls - free_calls_null);
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
 * Compose "<case>: <what>" into caller-supplied storage.  The two helpers
 * below are each used from several cases, and a fixed label would leave a
 * CTest log unable to say which case failed; the file and line on a failing
 * line point at the helper, so the label is what has to carry the case
 * identity.  Given a nonzero capacity snprintf() truncates rather than
 * overruns and writes a terminating null, and it never runs inside an armed
 * window.
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
 * A-1, A-2: the malloc at err.c:56, failed and then allowed to succeed.
 *
 * Self-contained on purpose.  Each case resets the observation state itself,
 * owns whatever it allocates, frees it, and leaves the allocator disarmed, so
 * independence is structural rather than a convention the next reader has to
 * trust -- which is what makes the file safe under `ctest -j N` and safe to
 * run a single case at a time.
 */
static int test_new_handle_alloc_failure(void)
{
  /*
   * One variable per RESULT, never one reused across cases.  A-1's result is
   * expected to be NULL, but "expected" is exactly what this file exists to
   * check: a regression in err.c, or an interposer the linker silently
   * dropped, would hand back a real OWNED handle there.  Reusing one variable
   * would then overwrite the only reference to it and leak it (CWE-401) on the
   * very diagnostic path meant to expose the defect -- and a leak report
   * arising from the test itself is worse than no report, because it is read
   * as evidence against err.c.  Separate variables make the unexpected result
   * releasable, which is what the cleanup below then does.
   */
  struct proverr_functions_st *failed_handle;
  struct proverr_functions_st *handle;
  unsigned long intercepted_before;
  unsigned long forced_before;
  unsigned long pending_after;
  long outstanding_before;
  int ok = 1;

  /*
   * A-1.  Fail the one allocation proverr_new_handle() makes and the function
   * must yield NULL: err.c:56 leaves `handle` at the err.c:24 initialiser and
   * err.c:62 returns it.  The core and the table are both valid, so none of
   * the assertions at err.c:26, err.c:27 or err.c:47-49 is in play and this
   * really is the allocation branch and not an aborting input in disguise.
   */
  mock_core_reset();

  /*
   * Settle stdio BEFORE the baselines are read, not between reading them and
   * arming.  The flush is the one operation here that can itself allocate, and
   * a flush placed after the snapshot would put its allocation inside the
   * measured window, making every delta below depend on how much output
   * happened to be buffered at that moment.  Flush, then snapshot, then arm:
   * the window then holds exactly what the call under test does, and nothing
   * prints again until after the disarm.
   */
  fflush(stdout);

  intercepted_before = alloc_intercepted;
  forced_before = alloc_forced;
  outstanding_before = alloc_outstanding();

  arm_alloc_failures(1);
  failed_handle = proverr_new_handle(&mock_core_primary,
                                     mock_dispatch_complete);
  pending_after = alloc_failures_pending();
  disarm_alloc_failures();

  TEST_ASSERT_PTR_NULL("A-1 new_handle returns NULL when err.c:56 fails",
                       failed_handle);
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

  /*
   * A failed allocation must leave the ledger exactly where it was: nothing
   * was supplied, so nothing may be released either.  This is what would catch
   * a failure path that tried to free a block it never obtained -- the
   * interposer would record a release with no matching allocation and the
   * figure would go negative.
   */
  TEST_ASSERT_INT_EQ("A-1 a failed allocation left the ledger unchanged",
                     alloc_outstanding(), outstanding_before);
  ok &= test;

  ok &= assert_no_callbacks("A-1");

  /*
   * Ownership on the failure path, and the reason it is not dead code.  The
   * assertion above has already recorded its verdict, so this is cleanup and
   * not a check: if err.c ever stopped honouring a failed allocation -- an
   * unchecked malloc, or a fallback to storage of its own -- A-1 would hand
   * back a real handle, that object would be owned by this test, and A-2
   * would overwrite the only reference to it.  Under a sanitizer the leak is
   * then reported alongside the real failure and buries it; without one it is
   * silent.  It is therefore released here exactly once, while
   * `failed_handle` is still the only name for it, and the pointer is cleared
   * so nothing below can free it a second time.  Freeing costs no allocation,
   * so it cannot perturb A-2's exact interception counts, and it happens
   * outside the armed window as this file's arm-late / disarm-early discipline
   * requires -- free(NULL) on the expected path is a defined no-op, so the
   * branch exists purely so a broken library cannot turn a clean failure into
   * noise.  Exactly once is also guaranteed by position: nothing reads
   * `failed_handle` between here and A-2's own call.
   */
  if (failed_handle != NULL) {
    proverr_free_handle(failed_handle);
    failed_handle = NULL;
  }

  /*
   * A-2.  With the allocator restored the very same call must succeed, which
   * is what proves the interposer is a switch and not a one-way door: an
   * interposer that stayed poisoned would make every later case vacuous, and
   * A-3's NULL in particular would then mean nothing at all.
   */
  mock_core_reset();

  fflush(stdout);

  intercepted_before = alloc_intercepted;
  forced_before = alloc_forced;
  outstanding_before = alloc_outstanding();

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
   * One block supplied and not yet released.  Not implied by the non-NULL
   * return above: a constructor that allocated, stored the pointer and freed
   * it again before returning would still hand back a non-NULL value -- a
   * dangling one -- and only the ledger would notice.
   */
  TEST_ASSERT_INT_EQ("A-2 one block was supplied and is still outstanding",
                     alloc_outstanding(), outstanding_before + 1L);
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

static int test_dup_handle_alloc_failure(void)
{
  /*
   * One variable per result again, for the reason given in
   * test_new_handle_alloc_failure(): A-3's result must be NULL, and if a
   * regression made it a real handle instead, reusing A-5's variable would
   * discard the only reference to it and leak it (CWE-401) on the diagnostic
   * path itself.
   */
  struct proverr_functions_st *source;
  struct proverr_functions_st *failed_copy;
  struct proverr_functions_st *copy;
  unsigned long intercepted_before;
  unsigned long forced_before;
  unsigned long pending_after;
  long outstanding_before;
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

  fflush(stdout);

  intercepted_before = alloc_intercepted;
  forced_before = alloc_forced;
  outstanding_before = alloc_outstanding();

  arm_alloc_failures(1);
  failed_copy = proverr_dup_handle(source);
  pending_after = alloc_failures_pending();
  disarm_alloc_failures();

  TEST_ASSERT_PTR_NULL("A-3 dup_handle returns NULL when err.c:71 fails",
                       failed_copy);
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

  /*
   * The failed duplication released nothing.  The interesting failure this
   * guards against is a dup_handle() that, on failing to allocate, tried to
   * tidy up by freeing its SOURCE: the source would still look usable for as
   * long as the freed memory happened to hold its old contents, so A-4's raise
   * below could well still pass, but a release with no matching allocation
   * inside this window makes the ledger move where it must stand still, and
   * that is what this line reads.
   */
  TEST_ASSERT_INT_EQ("A-3 a failed duplication left the ledger unchanged",
                     alloc_outstanding(), outstanding_before);
  ok &= test;

  ok &= assert_no_callbacks("A-3");

  /*
   * Ownership on the failure path, with an ALIAS CHECK that is not optional.
   * A-3's result must be NULL; if it is a real handle instead it belongs to
   * this test, and A-5 overwrites the pointer, so it is released here or the
   * object it names is leaked into a log that already has a real failure to
   * report.  But the other plausible regression -- a dup_handle() that returns
   * its own argument rather than allocating -- would make that pointer
   * `source` itself, and freeing it would destroy the handle A-4 through A-7
   * still read through and hand the tail of this function a double free
   * (CWE-415).  So only a pointer that is genuinely distinct from `source` is
   * released, and the variable is cleared either way so nothing below can
   * reach it -- without that guard A-4 would read back a handle this cleanup
   * had already destroyed, turning one clean mismatch into a use-after-free.
   * The allocator is already disarmed, so nothing here is intercepted.
   */
  if (failed_copy != NULL && failed_copy != source)
    proverr_free_handle(failed_copy);
  failed_copy = NULL;

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

  fflush(stdout);

  intercepted_before = alloc_intercepted;
  forced_before = alloc_forced;
  outstanding_before = alloc_outstanding();

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

  /*
   * A successful duplication adds one block to the ledger and removes none:
   * the copy is new storage and the source is untouched.  A dup_handle() that
   * released the source as a side effect of copying it would pass the
   * distinctness assertion above and fail here.
   */
  TEST_ASSERT_INT_EQ("A-5 the duplicate added one block to the ledger",
                     alloc_outstanding(), outstanding_before + 1L);
  ok &= test;

  ok &= assert_no_callbacks("A-5");

  /*
   * A-6 and A-7 are gated on the distinctness A-5 has just asserted, not
   * merely on the copy being non-NULL, and the guard is load-bearing rather
   * than decorative: A-7 frees the copy and then raises through the source,
   * which is defined only if the two really are separate objects.  Against a
   * library that aliased them the ungated version would free the source and
   * read it back, and the resulting fault would discard whatever stdout had
   * buffered -- hiding A-5's own self-diagnosing line, which is the diagnosis.
   * With the guard, such a library is reported by one clean failure line
   * instead of a signal.
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
 * A-8: the countdown decrements exactly once per intercepted allocation.
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
  /*
   * Whether the second and third results name objects of their own.  The
   * cleanup at the end of this case decides this BEFORE it frees anything,
   * because once an object is released its former pointer value is
   * indeterminate (C99 6.2.4p2) -- so `second != first` asked after `first`
   * had been freed would not be a question with a defined answer.  Deciding
   * first and freeing afterwards is what keeps that cleanup both leak-free and
   * double-free-free whatever the three calls returned.
   */
  int second_is_unique;
  int third_is_unique;
  long outstanding_before;
  int ok = 1;

  mock_core_reset();

  fflush(stdout);

  intercepted_before = alloc_intercepted;
  forced_before = alloc_forced;
  outstanding_before = alloc_outstanding();

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

  /*
   * Three calls, two of them failed, so exactly one block was supplied across
   * the window and none released.  Pins the correspondence between the
   * interception count above and the blocks that actually exist: a countdown
   * that returned NULL to err.c while still allocating underneath would
   * satisfy every assertion above and be caught here.
   */
  TEST_ASSERT_INT_EQ("A-8 only the successful call added to the ledger",
                     alloc_outstanding(), outstanding_before + 1L);
  ok &= test;

  ok &= assert_no_callbacks("A-8");

  /*
   * Ownership for all three results, not just the one that was expected to
   * exist.  Only `third` is expected to be a real handle, but the two armed
   * failures are exactly the results a regression would turn into owned
   * objects, and abandoning them would leak on the diagnostic path (CWE-401)
   * -- adding leak reports to a log whose assertions have already named the
   * defect precisely.  Each is therefore released, and each only if it is not
   * an alias of one already released, so a library that pooled handles and
   * handed the same object out more than once cannot be turned into a double
   * free (CWE-415) by this cleanup; the mismatch that pooling describes is the
   * business of the assertions above -- as is a defect that gave `third` the
   * storage one of the failing calls had already returned.  Both flags are
   * computed first, while all three pointers are still valid; see their
   * declarations for why the order matters.  The allocator is disarmed by this
   * point, so nothing here is intercepted.
   */
  second_is_unique = second != NULL && second != first;
  third_is_unique = third != NULL && third != first && third != second;

  if (first != NULL)
    proverr_free_handle(first);
  if (second_is_unique)
    proverr_free_handle(second);
  if (third_is_unique)
    proverr_free_handle(third);

  fflush(stdout);

  return ok;
}

/*
 * ---------------------------------------------------------------------------
 * A-9 to A-12: the free at err.c:82, made observable.
 * ---------------------------------------------------------------------------
 *
 * proverr_free_handle() (err.c:80-83) has no return value, no output parameter
 * and touches no callback, so nothing a caller can see distinguishes it from
 * an empty function.  Delete its body and every other assertion in this suite
 * still passes, because a handle that is never released is still a handle that
 * works.  The interposition this target already needs for the two allocation
 * failures is what closes that hole: with free wrapped, the pointer err.c:82
 * hands to the allocator, the number of times it does so, and the running
 * difference between blocks supplied and blocks released are all values, and a
 * no-op body fails A-9 on its first assertion.
 *
 * Every pointer-identity assertion below compares values captured while the
 * block was still live -- the interposer records its argument on entry, before
 * it delegates, and each case copies out the address it is about to pass
 * before it calls -- and no assertion ever dereferences either operand.  That
 * is what keeps "the block released was this handle" a comparison of captured
 * values rather than a read through a pointer whose object has gone.
 */
static int test_free_handle_release(void)
{
  struct proverr_functions_st *handle;
  struct proverr_functions_st *source;
  struct proverr_functions_st *copy;
  const void *handle_address;
  const void *source_address;
  const void *copy_address;
  const void *released;
  unsigned long free_before;
  unsigned long free_null_before;
  unsigned long free_delta;
  unsigned long free_null_delta;
  long outstanding_case_start;
  long outstanding_before;
  long outstanding_after;
  int ok = 1;

  /*
   * The ledger baseline for A-12, read before this case has allocated
   * anything.  Everything the case obtains between here and there has to be
   * back by the time A-12 looks.
   *
   * Flush first, then snapshot -- the same rule every measured window in this
   * file follows, for the reason spelt out at A-1: the flush is the one
   * operation around a window that can itself allocate, and a flush placed
   * after the baseline would sit inside the span the baseline measures.
   */
  mock_core_reset();
  fflush(stdout);

  outstanding_case_start = alloc_outstanding();

  handle = proverr_new_handle(&mock_core_primary, mock_dispatch_complete);

  TEST_ASSERT_PTR_NOT_NULL("A-9 handle for the release case", handle);
  ok &= test;

  if (handle == NULL)
    return 0;

  /*
   * A-9.  A live handle, released once.  The address is copied out here,
   * before the call, because afterwards `handle` names an object that no
   * longer exists; `released` is the copy the interposer took on entry.  Both
   * operands of the identity assertion therefore predate the deallocation.
   */
  handle_address = (const void *)handle;

  mock_core_reset();
  fflush(stdout);

  free_before = free_calls;
  outstanding_before = alloc_outstanding();

  proverr_free_handle(handle);

  free_delta = free_calls - free_before;
  released = last_freed;
  outstanding_after = alloc_outstanding();

  TEST_ASSERT_UINT_EQ("A-9 releasing a live handle reached free exactly once",
                      free_delta, 1UL);
  ok &= test;

  TEST_ASSERT_PTR_EQ("A-9 the block released is the handle itself", released,
                     handle_address);
  ok &= test;

  TEST_ASSERT_INT_EQ("A-9 the handle's block is no longer outstanding",
                     outstanding_after, outstanding_before - 1L);
  ok &= test;

  /*
   * Silence during a release, and not vacuously: the delta above has just
   * proved that a release really happened inside this observation window, so
   * "no callback ran" is a statement about a window in which something
   * definitely did occur.
   */
  ok &= assert_no_callbacks("A-9");

  /*
   * A-10.  proverr_free_handle(NULL) must release nothing.  What is asserted
   * is the CONTRACT -- no block leaves the ledger, no callback runs -- and
   * deliberately not the shape of the implementation.  err.c:80-83 forwards
   * its argument unconditionally, so NULL does reach the allocator here, but a
   * body written `if (handle != NULL) free(handle);` would satisfy the same
   * contract exactly as well.  The assertion is therefore on the number of
   * NON-NULL releases, which is zero under either shape, rather than on the
   * number of calls, which is not.  (The subtraction cannot underflow: every
   * increment of free_calls_null is accompanied by one of free_calls in the
   * same invocation.)
   */
  mock_core_reset();
  fflush(stdout);

  free_before = free_calls;
  free_null_before = free_calls_null;
  outstanding_before = alloc_outstanding();

  proverr_free_handle(NULL);

  free_delta = free_calls - free_before;
  free_null_delta = free_calls_null - free_null_before;
  outstanding_after = alloc_outstanding();

  TEST_ASSERT_UINT_EQ("A-10 free_handle(NULL) released no block",
                      free_delta - free_null_delta, 0UL);
  ok &= test;

  TEST_ASSERT_INT_EQ("A-10 free_handle(NULL) left the ledger unchanged",
                     outstanding_after, outstanding_before);
  ok &= test;

  ok &= assert_no_callbacks("A-10");

  /*
   * A-11.  Releasing a duplicate must release the DUPLICATE.  err.c:82 frees
   * exactly the pointer it is handed, so the only observable difference
   * between "freed the copy" and "freed the source" is that pointer value --
   * which this file now holds.  Both halves are stated: the copy's block left
   * the ledger, and the source is still a working handle afterwards.
   */
  mock_core_reset();
  fflush(stdout);

  source = proverr_new_handle(&mock_core_primary, mock_dispatch_complete);

  TEST_ASSERT_PTR_NOT_NULL("A-11 source handle for the duplicate release",
                           source);
  ok &= test;

  if (source == NULL)
    return 0;

  copy = proverr_dup_handle(source);

  TEST_ASSERT_PTR_NOT_NULL("A-11 duplicate to be released", copy);
  ok &= test;

  if (copy == NULL) {
    proverr_free_handle(source);
    return 0;
  }

  source_address = (const void *)source;
  copy_address = (const void *)copy;

  TEST_ASSERT_PTR_NE("A-11 the duplicate is a distinct block", copy_address,
                     source_address);
  ok &= test;

  mock_core_reset();
  fflush(stdout);

  free_before = free_calls;
  outstanding_before = alloc_outstanding();

  proverr_free_handle(copy);

  free_delta = free_calls - free_before;
  released = last_freed;
  outstanding_after = alloc_outstanding();

  TEST_ASSERT_UINT_EQ("A-11 releasing the duplicate reached free exactly once",
                      free_delta, 1UL);
  ok &= test;

  TEST_ASSERT_PTR_EQ("A-11 the block released is the duplicate", released,
                     copy_address);
  ok &= test;

  TEST_ASSERT_PTR_NE("A-11 the block released is not the source", released,
                     source_address);
  ok &= test;

  TEST_ASSERT_INT_EQ("A-11 exactly one block left the ledger",
                     outstanding_after, outstanding_before - 1L);
  ok &= test;

  ok &= assert_no_callbacks("A-11");

  /*
   * The source, raised through after its copy has been released.  A-7 already
   * shows a source surviving a FAILED duplication; what this adds is survival
   * of a SUCCESSFUL one whose product has since been freed, paired with the
   * pointer-level proof above that the block released was the copy's.  The
   * reason is unique to this case so a stale observation cannot pass for a
   * fresh one.
   */
  mock_core_reset();
  fflush(stdout);
  ERR_raise(source, 11u);

  ok &= assert_raise_observed("A-11 the source outlives its released copy",
                              &mock_core_primary, 11u);

  /*
   * A-12.  The ledger closes.  Releasing the source is the last thing this
   * case does, so afterwards the count of blocks the interposer supplied and
   * has not seen released again must be back at the value read on entry.  That
   * is a stronger statement than any single delta: it says the releases
   * MATCHED the allocations across the whole case, so a proverr_free_handle()
   * that released nothing, or released the wrong block, or released one block
   * for two allocations, cannot reach the end of this function quietly.
   */
  mock_core_reset();
  fflush(stdout);

  free_before = free_calls;

  proverr_free_handle(source);

  free_delta = free_calls - free_before;
  released = last_freed;
  outstanding_after = alloc_outstanding();

  TEST_ASSERT_UINT_EQ("A-12 releasing the source reached free exactly once",
                      free_delta, 1UL);
  ok &= test;

  TEST_ASSERT_PTR_EQ("A-12 the block released is the source", released,
                     source_address);
  ok &= test;

  TEST_ASSERT_INT_EQ("A-12 every block this case obtained has been released",
                     outstanding_after, outstanding_case_start);
  ok &= test;

  ok &= assert_no_callbacks("A-12");

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
   * already in place, which REDUCES the chance of an unrelated allocation
   * landing inside an armed window.  It is not what makes the file
   * deterministic -- the narrow arm-and-disarm window around each call under
   * test is; see the "arm late, disarm early" note at the top of the file.
   */
  printf("test_err_alloc: err.c allocator contract -- malloc at err.c:56 and"
         " err.c:71, free at err.c:82\n");
  fflush(stdout);

  cases &= test_new_handle_alloc_failure();
  cases &= test_dup_handle_alloc_failure();
  cases &= test_countdown_precision();
  cases &= test_free_handle_release();

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
  printf("interposer totals: %lu allocations intercepted, %lu forced to fail,"
         " %lu releases (%lu of them NULL)\n", alloc_intercepted, alloc_forced,
         free_calls, free_calls_null);
  TEST_ASSERT(alloc_intercepted > 0UL);
  cases &= test;

  /*
   * The same diagnostic for the other half of the interposition.  A build that
   * somehow acquired --wrap=malloc but not --wrap=free would satisfy every
   * assertion above and none of A-9 to A-12, and this line is what names the
   * cause instead of leaving four cases failing for no visible reason.  It is
   * a "greater than zero" for the same reason as the allocation total: the
   * exact figure depends on how many handles the cases above happen to build,
   * and the precision lives in the per-case deltas.
   */
  TEST_ASSERT(free_calls > 0UL);
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
   * The whole-executable ledger.  Every case above releases each handle it
   * builds, so by the time control reaches here the count of blocks the
   * interposer supplied and has not seen released again must be exactly zero
   * -- not "small", not "unchanged since some baseline", but zero, because the
   * baseline at process start was zero.  A negative figure would mean more
   * releases than allocations, which is why alloc_outstanding() is signed: an
   * over-release names itself here instead of wrapping an unsigned counter
   * round to a meaningless large number.
   *
   * This is the file-level counterpart of A-12's per-case ledger, and it is
   * the assertion that makes a leak in ANY case in this file a failure rather
   * than something only a sanitizer run would notice.
   */
  TEST_ASSERT_INT_EQ("every block the interposer supplied was released",
                     alloc_outstanding(), 0L);
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
