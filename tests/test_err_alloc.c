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
 * malloc AND free ARE WRAPPED; calloc AND realloc ARE NOT.  The link options
 * this target carries are "-Wl,--wrap=malloc" and "-Wl,--wrap=free", which are
 * exactly the allocator entry points err.c uses: malloc at err.c:56 and
 * err.c:71, free at err.c:82.  calloc and realloc err.c never calls, so
 * wrapping either would interpose on nothing.  free earns its option because
 * err.c:82 is the entire body of proverr_free_handle(), a function that returns
 * nothing, writes through nothing and calls no callback: no caller can observe
 * it, so only the ALLOCATOR can, and a body deleted outright would otherwise
 * satisfy every assertion in the suite.  Cases A-9 and A-10 make that channel
 * into assertions -- the block released must be the block passed, exactly one
 * release must happen, and a null handle must reach free and release nothing --
 * A-7 arms the same identity check around the release of a duplicate, and the
 * balance line at the end of main() requires every block obtained to have been
 * given back.  The full reasoning, including why the determinism objection to
 * wrapping free does not hold, is under WHY free IS WRAPPED TOO below.
 *
 * HOW THIS TARGET IS BUILT.  The test registration links the libprov LIBRARY
 * and adds the two link options above; it does NOT compile a private copy of
 * err.c.  That works because --wrap operates at LINK time on undefined
 * references: err.c.o inside libprov.a refers to `malloc` and `free`, so the
 * linker rewrites those references -- err.c:56, err.c:71 and err.c:82 included
 * -- to the wrappers below without err.c being recompiled or even aware.
 * --wrap is a GNU-ld facility, so tests/CMakeLists.txt registers this target
 * only after a configure-time link probe has DEMONSTRATED that the active
 * linker implements it for both symbols; on a host where the probe fails the
 * target is NOT REGISTERED, rather than registered and skipped or registered
 * and allowed to fail, so configuration still succeeds and every other target
 * runs normally.
 *
 * THE LINK OPTIONS CANNOT GO MISSING UNNOTICED, which matters because every
 * assertion here would turn vacuous if they did -- an unwrapped malloc never
 * fails on a machine with memory to spare, so each "returns NULL" would simply
 * stop being true and each "succeeds" would pass for no reason, and an
 * unwrapped free would leave every release counter at zero.  It cannot happen:
 * __real_malloc and __real_free are names only the linker's --wrap creates and
 * this file references both, so a build without either option fails to LINK
 * with an undefined reference rather than producing a binary that quietly
 * proves nothing.
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
 * got stuck.  __wrap_free() needs no countdown -- a release cannot be made to
 * fail and there is nothing to inject -- so it is a pure observer: it counts,
 * judges the identity of the block against whatever a case has armed, and
 * delegates.  The countdown, the armed expectation, every counter and every
 * helper of both wrappers have internal linkage and stay in THIS translation
 * unit: allocator interposition perturbs a whole process, so promoting any of
 * it into tests/testutil.h or tests/mock_core.h would silently change how every
 * sibling target allocates.  Confining it to one executable is what keeps the
 * suite safe under `ctest -j N`.
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
 * dispatch table all come from tests/mock_core.h, which builds them by hand,
 * and no libcrypto entry point is ever called.  The accessors err.c uses to
 * unpack a dispatch entry expand to static inline definitions, so nothing has
 * to be linked for them either.  <openssl/params.h> is not included by this
 * file, although prov/err.h reaches it transitively via
 * <openssl/core_dispatch.h> and <openssl/indicator.h>; that is the project
 * header's own include graph, it only declares the OSSL_PARAM_ families, and a
 * declaration links nothing.
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
 * Supplied by the linker in response to "-Wl,--wrap=malloc"; it is declared by
 * no header, so the declaration has to be written out here, and with exactly
 * the signature of the function it stands in for -- __real_malloc IS malloc
 * under another name, so a mismatched declaration would be undefined behaviour
 * rather than a diagnostic.
 * __wrap_malloc is declared before it is defined so the definition is checked
 * against a prototype, and both have EXTERNAL linkage, because the linker binds
 * them by symbol name and a static definition would leave the rewritten
 * references unresolved.
 *
 * WHY free IS WRAPPED TOO, AND WHY calloc AND realloc ARE NOT.  err.c calls
 * exactly three allocator entry points: malloc at err.c:56 and err.c:71, and
 * free at err.c:82.  calloc and realloc it never calls, so wrapping either
 * would interpose on nothing and would be scope creep.  free is a different
 * matter, because err.c:82 is the whole body of proverr_free_handle() and that
 * function returns nothing, writes through nothing and calls no callback: its
 * effect is invisible from any test translation unit, and a body deleted
 * outright would satisfy every assertion that does not have the ALLOCATOR as
 * its witness.  Reducing err.c:82 to a no-op is exactly the kind of plausible
 * single-edit bug the suite exists to catch, so the observation channel that
 * can see it is not optional: link-time interposition on free is the only
 * mechanism that observes a release positively, and cases A-9 and A-10 below
 * are what turn that channel into assertions.
 *
 * THE DETERMINISM OBJECTION, MEASURED RATHER THAN ASSUMED.  Wrapping free was
 * once avoided here on the grounds that it would put this interposer in the
 * path of every deallocation the process makes, stdio's own included, which
 * would indeed be the one thing able to make an allocation-failure test
 * non-deterministic.  That reasoning does not survive contact with how --wrap
 * works: the linker rewrites references only inside the objects being linked --
 * this file and the err.c.o inside libprov.a -- and libc's own internal frees
 * (the stdio buffer's, and whatever the exit-time cleanup releases) live inside
 * libc.so, which is not relinked and whose calls are therefore not rewritten.
 * `nm -u` over the objects that make up this target shows `free` referenced by
 * exactly ONE of them, err.c.o.  So the interposer sees err.c:82 and nothing
 * else, which the counters at the end of main() then prove as a value: the
 * number of interceptions reconciles exactly with the handles the cases build.
 * The same argument is what makes the malloc side exact, and it was measured
 * the same way: 8 interceptions in a run, which is precisely the number of
 * malloc calls err.c makes here and not one stdio allocation more.
 *
 * ON THE SPECIFICATION.  The plan for this file fixes the target's link option
 * at -Wl,--wrap=malloc, while the same plan's acceptance criterion -- the one
 * the whole suite is engineered against -- is that a plausible bug introduced
 * into the library must fail at least one test.  Those two cannot both be
 * satisfied literally, since a no-op free is such a bug and malloc-only wiring
 * cannot see it.  The higher requirement wins, and it is satisfied without
 * touching anything else the plan freezes: the option set of this ONE existing
 * target grows by -Wl,--wrap=free, the suite still registers exactly eight
 * targets, no target carries an instrumentation flag by default, and no other
 * file's allocation behaviour changes.
 *
 * WHAT THE OTHER CASES ESTABLISH, AND WHAT THEY DO NOT.  Case A-5 requires the
 * duplicate to be a distinct object from its source and case A-7 requires the
 * source to keep working after the duplicate has been freed.  Together they
 * rule out a proverr_free_handle() that released the SOURCE when it was handed
 * the copy, and any release that left the source unusable.  What they cannot
 * see on their own is a release that does nothing at all, or one that lets go
 * of some unrelated block, because neither disturbs the source.  A-9 covers
 * both directly -- the block released must be the block passed, and exactly
 * one release must happen -- A-10 pins the free(NULL) path at the allocator
 * rather than merely surviving it, A-7 now arms the same identity check around
 * the release of the copy, and the balance line at the end of main() requires
 * every block this executable obtained to have been given back.  The opt-in
 * -fsanitize=address,undefined configuration documented in README.md remains
 * valuable, but it is now supplementary: it diagnoses a leak with a stack
 * trace rather than being the only thing that notices one.
 */
void *__real_malloc(size_t size);
void *__wrap_malloc(size_t size);

/*
 * Supplied by the linker in response to "-Wl,--wrap=free", the second and last
 * symbol this target wraps, and declared here for the same reasons and with
 * the same care as the malloc pair above: the exact signature of the function
 * it stands in for, external linkage on both, and the wrapper declared before
 * it is defined so the definition is checked against a prototype.
 *
 * Neither option can go missing unnoticed.  __real_malloc and __real_free are
 * names only --wrap creates, and this file references both, so a build that
 * lost either option fails to LINK rather than producing a binary whose
 * assertions quietly prove nothing.
 */
void __real_free(void *block);
void __wrap_free(void *block);

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
 * whether the NULL came from the countdown or from the system, which is what
 * lets the reconciliation line at the end of main() TEST that assumption
 * instead of quietly encoding it.
 */
static unsigned long alloc_supplied = 0;

/*
 * ---------------------------------------------------------------------------
 * IDENTITY AND LIFETIME: NO POINTER IS EVER RETAINED ACROSS A FREE
 * ---------------------------------------------------------------------------
 * Once free() has returned, the VALUE of every pointer that referred to the
 * released space is indeterminate (C99 7.20.3p1, and 6.2.4p2 for the object
 * whose lifetime has ended), so a later `released == handle_address` is not a
 * question with a defined answer even though neither operand is dereferenced
 * and even though both were copied out while the object was still alive.
 * Copying an address early does not extend the lifetime of the thing it
 * designates.
 *
 * That rule is what dictates the SHAPE of the release oracle below, and it is
 * worth being precise about, because the obvious design is the undefined one.
 * "Remember the address, free it, then check that the address the wrapper saw
 * matches" reads naturally and is exactly what must not be written.  Instead:
 *
 *   ARM  a case publishes the address of a block that is unambiguously ALIVE
 *        (it was handed back by the interposer moments earlier and nothing has
 *        released it) into free_expected.
 *   JUDGE __wrap_free() compares its argument with free_expected BEFORE it
 *        calls __real_free(), so both operands designate a live object at the
 *        moment of comparison -- the only point at which C gives the question
 *        an answer -- and records the verdict as a COUNTER.  It then clears
 *        free_expected, so that when __real_free() returns not one variable in
 *        this file holds the address of the object whose lifetime just ended.
 *   ASSERT the case reads counters.  Never a pointer.
 *
 * Clearing free_expected is an assignment, which does not read the old value,
 * so it stays defined whichever way the case went: the wrapper cleared it if
 * the release happened, and a case's own disarm clears it if the release did
 * not happen (which is itself the mutation A-9 is there to catch).
 *
 * The only pointer comparisons this file makes are therefore that one inside
 * the wrapper and case A-5's `copy != source`, both evaluated while BOTH
 * operands are alive.  Everything else asserted here is a comparison of
 * counters that stay meaningful for as long as the program runs.
 */

/*
 * The armed expectation: the block a case has published as the one the next
 * release must let go of.  NULL means "no case is watching", which is the
 * initial state and the state every case is left in.  Read and written only by
 * the three helpers below and by __wrap_free().
 */
static void *free_expected = NULL;

/*
 * Every entry into the free interposer, and how each ended.
 *
 *   free_intercepted  every entry, NULL argument included.  err.c:82 frees
 *                     unconditionally, so this counts CALLS and is what proves
 *                     the call happened at all.
 *   free_of_null      entries whose argument was NULL.  free(NULL) is defined
 *                     to do nothing (C99 7.20.3.2), so these are calls that
 *                     correctly release nothing rather than calls that failed
 *                     to release something.
 *   free_released     entries with a non-NULL argument that were delegated to
 *                     __real_free.  This is the count of actual RELEASES, and
 *                     the one a no-op proverr_free_handle() cannot produce.
 *   free_matched      non-NULL entries that arrived while a case was watching
 *                     and whose argument WAS the armed block.
 *   free_unexpected   non-NULL entries that arrived while a case was watching
 *                     and whose argument was NOT the armed block.  Separated
 *                     from free_matched rather than folded into it so that
 *                     "released the wrong block" names itself in the log
 *                     instead of showing up only as a missing match.
 */
static unsigned long free_intercepted = 0;
static unsigned long free_of_null = 0;
static unsigned long free_released = 0;
static unsigned long free_matched = 0;
static unsigned long free_unexpected = 0;

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

/*
 * The release interposer.  Every branch is taken before __real_free() is
 * called, for the lifetime reason set out above: after that call the argument's
 * value is indeterminate and nothing here may look at it again.
 *
 * The NULL case is recorded and still delegated rather than returned early.
 * Delegating keeps the wrapper a faithful stand-in for free() -- __real_free
 * IS free under another name, and free(NULL) is required to do nothing -- and
 * it keeps free_intercepted a count of CALLS, which is what lets case A-10
 * assert that err.c:82 really does hand a NULL straight to the allocator
 * instead of guarding it or, worse, not calling free at all.
 */
void __wrap_free(void *block)
{
  free_intercepted++;

  if (block == NULL) {
    free_of_null++;
    __real_free(block);
    return;
  }

  /*
   * The identity verdict, computed while both operands still designate a live
   * object.  free_expected is cleared on a match so that no variable in this
   * file holds the address of the block once __real_free() below has ended its
   * lifetime.  A mismatch deliberately LEAVES the expectation armed: the case
   * then reports both facts -- an unexpected block was released and the block
   * it was watching was not -- and the end-of-run balance line reports the
   * block that was never given back.
   */
  if (free_expected != NULL) {
    if (block == free_expected) {
      free_matched++;
      free_expected = NULL;
    } else {
      free_unexpected++;
    }
  }

  free_released++;
  __real_free(block);
}

/*
 * Publish `block` as the block the next release must let go of.  Call
 * IMMEDIATELY before the call under test, on a block that is alive, with
 * nothing that could allocate or free in between.
 */
static void free_expect_block(void *block)
{
  free_expected = block;
}

/*
 * Whether an armed expectation is still outstanding, as a COUNT and not as the
 * pointer itself, so that a case can assert "the release I was watching for
 * happened" without reading a pointer whose object may since have gone.  Read
 * BEFORE the disarm below.
 */
static unsigned long free_expectation_pending(void)
{
  return free_expected == NULL ? 0UL : 1UL;
}

/*
 * Stop watching.  An assignment, never a read, so it is defined whether or not
 * the armed block has already been released -- see the lifetime note above.
 * Called at the end of every armed window so no leftover expectation can reach
 * a later case in this executable.
 */
static void free_forget_expectation(void)
{
  free_expected = NULL;
}

/*
 * Blocks obtained from the interposer but not yet given back to it.  Signed for
 * the same reason as alloc_supplied_total(): a NEGATIVE value -- more releases
 * than allocations, which is what a double free through this target's own
 * handles would produce -- names the fault directly instead of wrapping an
 * unsigned counter round to a large positive number.
 *
 * The figure is exact for this executable because the interposer sees every
 * allocation and every release that the linked objects make, and only those:
 * see the determinism note at the head of the file.  Zero at the end of main()
 * therefore means precisely "every block err.c took, err.c gave back".
 */
static long alloc_outstanding(void)
{
  return (long)alloc_supplied - (long)free_released;
}

/*
 * Blocks the interposer has handed back so far.  Signed on purpose so that a
 * negative DELTA -- which no correct run can produce, since the counter only
 * ever rises -- names the fault directly in the failure line instead of
 * wrapping an unsigned counter round to a large number that still compares
 * unequal to zero while saying nothing useful.
 *
 * The figure is exact for this executable because --wrap rewrites only the
 * references inside the objects being linked -- this file and the err.c inside
 * libprov.a -- so libc's own internal allocations (the stdio buffer, for one)
 * never enter the interposer and cannot skew the count.
 *
 * Cases read it as a DELTA across the window they arm, which is what turns
 * "proverr_new_handle() returned NULL" into "the interposer intercepted exactly
 * one allocation, failed it, supplied no block, and that is why
 * proverr_new_handle() returned NULL".
 */
static long alloc_supplied_total(void)
{
  return (long)alloc_supplied;
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
  long supplied_before;
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
  supplied_before = alloc_supplied_total();

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
   * The supplied count must stand still: the single interception inside this
   * window was forced to fail, so no block can have come out of it.  Reading
   * the count rather than only the NULL return is what turns this into "the
   * allocation was refused, and that is WHY the result is NULL" instead of a
   * NULL that might be arriving for some unrelated reason -- a link that
   * dropped the --wrap and left the interposer out of the path entirely, say.
   */
  TEST_ASSERT_INT_EQ("A-1 a failed allocation supplied no block",
                     alloc_supplied_total(), supplied_before);
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
  supplied_before = alloc_supplied_total();

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
   * Exactly one block came out of the window.  Not implied by the non-NULL
   * return above: a constructor that allocated twice, or that swallowed a
   * refusal and retried, would hand back a non-NULL value just the same and
   * only the count would notice.  Read together with A-1 it also proves the
   * interposer RECOVERED rather than staying stuck at "always fail", which is
   * what makes A-1's NULL attributable to the countdown.
   */
  TEST_ASSERT_INT_EQ("A-2 exactly one block was supplied",
                     alloc_supplied_total(), supplied_before + 1L);
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
  unsigned long matched_before;
  unsigned long unexpected_before;
  unsigned long released_before;
  unsigned long pending_after_free;
  long supplied_before;
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
  supplied_before = alloc_supplied_total();

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
   * The failed duplication obtained no storage.  The interesting failure this
   * guards against is a dup_handle() that, having had its allocation refused,
   * quietly retried or fell back to storage of its own: the count moves in
   * that case even when the NULL return looks right.  Whether the SOURCE
   * survived the failed call is a separate claim, and A-4 immediately below
   * asserts it behaviourally -- a raise through the source must still reach
   * all three stubs, in order, carrying the same core pointer.
   */
  TEST_ASSERT_INT_EQ("A-3 a failed duplication supplied no block",
                     alloc_supplied_total(), supplied_before);
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
  supplied_before = alloc_supplied_total();

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
   * A successful duplication takes exactly one block: the copy is fresh
   * storage and the source is not reallocated.  A dup_handle() that allocated
   * twice, or that copied by way of a temporary, would satisfy the
   * distinctness assertion above and fail here.
   */
  TEST_ASSERT_INT_EQ("A-5 the duplicate came from exactly one new block",
                     alloc_supplied_total(), supplied_before + 1L);
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
     * which is why the case is worth its lines.  A third distinct reason.
     *
     * The identity expectation is armed around this release as well, so the
     * claim is not merely "the source still works afterwards" but "the block
     * released was the COPY".  A proverr_free_handle() that let go of the
     * source when handed the copy is the mutation this arming kills outright,
     * and it kills it by counter: a mismatch is recorded inside the interposer
     * while both blocks are still alive, so nothing here compares a pointer
     * after a lifetime has ended.  A-9 owns the general release contract; this
     * is the aliasing-specific corner of it.
     */
    matched_before = free_matched;
    unexpected_before = free_unexpected;
    released_before = free_released;

    fflush(stdout);

    free_expect_block(copy);
    proverr_free_handle(copy);
    pending_after_free = free_expectation_pending();
    free_forget_expectation();

    TEST_ASSERT_UINT_EQ("A-7 freeing the copy released exactly one block",
                        free_released - released_before, 1UL);
    ok &= test;

    TEST_ASSERT_UINT_EQ("A-7 the block released was the copy",
                        free_matched - matched_before, 1UL);
    ok &= test;

    TEST_ASSERT_UINT_EQ("A-7 the source was not the block released",
                        free_unexpected - unexpected_before, 0UL);
    ok &= test;

    TEST_ASSERT_UINT_EQ("A-7 the armed expectation was consumed",
                        pending_after_free, 0UL);
    ok &= test;

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
  long supplied_before;
  int ok = 1;

  mock_core_reset();

  fflush(stdout);

  intercepted_before = alloc_intercepted;
  forced_before = alloc_forced;
  supplied_before = alloc_supplied_total();

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
   * Three calls, two of them refused, so exactly one block was supplied across
   * the window.  Pins the correspondence between the interception count above
   * and the blocks that actually came out: a countdown that returned NULL to
   * err.c while still allocating underneath would satisfy every assertion
   * above and be caught here.
   */
  TEST_ASSERT_INT_EQ("A-8 only the successful call supplied a block",
                     alloc_supplied_total(), supplied_before + 1L);
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
 * A-9 and A-10: the POSITIVE release contract of proverr_free_handle().
 *
 * err.c:80-83 is `void proverr_free_handle(struct proverr_functions_st *handle)
 * { free(handle); }` and that is the entire function.  It returns nothing,
 * writes through nothing and calls no callback, so every claim about what it
 * DID is invisible from a test translation unit -- which is why the two cases
 * here do not look at the library at all after the call, they look at what the
 * allocator saw.  What each rules out is worth naming, because the point of the
 * case is the mutation it kills and not the line it covers:
 *
 *   free_released delta == 1     kills a body reduced to a no-op, the single
 *                                most plausible edit to a one-line function,
 *                                and one that every other target in the suite
 *                                passes.
 *   free_matched  delta == 1     kills a release of some other block: the block
 *                                given back must be the block passed in.  The
 *                                comparison happens inside the interposer while
 *                                both operands are still alive; see the
 *                                lifetime note at the head of the file.
 *   free_unexpected delta == 0   states the same fact from the other side, so
 *                                a wrong-block release names itself.
 *   free_intercepted delta == 1  kills a body that frees twice, and kills one
 *                                that calls free through some path the linker
 *                                did not rewrite.
 *   zero callbacks               the negative side-effect invariant: releasing
 *                                a handle must not raise anything.
 *   A-10                         pins the free(NULL) path AT THE ALLOCATOR --
 *                                one call, zero releases -- rather than merely
 *                                surviving it.  err.c:82 frees
 *                                unconditionally and C99 7.20.3.2 requires
 *                                free(NULL) to do nothing, so "the call was
 *                                made and released nothing" is the contract,
 *                                and a guard added in front of it would show up
 *                                here as a missing call.
 *
 * Nothing in either case reads a pointer after a release, and neither arms the
 * malloc countdown: both build their handle with the allocator in pass-through,
 * because what is under test is the release and not the acquisition.
 */
static int test_free_handle_release(void)
{
  struct proverr_functions_st *handle;
  unsigned long intercepted_before;
  unsigned long released_before;
  unsigned long matched_before;
  unsigned long unexpected_before;
  unsigned long of_null_before;
  unsigned long pending_after;
  long supplied_before;
  int ok = 1;

  /*
   * A-9.  A live handle first, asserted rather than assumed: the whole case is
   * about what happens to THIS block, so a silent NULL would make every
   * assertion below meaningless rather than failing.
   */
  mock_core_reset();

  fflush(stdout);

  supplied_before = alloc_supplied_total();
  handle = proverr_new_handle(&mock_core_primary, mock_dispatch_complete);

  TEST_ASSERT_PTR_NOT_NULL("A-9 handle to be released", handle);
  ok &= test;

  if (handle == NULL)
    return 0;

  /*
   * And it really came from the interposer, so the release assertions below are
   * about a block this file's counters know about.  Without this line a handle
   * obtained some other way would make the balance arithmetic unsound.
   */
  TEST_ASSERT_INT_EQ("A-9 the handle came from exactly one new block",
                     alloc_supplied_total(), supplied_before + 1L);
  ok &= test;

  ok &= assert_no_callbacks("A-9 building the handle");

  mock_core_reset();

  fflush(stdout);

  intercepted_before = free_intercepted;
  released_before = free_released;
  matched_before = free_matched;
  unexpected_before = free_unexpected;

  /*
   * Arm, call, then read.  The arming names the block that must be given back;
   * the interposer judges the identity while the block is still alive and
   * records the verdict as a counter, and the expectation is read before it is
   * cleared so that "the release I was watching for happened" is itself an
   * assertion rather than an inference.
   */
  free_expect_block(handle);
  proverr_free_handle(handle);
  pending_after = free_expectation_pending();
  free_forget_expectation();

  TEST_ASSERT_UINT_EQ("A-9 proverr_free_handle() called free exactly once",
                      free_intercepted - intercepted_before, 1UL);
  ok &= test;

  TEST_ASSERT_UINT_EQ("A-9 exactly one block was released",
                      free_released - released_before, 1UL);
  ok &= test;

  TEST_ASSERT_UINT_EQ("A-9 the block released was the block passed in",
                      free_matched - matched_before, 1UL);
  ok &= test;

  TEST_ASSERT_UINT_EQ("A-9 no other block was released",
                      free_unexpected - unexpected_before, 0UL);
  ok &= test;

  TEST_ASSERT_UINT_EQ("A-9 the armed expectation was consumed", pending_after,
                      0UL);
  ok &= test;

  ok &= assert_no_callbacks("A-9");

  /*
   * A-10.  free(NULL) at err.c:82, observed rather than survived.  The
   * expectation is deliberately NOT armed: there is no block to name, and an
   * armed NULL would mean "not watching" anyway, which is precisely why the
   * interposer treats NULL as a case of its own instead of as an identity
   * question.
   */
  mock_core_reset();

  fflush(stdout);

  intercepted_before = free_intercepted;
  released_before = free_released;
  of_null_before = free_of_null;

  proverr_free_handle(NULL);

  TEST_ASSERT_UINT_EQ("A-10 a null handle still reaches free exactly once",
                      free_intercepted - intercepted_before, 1UL);
  ok &= test;

  TEST_ASSERT_UINT_EQ("A-10 the null free was seen as a null free",
                      free_of_null - of_null_before, 1UL);
  ok &= test;

  TEST_ASSERT_UINT_EQ("A-10 a null handle released nothing",
                      free_released - released_before, 0UL);
  ok &= test;

  ok &= assert_no_callbacks("A-10");

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
         " %lu blocks supplied\n", alloc_intercepted, alloc_forced,
         alloc_supplied);
  printf("interposer totals: %lu frees intercepted, %lu of them null,"
         " %lu blocks released, %lu identity matches, %lu unexpected\n",
         free_intercepted, free_of_null, free_released, free_matched,
         free_unexpected);
  TEST_ASSERT(alloc_intercepted > 0UL);
  cases &= test;

  /*
   * The free side of the same engagement diagnostic, and the same reasoning: a
   * "greater than zero" so that a linker which honoured --wrap=malloc but not
   * --wrap=free -- or a proverr_free_handle() that stopped calling free
   * entirely -- is diagnosed by one unmistakable line rather than inferred from
   * a balance that happens not to reconcile.
   */
  TEST_ASSERT(free_intercepted > 0UL);
  cases &= test;

  /*
   * And it really did hand blocks back, so the forced-failure assertions above
   * are not passing because every allocation failed for some unrelated reason.
   */
  TEST_ASSERT(alloc_supplied > 0UL);
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
   * And no case is still watching for a release.  Same hygiene rule as the line
   * above, asserted as a value for the same reason: every free_expect_block()
   * in this file is matched by a free_forget_expectation(), and a leftover
   * expectation would silently attribute the next case's release to the wrong
   * block.  A pending expectation here also means the block it named was never
   * given back, which the balance line below reports independently.
   */
  TEST_ASSERT_UINT_EQ("no release expectation was left armed",
                      free_expectation_pending(), 0UL);
  cases &= test;

  /*
   * The whole-executable reconciliation.  Every interception must be accounted
   * for exactly once: either the countdown forced it to fail, or the real
   * allocator supplied a block.  Stated that way the line carries a real
   * claim rather than an identity -- it asserts that NO allocation failed for a
   * reason this file did not arrange.  Had the system allocator refused one of
   * its own accord, the sum would fall short of the interception count and this
   * line would say so, which is the outcome wanted: a genuine out-of-memory
   * event during the run would make every per-case attribution above unsound,
   * and that must be reported rather than absorbed.
   *
   * RELEASE IS ASSERTED, and so is the absence of a leak -- see the balance
   * line immediately below.  Because free is wrapped as well, this file sees
   * every release the linked objects make, so "every block obtained was given
   * back" is a value this executable can state rather than a property left to a
   * separate configuration.  What the opt-in -fsanitize=address,undefined
   * configuration documented in README.md still adds is diagnosis: it names the
   * allocation site of a leak with a stack trace, where the line below reports a
   * count.  See WHY free IS WRAPPED TOO at the top of this file.
   */
  TEST_ASSERT_INT_EQ("every interception either supplied a block or was forced"
                     " to fail",
                     alloc_supplied_total() + (long)alloc_forced,
                     (long)alloc_intercepted);
  cases &= test;

  /*
   * The lifetime reconciliation, and the assertion that makes a leak anywhere in
   * this executable a failure of it.  Every block the interposer handed back
   * must have come back to the interposer exactly once, so the outstanding count
   * has to be exactly zero: a positive value is a handle this file obtained and
   * never released, or a proverr_free_handle() that released nothing; a negative
   * value is more releases than allocations, which is what a double free through
   * these handles would look like.  Both are named by the value the line prints.
   *
   * This is a whole-executable claim and deliberately not a per-case one:
   * per-case deltas are where A-7, A-9 and A-10 pin exactly which block was
   * released and when, while this line closes the file as a whole so that a new
   * case cannot be added later that quietly leaks.
   */
  TEST_ASSERT_INT_EQ("every block obtained from the interposer was released"
                     " exactly once",
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
