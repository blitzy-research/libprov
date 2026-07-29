/* CC0 license applied, see LICENSE */

/*
 * _POSIX_C_SOURCE must be defined BEFORE THE FIRST #include in this file, and
 * nothing but comments may precede it.  A feature-test macro selects which
 * declarations the C library's headers make visible, so defining it after a
 * header had already been processed would come too late to have any effect.
 * 200809L is POSIX.1-2008, the oldest revision that guarantees everything
 * used below: fork(), waitpid(), the wait-status macros and _exit().  On this
 * glibc a plain -std=c99 build happens to expose them anyway (measured); on a
 * stricter C library it would not, so this line is what makes the file
 * portable rather than merely lucky.
 */
#define _POSIX_C_SOURCE 200809L

/*
 * ===========================================================================
 * test_err_death.c -- the POSITIVE assertion of err.c's assert() contract
 * ===========================================================================
 *
 * proverr_new_handle() is guarded by five assertions: the core handle
 * (err.c:26) and the dispatch table (err.c:27) must not be NULL, and the
 * dispatch scan at err.c:34-45 must have resolved all three core callbacks
 * (err.c:47, err.c:48, err.c:49).  Where those assertions are live -- which is
 * the default build -- an invalid input does not return an error code, it
 * ABORTS.  This file asserts that the abort really happens, for every one of
 * those inputs.  It is the only file in the suite that forks.
 *
 * The complementary half of the contract belongs to test_err_guards.c: with
 * NDEBUG defined the assertions vanish, the guard at err.c:51-54 becomes
 * reachable, and the same inputs return NULL instead.  The two halves are
 * mutually exclusive under any one set of preprocessor flags, which is exactly
 * why they are two files and not two halves of one.
 *
 * NO USER-SPECIFIED RULES EXIST for this project: review_rules reports, in
 * full, "No user rules provided."  Nothing here is shaped by one and none has
 * been invented; the file is held to ordinary enterprise practice instead.
 * What does bind it is the prompt's own constraints -- assert a SPECIFIC
 * outcome rather than the mere absence of an error, never skip or weaken a
 * case, mock the OpenSSL core instead of depending on libcrypto or on a
 * running provider, and leave every non-test source untouched.  No defect was
 * found in err.c, so err.c is read here and never modified; compiling it into
 * this test target (see BUILD, below) is not a modification of it.
 *
 * ---------------------------------------------------------------------------
 * WHY A HAND-ROLLED fork()/waitpid() HARNESS AND NOT A CTest PROPERTY
 * ---------------------------------------------------------------------------
 * Please do not "simplify" this file into a CTest property.  Both plausible
 * candidates were tried against a real SIGABRT child and BOTH FAILED:
 *
 *   PASS_REGULAR_EXPRESSION, matching the assertion message -- documented to
 *     pass because "the process exit code is ignored" -- FAILED, reported by
 *     CTest as "(Subprocess aborted)".
 *   WILL_FAIL TRUE -- documented to invert a failure into a pass -- FAILED,
 *     reported in exactly the same way.
 *
 * A control (an executable returning 0, with WILL_FAIL TRUE) was correctly
 * reported as failed, which proves the property really was in effect and that
 * the negative result above was not a misconfiguration.  The documented "exit
 * code is ignored" evidently governs exit CODES and not SIGNAL terminations:
 * CTest treats an abnormally-terminated child as a hard failure either way.
 *
 * So the harness below is not a stylistic preference, it is the only mechanism
 * that works.  It is also strictly more precise, because it distinguishes
 * "aborted FOR THE EXPECTED REASON" from "died some other way" -- a
 * distinction neither property can express, and the difference between a test
 * that pins err.c's contract and one that would also pass on a segfault.
 *
 * ---------------------------------------------------------------------------
 * HOW THIS TARGET IS BUILT -- err.c IS COMPILED INTO IT
 * ---------------------------------------------------------------------------
 *   if(UNIX)
 *     libprov_add_test(test_err_death SOURCES test_err_death.c
 *                      ${PROJECT_SOURCE_DIR}/err.c COPTS -UNDEBUG)
 *     set_tests_properties(test_err_death PROPERTIES TIMEOUT 30)
 *   endif()
 *
 * Every part of that earns its place:
 *
 *   err.c is compiled INTO this target rather than reached through the libprov
 *     library, because NDEBUG has to be in effect for the translation unit
 *     that holds the assert() -- and libprov's err.c.o was already compiled
 *     once, with the project's own flags, so no definition on the *test*
 *     target could reach it.
 *   -UNDEBUG keeps the assertions live even in a configuration that defines
 *     NDEBUG globally, which -DCMAKE_BUILD_TYPE=Release does.  Without it a
 *     Release build would silently turn every abort into the graceful NULL of
 *     err.c:51-54, and every assertion in this file would fail.
 *   TIMEOUT 30 makes a harness defect degrade into a reported timeout instead
 *     of a hung suite.  It is a safety net and not a budget: the whole file
 *     completes in a few milliseconds.
 *   if(UNIX) means that on a host genuinely without POSIX process control this
 *     target is NOT REGISTERED AT ALL.  It is never registered-and-skipped and
 *     never allowed to fail; configuration still succeeds and every other
 *     target runs normally.
 *
 * Nothing here links or calls libcrypto.  The core handle and the dispatch
 * tables come from tests/mock_core.h, whose OSSL_CORE_HANDLE is a test-local
 * definition of a type <openssl/core.h> leaves incomplete, and the accessors
 * err.c uses expand to static inline code.  <openssl/params.h>, whose
 * OSSL_PARAM_ families are libcrypto functions, is deliberately absent.
 *
 * ---------------------------------------------------------------------------
 * DEBUGGING
 * ---------------------------------------------------------------------------
 * This harness forks, so a debugger stops in the PARENT by default and the
 * abort is never seen.  Tell it to follow the child:
 *
 *     gdb --args ./build/tests/test_err_death
 *     (gdb) set follow-fork-mode child
 *
 * Without that a debugger sits in the parent and the interesting process runs
 * unobserved.
 *
 * ---------------------------------------------------------------------------
 * WHY THE NON-ABORTING CONTROL CASE IS MANDATORY
 * ---------------------------------------------------------------------------
 * Six cases that all expect an abort cannot tell a correct harness from one
 * that answers "aborted" unconditionally: a harness stuck at "yes" would pass
 * all six and prove nothing whatsoever.  The control feeds the harness a VALID
 * input and requires the child to exit 0 with NO signal, so both answers the
 * harness can give are exercised and a stuck harness fails immediately.  It is
 * the case that makes the other six mean something.  Do not remove it.
 */

#include "testutil.h"
#include "mock_core.h"
#include "prov/err.h"

/* ISO C headers, needed by both the POSIX body and the fallback below. */
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>

/*
 * The POSIX headers are included INSIDE the guard on purpose.  <sys/wait.h>,
 * <unistd.h> and <sys/types.h> do not exist on a non-POSIX host, so including
 * them unconditionally would make the fallback at the foot of this file
 * unreachable: the compile would fail on a missing header long before the
 * preprocessor reached the alternative.  <signal.h> and <errno.h> are ISO C
 * and stay above.
 */
#ifndef _WIN32

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * Exit statuses a child uses to report that something went wrong INSIDE it.
 * Far from 0 on purpose: 0 is the control case's expected status and has to
 * mean exactly one thing, namely "the body returned and nothing went wrong".
 */
#define DEATH_CHILD_REDIRECT_FAILED 97
#define DEATH_CHILD_UNEXPECTED      98

/*
 * How a forked child ended.  Classifying the outcome, rather than reducing it
 * to a bare boolean inside the harness, is what lets a failing case say WHY it
 * failed -- "exited with status 0" and "killed by SIGSEGV" are very different
 * bugs, and both are simply "not SIGABRT" to a boolean.
 */
#define DEATH_END_SIGABRT      1
#define DEATH_END_OTHER_SIGNAL 2
#define DEATH_END_EXITED       3
#define DEATH_END_FORK_FAILED  4
#define DEATH_END_WAIT_FAILED  5

struct death_result {
  int how;                        /* one of DEATH_END_ above              */
  int signum;                     /* set for SIGABRT and OTHER_SIGNAL     */
  int code;                       /* exit status, or errno for a failure  */
};

/*
 * Say what the child actually did.  Called only when the observed outcome
 * contradicts the expected one, so a passing run stays quiet, and printed just
 * above the [FAIL] line that testutil.h emits -- context first, verdict
 * second.  The 11-space indent matches testutil.h's own detail rows.
 */
static void death_describe(const struct death_result *result)
{
  switch (result->how) {
  case DEATH_END_SIGABRT:
    printf("           observed : terminated by signal %d (SIGABRT)\n",
           result->signum);
    break;
  case DEATH_END_OTHER_SIGNAL:
    printf("           observed : terminated by signal %d, which is not"
           " SIGABRT (%d)\n", result->signum, SIGABRT);
    break;
  case DEATH_END_EXITED:
    printf("           observed : returned from the body and exited with"
           " status %d\n", result->code);
    break;
  case DEATH_END_FORK_FAILED:
    printf("           observed : fork() failed, errno %d -- the harness could"
           " not run this case\n", result->code);
    break;
  case DEATH_END_WAIT_FAILED:
    printf("           observed : waitpid() did not report a normal or"
           " signalled exit, errno %d -- the child's fate is unknown\n",
           result->code);
    break;
  default:
    printf("           observed : unclassifiable outcome %d\n", result->how);
    break;
  }
}

/*
 * Run body() in a forked child and classify how that child ended.
 *
 * The child NEVER returns from this function: it either dies inside body() --
 * which is the point of the exercise -- or reaches the _exit() below.  That is
 * what stops a surviving child from falling through into the rest of main()
 * and running every remaining case a second time.
 */
static struct death_result death_run(void (*body)(void))
{
  struct death_result result;
  pid_t child;
  pid_t waited;
  int status = 0;

  result.how = DEATH_END_FORK_FAILED;
  result.signum = 0;
  result.code = 0;

  /*
   * Flush every stream before forking.  Anything still buffered would be
   * inherited by the child and written out twice, once from each process, and
   * would then appear twice in the CTest log.
   */
  fflush(NULL);

  child = fork();
  if (child < 0) {
    /*
     * A harness failure, reported as such.  It must never be mistaken for a
     * pass: DEATH_END_FORK_FAILED is not DEATH_END_SIGABRT, so the predicates
     * below answer 0 and the caller's assertion fails, loudly and located.
     */
    result.code = errno;
    return result;
  }

  if (child == 0) {
    /*
     * The child.  Its stderr goes to /dev/null so that the assertion messages
     * this file EXPECTS -- glibc's "Assertion `core != NULL' failed" and its
     * kin -- do not pollute the log of a passing test.
     *
     * The freopen() result HAS to be consumed: glibc declares freopen()
     * warn_unused_result, and GCC diagnoses a bare call under
     * -D_FORTIFY_SOURCE=2 -O2 (measured), which the project may well be built
     * with.  A (void) cast is not a documented remedy for that attribute, so
     * the value is TESTED instead -- consumed by the comparison itself rather
     * than parked in a local, which keeps cppcheck's variableScope and
     * constVariablePointer advice satisfied as well.  Nor is the test mere
     * ceremony: if the redirection failed, the child says so with a status of
     * its own instead of quietly leaking assertion text into the log, and the
     * parent reports "exited with status 97" (measured).
     */
    if (freopen("/dev/null", "w", stderr) == NULL)
      _exit(DEATH_CHILD_REDIRECT_FAILED);

    body();

    /*
     * body() returned, so no assertion fired.  _exit() and not exit(): the
     * child inherited the parent's stdio buffers, and exit() would flush them,
     * printing the parent's pending output a second time -- and would also run
     * any atexit() handler a second time.  EXIT_SUCCESS is what the control
     * case requires, so "the body survived" is signalled by the ABSENCE of a
     * signal rather than by a special status.
     */
    _exit(EXIT_SUCCESS);
  }

  /*
   * The parent.  waitpid() is retried for EINTR and for nothing else: any
   * other error means it will never succeed, and retrying regardless would
   * spin until TIMEOUT 30 killed the suite -- a reported timeout being a far
   * worse diagnostic than a named failure.
   */
  do {
    waited = waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);

  if (waited != child) {
    result.how = DEATH_END_WAIT_FAILED;
    result.code = errno;
    return result;
  }

  if (WIFSIGNALED(status)) {
    result.signum = WTERMSIG(status);
    result.how = result.signum == SIGABRT ? DEATH_END_SIGABRT
                                          : DEATH_END_OTHER_SIGNAL;
  } else if (WIFEXITED(status)) {
    result.how = DEATH_END_EXITED;
    result.code = WEXITSTATUS(status);
  } else {
    /*
     * Neither exited nor signalled.  waitpid() was called without WUNTRACED
     * or WCONTINUED, so this is not reachable through this call; it is
     * classified rather than ignored so that a future edit adding either flag
     * cannot turn a merely stopped child into a silent pass.
     */
    result.how = DEATH_END_WAIT_FAILED;
    result.code = 0;
  }

  return result;
}

/*
 * 1 if calling body() in a forked child terminated that child via SIGABRT, and
 * 0 for every other outcome -- a different signal, a normal return, or a
 * harness failure.  The claim is precisely
 *
 *     WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT
 *
 * which is strictly stronger than "the child failed": a segfault, a
 * raise(SIGTERM) and an exit(1) all answer 0 here.  That precision is the
 * whole reason this harness exists rather than a CTest property.
 */
static int aborts(void (*body)(void))
{
  struct death_result result = death_run(body);

  if (result.how != DEATH_END_SIGABRT) {
    printf("           expected : termination by SIGABRT (%d)\n", SIGABRT);
    death_describe(&result);
  }
  return result.how == DEATH_END_SIGABRT ? 1 : 0;
}

/*
 * The mirror image, for the control case: 1 only if the child returned from
 * body(), exited with status 0, and was NOT signalled.  Spelled out as
 * separate claims rather than as "did not abort", because "did not abort"
 * would also accept a segfault, a non-zero exit and a fork failure.
 *
 * DEATH_END_EXITED is assigned only after WIFSIGNALED(status) has already been
 * ruled out in death_run(), so testing for it carries the !WIFSIGNALED(status)
 * half of the claim as well.
 */
static int exits_cleanly(void (*body)(void))
{
  struct death_result result = death_run(body);

  if (result.how != DEATH_END_EXITED || result.code != 0) {
    printf("           expected : return from the body, exit status 0, no"
           " signal\n");
    death_describe(&result);
  }
  return result.how == DEATH_END_EXITED && result.code == 0 ? 1 : 0;
}

/*
 * ---------------------------------------------------------------------------
 * The bodies.  One aborting input each, and nothing else.
 * ---------------------------------------------------------------------------
 * Freeing the result is unreachable wherever the assertion under test is live,
 * which is the whole point of the case.  It is there so that a build in which
 * that assertion is ABSENT leaks nothing and the case still fails HONESTLY --
 * by the child surviving -- instead of by tripping a leak checker.
 * proverr_free_handle() is a bare free() (err.c:80-83), so it tolerates the
 * NULL that err.c:29-32 or err.c:51-54 would hand back in such a build.
 *
 * Nothing in a body asserts.  An assertion there would be recorded in the
 * CHILD's private copy of testutil.h's counters and would die with the child;
 * how the child ended is the only thing that survives into the parent, and
 * that is what the parent asserts on.
 */

/* D-1: a NULL core handle.  err.c:26  assert(core != NULL) */
static void body_null_core(void)
{
  struct proverr_functions_st *handle;

  handle = proverr_new_handle(NULL, mock_dispatch_complete);
  proverr_free_handle(handle);
}

/*
 * D-2: a NULL dispatch table.  err.c:27  assert(dispatch != NULL)
 * The core handle is valid, so err.c:26 passes and the abort can only have
 * come from err.c:27.
 */
static void body_null_dispatch(void)
{
  struct proverr_functions_st *handle;

  handle = proverr_new_handle(&mock_core_primary, NULL);
  proverr_free_handle(handle);
}

/*
 * D-3: a well-formed but EMPTY table -- nothing but the { 0, NULL } sentinel.
 * Both pointers are valid, so err.c:26-27 pass; err.c:34 then ends the scan
 * immediately, leaving all three callbacks at the NULL they were initialised
 * to (err.c:21-23), and the first resolution assertion fires:
 * err.c:47  assert(c_new_error != NULL)
 *
 * An empty table is emphatically not D-2's null pointer: this input reaches
 * the scan, that one is stopped before it.  Asserting both is what proves
 * err.c distinguishes them.
 */
static void body_empty_table(void)
{
  struct proverr_functions_st *handle;

  handle = proverr_new_handle(&mock_core_primary, mock_dispatch_empty);
  proverr_free_handle(handle);
}

/*
 * D-4: every callback except OSSL_FUNC_CORE_NEW_ERROR.  The scan resolves two
 * of the three, so this isolates err.c:47  assert(c_new_error != NULL) on a
 * table that is otherwise exactly what a working core would supply.
 */
static void body_missing_new_error(void)
{
  struct proverr_functions_st *handle;

  handle = proverr_new_handle(&mock_core_primary,
                              mock_dispatch_no_new_error);
  proverr_free_handle(handle);
}

/*
 * D-5: every callback except OSSL_FUNC_CORE_SET_ERROR_DEBUG.  c_new_error
 * resolves, so err.c:47 passes and the abort is attributable to
 * err.c:48  assert(c_set_error_debug != NULL)
 */
static void body_missing_set_error_debug(void)
{
  struct proverr_functions_st *handle;

  handle = proverr_new_handle(&mock_core_primary,
                              mock_dispatch_no_set_error_debug);
  proverr_free_handle(handle);
}

/*
 * D-6: every callback except OSSL_FUNC_CORE_VSET_ERROR.  The first two
 * resolve, so err.c:47 and err.c:48 pass and the abort is attributable to
 * err.c:49  assert(c_vset_error != NULL)
 */
static void body_missing_vset_error(void)
{
  struct proverr_functions_st *handle;

  handle = proverr_new_handle(&mock_core_primary,
                              mock_dispatch_no_vset_error);
  proverr_free_handle(handle);
}

/*
 * THE CONTROL (see WHY THE NON-ABORTING CONTROL CASE IS MANDATORY, above).
 * A complete table resolves all three callbacks, so not one of the five
 * assertions in err.c:26-49 can fire and proverr_new_handle() must succeed.
 *
 * The early _exit() makes this control stronger than "did not abort": the
 * child's status is 0 only if the handle really was non-NULL, so
 * exits_cleanly() proves the valid input produced a handle at the same time as
 * it proves the harness is capable of answering "no abort".
 */
static void body_complete_table(void)
{
  struct proverr_functions_st *handle;

  handle = proverr_new_handle(&mock_core_primary, mock_dispatch_complete);
  if (handle == NULL)
    _exit(DEATH_CHILD_UNEXPECTED);
  proverr_free_handle(handle);
}

int main(void)
{
  /*
   * The project's "TEST_ASSERT(...); ret &= test;" idiom, with the accumulator
   * named all_ok rather than ret: testutil.h:134 already defines a file-scope
   * `ret`, which every assertion REASSIGNS from the counters and which
   * therefore cannot accumulate, and a local called ret would shadow it
   * (-Wshadow, measured).
   */
  int all_ok = 1;
  int observed;
  int status;

  /*
   * mock_core_reset() at the start of every case, as tests/mock_core.h asks.
   * Here it is hygiene rather than load-bearing, and deliberately so: nothing
   * in this file asserts on mock_core_obs.  proverr_new_handle() only RESOLVES
   * callbacks (err.c:34-45) and never invokes one, and in any case the child
   * receives a private copy of mock_core_obs the instant it is forked, so no
   * observation the child could record would ever reach the parent.  What the
   * parent asserts on is how the child ended, which is all that survives.
   *
   * CALL, STORE, THEN ASSERT throughout, as testutil.h requires: the harness
   * runs first and its answer is stored, and only then is the stored value
   * compared.  It also keeps the "expected/observed" detail lines immediately
   * above the verdict line they explain.
   *
   * The parent itself makes no aborting call -- every one of them happens in a
   * child -- because an abort here would take the whole test process with it
   * and the remaining cases would never run.
   */

  /*
   * A misconfiguration HINT, printed and not asserted.  NDEBUG being defined
   * for this translation unit means the target was not given the -UNDEBUG that
   * tests/CMakeLists.txt is supposed to supply (see HOW THIS TARGET IS BUILT,
   * above); a globally-defined NDEBUG -- which -DCMAKE_BUILD_TYPE=Release
   * supplies -- would have reached err.c as well, compiling its assertions
   * out and leaving all six cases below asserting a contract the binary does
   * not implement.  Measured: with err.c built -DNDEBUG all six fail and the
   * control still passes, which is a confusing picture without this line.
   *
   * It is a hint rather than an assertion on purpose.  This file can see
   * NDEBUG for itself but not for err.c's translation unit, so in the
   * contrived case where only THIS target carries -DNDEBUG the six cases
   * would legitimately pass; asserting here would fail a correct run.  The
   * verdict therefore stays with the seven real cases, which fail on their own
   * whenever the assertions are genuinely absent -- this only says why.
   */
#ifdef NDEBUG
  printf("test_err_death: NOTE -- NDEBUG is defined for this translation"
         " unit.  If the cases below fail, err.c's assertions were compiled"
         " out: register this target with COPTS -UNDEBUG and err.c among its"
         " SOURCES.\n");
#endif

  /* D-1  err.c:26  assert(core != NULL) */
  mock_core_reset();
  observed = aborts(body_null_core);
  TEST_ASSERT_INT_EQ("D-1 new_handle(NULL, complete) aborts with SIGABRT",
                     observed, 1);
  all_ok &= test;

  /* D-2  err.c:27  assert(dispatch != NULL) */
  mock_core_reset();
  observed = aborts(body_null_dispatch);
  TEST_ASSERT_INT_EQ("D-2 new_handle(core, NULL) aborts with SIGABRT",
                     observed, 1);
  all_ok &= test;

  /* D-3  err.c:47  assert(c_new_error != NULL), via an empty table */
  mock_core_reset();
  observed = aborts(body_empty_table);
  TEST_ASSERT_INT_EQ("D-3 new_handle(core, empty) aborts with SIGABRT",
                     observed, 1);
  all_ok &= test;

  /* D-4  err.c:47  assert(c_new_error != NULL) */
  mock_core_reset();
  observed = aborts(body_missing_new_error);
  TEST_ASSERT_INT_EQ("D-4 new_handle(core, no new_error) aborts with SIGABRT",
                     observed, 1);
  all_ok &= test;

  /* D-5  err.c:48  assert(c_set_error_debug != NULL) */
  mock_core_reset();
  observed = aborts(body_missing_set_error_debug);
  TEST_ASSERT_INT_EQ("D-5 new_handle(core, no set_error_debug) aborts with"
                     " SIGABRT", observed, 1);
  all_ok &= test;

  /* D-6  err.c:49  assert(c_vset_error != NULL) */
  mock_core_reset();
  observed = aborts(body_missing_vset_error);
  TEST_ASSERT_INT_EQ("D-6 new_handle(core, no vset_error) aborts with SIGABRT",
                     observed, 1);
  all_ok &= test;

  /*
   * The control.  Without it the six cases above could all be passed by a
   * harness that answered "aborted" unconditionally.
   */
  mock_core_reset();
  observed = exits_cleanly(body_complete_table);
  TEST_ASSERT_INT_EQ("control new_handle(core, complete) returns a handle,"
                     " exits 0, no signal", observed, 1);
  all_ok &= test;

  /*
   * The exit status comes from testutil.h's counters, which also fail a run
   * that asserted nothing at all -- reaching the end of main() cannot
   * manufacture a pass.  all_ok is an independent spelling of the same
   * verdict, and requiring both means no run can pass that either one calls a
   * failure.
   */
  status = TEST_REPORT("test_err_death");
  return status != 0 || !all_ok ? 1 : 0;
}

#else                           /* _WIN32 */

/*
 * The non-POSIX fallback.  DEAD CODE in practice, and documented as such:
 * tests/CMakeLists.txt registers this target inside if(UNIX), so a host
 * without POSIX process control never configures it, let alone builds or runs
 * it.  Non-registration is the mechanism on purpose -- skipping a registered
 * test is precisely what this suite is forbidden to do, and a target that does
 * not exist cannot be mistaken for one that was weakened.
 *
 * If it is ever reached anyway it must not pretend to pass.  It asserts
 * nothing, and testutil.h's exit-status contract fails a run in which no
 * assertion executed, so TEST_REPORT() returns a failing status and prints the
 * reason.  A vacuous pass here would be worse than no test at all: it would
 * report that err.c's assert() contract had been verified on a host where it
 * cannot be.
 */
int main(void)
{
  printf("test_err_death: fork()/waitpid() are unavailable on this host, so"
         " err.c's assert() contract (err.c:26, :27, :47, :48, :49) CANNOT be"
         " verified here.\n");
  printf("test_err_death: this target is meant to be registered only under"
         " CMake's if(UNIX) guard.  Reaching this code means it was registered"
         " anyway, so it FAILS deliberately rather than passing without"
         " asserting anything.\n");
  return TEST_REPORT("test_err_death (unsupported host)");
}

#endif                          /* _WIN32 */
