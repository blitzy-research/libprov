/* CC0 license applied, see LICENSE */

/*
 * _POSIX_C_SOURCE must be defined BEFORE THE FIRST #include in this file, and
 * nothing but comments may precede it.  A feature-test macro selects which
 * declarations the C library's headers make visible, so defining it after a
 * header had already been processed would come too late to have any effect.
 * _POSIX_C_SOURCE=200809L selects the POSIX.1-2008 feature-test level.  That is
 * not the oldest level that would do: fork(), waitpid(), the wait-status macros
 * and _exit() have been in POSIX since POSIX.1-1990 and are visible at
 * _POSIX_C_SOURCE=1.  200809L is chosen because it is the current, universally
 * available baseline and asking for it costs nothing, not because anything
 * below needs it.  What the line is FOR is visibility: a glibc host may expose
 * these declarations under a plain -std=c99 build anyway, and a stricter C
 * library will not, so defining the macro is what makes the file portable
 * rather than merely lucky.
 */
#define _POSIX_C_SOURCE 200809L

/*
 * The POSITIVE assertion of err.c's assert() contract.
 *
 * proverr_new_handle() is guarded by five assertions: the core handle
 * (err.c:26) and the dispatch table (err.c:27) must not be NULL, and the
 * dispatch scan at err.c:34-45 must have resolved all three core callbacks
 * (err.c:47, err.c:48, err.c:49).  Where those assertions are live -- which is
 * the default build -- an invalid input does not return an error code, it
 * ABORTS.  This file asserts that the abort really happens, for every one of
 * those inputs.  Its harness is file-local and shared with nothing: the only
 * other place in the suite that forks is param_util.h's protected-boundary
 * oracle, compiled into the two numeric targets alone, whose subject is num.c's
 * memory safety rather than err.c's assertions and whose child looks for a
 * SIGSEGV-class fault rather than SIGABRT.  Neither harness is a candidate for
 * being folded into the other.
 *
 * The complementary half of the contract belongs to test_err_guards.c: with
 * NDEBUG defined the assertions vanish, the guard at err.c:51-54 becomes
 * reachable, and the same inputs return NULL instead.  The two halves are
 * mutually exclusive under any one set of preprocessor flags, which is exactly
 * why they are two files and not two halves of one.
 *
 * WHY A HAND-ROLLED fork()/waitpid() HARNESS AND NOT A CTest PROPERTY
 *
 * Please do not "simplify" this file into a CTest property.  Neither plausible
 * candidate works against a SIGABRT child:
 *
 *   PASS_REGULAR_EXPRESSION, matching the assertion message -- documented to
 *     pass because "the process exit code is ignored" -- still fails, reported
 *     by CTest as "(Subprocess aborted)".
 *   WILL_FAIL TRUE -- documented to invert a failure into a pass -- fails in
 *     exactly the same way.
 *
 * The documented "exit code is ignored" governs exit CODES and not SIGNAL
 * terminations: CTest treats an abnormally-terminated child as a hard failure
 * either way.  The harness below is therefore not a stylistic preference but
 * the only mechanism that works, and it is strictly more precise as well,
 * because it distinguishes "aborted FOR THE EXPECTED REASON" from "died some
 * other way" -- a distinction neither property can express, and the difference
 * between a test that pins err.c's contract and one that would also pass on a
 * segfault.
 *
 * HOW THIS TARGET MUST BE BUILT -- err.c COMPILED INTO IT, UNDER A CAPABILITY
 * PROBE
 *
 *   err.c must be compiled INTO this target rather than reached through the
 *     libprov library, because the NDEBUG state that matters is the one in
 *     effect for the translation unit holding the assert() -- and libprov's
 *     err.c.o was already compiled once, with the project's own flags, so no
 *     definition on the *test* target could reach it.
 *   -UNDEBUG must apply to that compilation, so the assertions stay live even
 *     in a configuration that defines NDEBUG globally, which
 *     -DCMAKE_BUILD_TYPE=Release does.  Without it a Release build would turn
 *     every abort into the graceful NULL of err.c:51-54 and every assertion in
 *     this file would fail.
 *   A TIMEOUT on the registered test makes a harness defect degrade into a
 *     reported timeout instead of a hung suite.  It is a safety net, not a
 *     budget: the whole file completes in a few milliseconds.
 *   Registration must sit behind a probe of the interfaces this file actually
 *     uses -- fork/waitpid with the wait-status macros, SIGABRT, and
 *     setrlimit(RLIMIT_CORE) -- which tests/CMakeLists.txt performs as
 *     LIBPROV_HAVE_POSIX_DEATH_HARNESS, at this file's own _POSIX_C_SOURCE
 *     level.
 *     A platform's name is not that proof: on a UNIX-like host that does not
 *     declare setrlimit(), an if(UNIX) gate would have registered this target
 *     and then failed the BUILD.  Where the probe fails the target is NOT
 *     REGISTERED AT ALL.  It is never registered-and-skipped and never allowed
 *     to fail; configuration still succeeds and every other target runs
 *     normally.
 *
 * Nothing here links or calls libcrypto.  The core handle and the dispatch
 * tables come from tests/mock_core.h, whose OSSL_CORE_HANDLE is a test-local
 * definition of a type <openssl/core.h> leaves incomplete, and the accessors
 * err.c uses expand to static inline code.  <openssl/params.h> is not included
 * by this file; prov/err.h reaches it transitively through
 * <openssl/core_dispatch.h> and <openssl/indicator.h>, which is the project
 * header's own include graph.  The OSSL_PARAM_ families it declares are
 * libcrypto functions and a declaration links nothing -- none of them is ever
 * called.
 *
 * DEBUGGING.  This harness forks, so a debugger stops in the PARENT by default
 * and the abort is never seen.  Tell it to follow the child:
 *
 *     gdb --args ./build/tests/test_err_death
 *     (gdb) set follow-fork-mode child
 *
 * WHY THE NON-ABORTING CONTROL CASE IS MANDATORY.  Six cases that all expect
 * an abort cannot tell a correct harness from one that answers "aborted"
 * unconditionally: a harness stuck at "yes" would pass all six and prove
 * nothing.  The control feeds the harness a VALID input and requires the child
 * to exit 0 with NO signal, so both answers the harness can give are exercised
 * and a stuck harness fails immediately.  Do not remove it.
 */

#include "testutil.h"
#include "mock_core.h"
#include "prov/err.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>

/*
 * The POSIX headers are included INSIDE the guard on purpose.  <sys/wait.h>,
 * <unistd.h>, <sys/types.h> and <sys/resource.h> do not exist on a non-POSIX
 * host, so including them unconditionally would make the fallback at the foot
 * of this file unreachable: the compile would fail on a missing header long
 * before the preprocessor reached the alternative.  <signal.h> and <errno.h>
 * are ISO C and stay above.
 *
 * <sys/resource.h> is here for the setrlimit(RLIMIT_CORE) call in the forked
 * child inside death_run(): see the comment there for the artifact this
 * harness would otherwise leave behind on every run.  It is one of the
 * interfaces tests/CMakeLists.txt probes before registering this target, so a
 * host that lacks it leaves the target unregistered instead of reaching this
 * include and failing the build.
 */
#ifndef _WIN32

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/resource.h>

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
     * The child.  Every aborting case in this file kills it with SIGABRT, and
     * SIGABRT is a core-dumping signal, so an inherited RLIMIT_CORE lets each
     * EXPECTED abort write a core file.  Measured before this call existed: one
     * direct run of test_err_death left 6 dumps of 454656 bytes each, ~2.7 MB
     * per run, at whatever /proc/sys/kernel/core_pattern points to -- and on a
     * host whose pattern is the default bare "core" that is inside the CTest
     * working directory, where it also shows up in git status.  AAP 0.7.2
     * requires a run to leave no artifact behind, so the limit is dropped to
     * zero here, in the child only, before anything can fault.
     *
     * This changes only whether the kernel writes the image: the child is still
     * killed by SIGABRT, so WIFSIGNALED()/WTERMSIG() below observe exactly what
     * they observed before, and the parent's limits are untouched because
     * setrlimit() applies to the calling process after fork().
     *
     * The result is deliberately cast away rather than tested.  A host that
     * refuses to lower RLIMIT_CORE (which cannot happen for a soft-limit
     * decrease under POSIX) would merely go back to writing the dumps it wrote
     * before; that is a hygiene regression, not a wrong verdict, and failing
     * the abort contract over it would be a false negative.
     */
    struct rlimit death_no_core;

    death_no_core.rlim_cur = 0;
    death_no_core.rlim_max = 0;
    (void)setrlimit(RLIMIT_CORE, &death_no_core);

    /*
     * Its stderr goes to /dev/null so that the assertion messages this file
     * EXPECTS -- glibc's "Assertion `core != NULL' failed" and its kin -- do
     * not pollute the log of a passing test.
     *
     * The freopen() result has to be consumed, because glibc declares
     * freopen() warn_unused_result.  It is TESTED rather than cast away: if
     * the redirection failed, the child reports that with a status of its own
     * instead of quietly leaking assertion text into the log, and the parent
     * names it.
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
   * spin until the registered timeout killed the suite -- a reported timeout
   * being a far worse diagnostic than a named failure.
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
 * The bodies.  One aborting input each, and nothing else.
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
  int all_ok = 1;
  int observed;
  int status;

  /*
   * mock_core_reset() at the start of every case, as tests/mock_core.h asks.
   * Here it is hygiene rather than load-bearing: nothing in this file asserts
   * on mock_core_obs.  proverr_new_handle() only RESOLVES callbacks
   * (err.c:34-45) and never invokes one, and the child receives a private copy
   * of mock_core_obs the instant it is forked, so no observation the child
   * could record would ever reach the parent.  What the parent asserts on is
   * how the child ended, which is all that survives.
   *
   * CALL, STORE, THEN ASSERT throughout: the harness runs first and its answer
   * is stored, and only then is the stored value compared.
   *
   * The parent itself makes no aborting call -- every one of them happens in a
   * child -- because an abort here would take the whole test process with it
   * and the remaining cases would never run.
   */

  /*
   * A misconfiguration HINT, printed and not asserted.  NDEBUG being defined
   * for this translation unit means the target was not given the -UNDEBUG this
   * file requires (see HOW THIS TARGET MUST BE BUILT, above); a
   * globally-defined NDEBUG -- which -DCMAKE_BUILD_TYPE=Release supplies --
   * would reach err.c as well, compiling its assertions out and leaving all
   * six cases below asserting a contract the binary does not implement, while
   * the control still passes.
   *
   * It is a hint rather than an assertion on purpose.  This file can see
   * NDEBUG for itself but not for err.c's translation unit, so in the
   * contrived case where only THIS target carries -DNDEBUG the six cases would
   * legitimately pass; asserting here would fail a correct run.  The verdict
   * stays with the seven real cases, which fail on their own whenever the
   * assertions are genuinely absent -- this only says why.
   */
#ifdef NDEBUG
  printf("test_err_death: NOTE -- NDEBUG is defined for this translation"
         " unit.  If the cases below fail, err.c's assertions were compiled"
         " out: register this target with COPTS -UNDEBUG and err.c among its"
         " SOURCES.\n");
#endif

  mock_core_reset();
  observed = aborts(body_null_core);
  TEST_ASSERT_INT_EQ("D-1 new_handle(NULL, complete) aborts with SIGABRT",
                     observed, 1);
  all_ok &= test;

  mock_core_reset();
  observed = aborts(body_null_dispatch);
  TEST_ASSERT_INT_EQ("D-2 new_handle(core, NULL) aborts with SIGABRT",
                     observed, 1);
  all_ok &= test;

  mock_core_reset();
  observed = aborts(body_empty_table);
  TEST_ASSERT_INT_EQ("D-3 new_handle(core, empty) aborts with SIGABRT",
                     observed, 1);
  all_ok &= test;

  mock_core_reset();
  observed = aborts(body_missing_new_error);
  TEST_ASSERT_INT_EQ("D-4 new_handle(core, no new_error) aborts with SIGABRT",
                     observed, 1);
  all_ok &= test;

  mock_core_reset();
  observed = aborts(body_missing_set_error_debug);
  TEST_ASSERT_INT_EQ("D-5 new_handle(core, no set_error_debug) aborts with"
                     " SIGABRT", observed, 1);
  all_ok &= test;

  mock_core_reset();
  observed = aborts(body_missing_vset_error);
  TEST_ASSERT_INT_EQ("D-6 new_handle(core, no vset_error) aborts with SIGABRT",
                     observed, 1);
  all_ok &= test;

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
 * The non-POSIX fallback.  DEAD CODE wherever the target is registered as this
 * file requires -- behind tests/CMakeLists.txt's
 * LIBPROV_HAVE_POSIX_DEATH_HARNESS
 * probe -- because a host without POSIX process control fails that probe and
 * then never configures the target, let alone builds or runs it.
 * Non-registration is the mechanism on purpose: skipping a registered test is
 * precisely what this suite is forbidden to do, and a target that does not
 * exist cannot be mistaken for one that was weakened.
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
  printf("test_err_death: this target is meant to be registered only when"
         " CMake's LIBPROV_HAVE_POSIX_DEATH_HARNESS probe succeeds.  Reaching"
         " this"
         " code means it was registered anyway, so it FAILS deliberately rather"
         " than passing without asserting anything.\n");
  return TEST_REPORT("test_err_death (unsupported host)");
}

#endif                          /* _WIN32 */
