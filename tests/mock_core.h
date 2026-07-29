/* CC0 license applied, see LICENCE.md */

#ifndef LIBPROV_TESTS_MOCK_CORE_H
#define LIBPROV_TESTS_MOCK_CORE_H

/*
 * ===========================================================================
 * tests/mock_core.h -- the hand-built OpenSSL core that libprov's error tests
 *                      are run against
 * ===========================================================================
 *
 * err.c exists to capture three callbacks out of the OSSL_DISPATCH table that
 * the OpenSSL core hands a provider at initialization, and to forward calls to
 * them.  Testing it therefore means playing the part of the core.  This header
 * is the whole of that part: a test-local OSSL_CORE_HANDLE, a set of recording
 * stub callbacks, a call-sequence recorder, a reset helper, and nine
 * ready-made OSSL_DISPATCH tables.  It is included by every program that tests
 * err.c -- test_err_handle.c, test_err_raise.c, test_err_guards.c,
 * test_err_death.c and test_err_alloc.c -- and it is the only OpenSSL core
 * those programs ever see.
 *
 * No user-specified rules exist for this project: the rules facility reports
 * "No user rules provided".  Nothing here was therefore shaped by a project
 * rule, and none has been invented; the file is held to ordinary
 * enterprise-standard C practice.  The constraints it does honour come from
 * the project's testing requirements and each is stated below next to the code
 * that implements it.
 *
 * ---------------------------------------------------------------------------
 * 1.  The requirement this file exists to satisfy, quoted in full
 * ---------------------------------------------------------------------------
 *
 *     "Where OpenSSL types are needed, construct them directly or mock them
 *      (e.g., a hand-built dispatch table with stub callbacks); do not add a
 *      dependency on a running provider or on libcrypto functions."
 *
 * The parenthetical is taken as a prescription rather than a suggestion: what
 * follows is literally a statically-initialised OSSL_DISPATCH array of stub
 * function pointers plus a test-local OSSL_CORE_HANDLE.  Three things follow
 * from that requirement and are absolute:
 *
 *   - <openssl/params.h> is NOT included, here or by any test.  Its
 *     OSSL_PARAM_get_*, OSSL_PARAM_set_* and OSSL_PARAM_construct_* families
 *     are libcrypto functions, and libprov's provnum_ family exists precisely
 *     to replace them, so calling them would measure upstream OpenSSL rather
 *     than libprov -- and would link libcrypto into a test suite that must not
 *     need it.
 *
 *   - No running provider, no provider-init sequence, no OSSL_LIB_CTX and no
 *     real OpenSSL error queue is involved.  Only OpenSSL *headers* are
 *     consumed, and the accessors err.c calls -- OSSL_FUNC_core_new_error()
 *     and friends -- expand from OSSL_CORE_MAKE_FUNC to static inline
 *     definitions, so they need no link-time symbol.  A test binary built with
 *     this header links libc and nothing else.
 *
 *   - No third-party mocking library is introduced.  The repository has no
 *     package manifest and no dependency of any kind, and this header does not
 *     become the first one.
 *
 * ---------------------------------------------------------------------------
 * 2.  The error handle is OPAQUE, so every check has to be behavioural
 * ---------------------------------------------------------------------------
 *
 * struct proverr_functions_st -- the four-member structure holding the core
 * handle and the three resolved callbacks -- is defined only inside err.c
 * (err.c:7-12).  include/prov/err.h:58 merely forward-declares it.  A test
 * consequently CANNOT read handle->core or handle->core_new_error: that is a
 * compile error on an incomplete type, not a style choice.
 *
 * Everything a test needs to know about a handle therefore has to be learned
 * by USING it and watching what arrives here.  That single fact is the reason
 * for three otherwise-surprising design decisions:
 *
 *   - every stub records the core pointer it was handed, so "the handle stored
 *     the core it was given" becomes an observable claim (assert pointer
 *     identity against &mock_core_primary);
 *
 *   - there are TWO distinguishable new_error stubs, so "the later duplicate
 *     table entry won" becomes observable through *which* stub fired;
 *
 *   - there is a call-sequence recorder, so the comma-expression evaluation
 *     order that IS the contract of ERR_raise_data() becomes observable.
 *
 * ---------------------------------------------------------------------------
 * 3.  The observation protocol: reset, configure, exercise, assert
 * ---------------------------------------------------------------------------
 *
 * Every recorded fact lands in the single object mock_core_obs.  Read its
 * fields only after the call under test has returned, and clear it with
 * mock_core_reset() at the START of every case -- not at the end, where a
 * mid-case early return would skip it:
 *
 *     #include "testutil.h"                          (always included first)
 *     #include "mock_core.h"
 *
 *     static const int expected[] = { MOCK_CORE_ORD_NEW_ERROR,
 *                                     MOCK_CORE_ORD_SET_ERROR_DEBUG,
 *                                     MOCK_CORE_ORD_VSET_ERROR };
 *     struct proverr_functions_st *handle;
 *
 *     mock_core_reset();                                        (1) clear
 *     handle = proverr_new_handle(&mock_core_primary,
 *                                 mock_dispatch_complete);      (2) build
 *     TEST_ASSERT_PTR_NOT_NULL("handle", handle);
 *
 *     ERR_raise(handle, 42u);                                   (3) exercise
 *
 *     TEST_ASSERT_SIZE_EQ("calls", mock_core_obs.seq_len, (size_t)3);
 *     TEST_ASSERT_MEM_EQ("order", mock_core_obs.seq, expected,
 *                        sizeof expected);                      (4) assert
 *     TEST_ASSERT_UINT_EQ("reason", mock_core_obs.reason, 42u);
 *     TEST_ASSERT_PTR_NULL("fmt", mock_core_obs.fmt_ptr);
 *     TEST_ASSERT_PTR_EQ("core", mock_core_obs.new_error_core,
 *                        &mock_core_primary);
 *     proverr_free_handle(handle);
 *
 * The order matters for a second reason as well: C does not specify the order
 * in which function-call arguments are evaluated, so reading an observation in
 * the same expression that triggers it is a bug.  Exercise first, then assert.
 *
 * ---------------------------------------------------------------------------
 * 4.  Isolation and parallel safety
 * ---------------------------------------------------------------------------
 *
 * Every object below has internal linkage, so each test executable owns its
 * own private copy of the observation state and no two executables can
 * interfere: "ctest -j N" is safe.  Nothing here allocates, opens a file,
 * reads the environment, forks, installs a signal handler, or keeps state
 * across a reset.
 *
 * The two mechanisms in this suite that DO have global side effects are
 * deliberately absent from this shared header and stay file-local to the one
 * executable that needs them: the countdown malloc() interposer belongs to
 * tests/test_err_alloc.c, and the fork()/waitpid() death harness belongs to
 * tests/test_err_death.c.  Hoisting either one here would perturb the
 * allocation or process behaviour of every other test that includes it.
 *
 * Also deliberately absent, because each is another fixture's job: assertion
 * machinery (tests/testutil.h), OSSL_PARAM construction (tests/param_util.h),
 * and any main().  This header does not assert anything itself -- its job is
 * to make specific values observable so that its consumers can assert them,
 * which is what keeps them from degenerating into tests that merely check that
 * code ran without crashing.
 *
 * ---------------------------------------------------------------------------
 * 5.  Include guards, and why the project's public headers have none
 * ---------------------------------------------------------------------------
 *
 * include/prov/err.h and include/prov/num.h deliberately carry no include
 * guards and get away with it, err.h because it precedes each of its #defines
 * with a matching #undef.  This header takes the opposite and ordinary
 * position and DOES guard, because it defines objects with internal linkage
 * and a struct type, all of which would break on a second inclusion.  The
 * guard above this comment is that guard, and a double inclusion is part of
 * this file's regression checks.
 */

#include <stdarg.h>            /* va_list, va_arg -- the vset_error stub    */
#include <stdint.h>            /* uint32_t -- the reason argument           */
#include <stddef.h>            /* size_t, NULL                             */
#include <string.h>            /* memcpy, memset, strlen                   */
#include "prov/err.h"          /* the API under test                       */

/*
 * Each of the four standard headers above is needed directly, and each is
 * included even though "prov/err.h" happens to reach some of them anyway:
 * <stdint.h> from include/prov/err.h:3 and <stdarg.h> from
 * <openssl/core_dispatch.h>.  Relying on a transitive include is relying on
 * somebody else's include list not changing.
 *
 * "prov/err.h" then supplies everything OpenSSL-shaped that this file uses:
 * <openssl/core.h> for OSSL_DISPATCH and the incomplete OSSL_CORE_HANDLE, and
 * <openssl/core_dispatch.h> for the OSSL_FUNC_CORE_* ids, the
 * OSSL_FUNC_core_*_fn typedefs and the accessors err.c resolves through.
 * <openssl/params.h> is deliberately NOT among them -- see section 1.
 */

/*
 * ---------------------------------------------------------------------------
 * "Maybe unused", spelled portably.
 *
 * Not every consumer uses every stub and every table -- test_err_death.c wants
 * the incomplete tables, test_err_raise.c wants the complete one -- and an
 * unused static function defined in a header draws -Wunused-function under
 * plain -Wall -Wextra.  (Unused static const objects are quieter: GCC reports
 * those only from -Wunused-const-variable=2 upwards.  Both are marked anyway,
 * so the header stays silent however strictly a consumer is compiled.)
 *
 * This is spelled out here rather than borrowed: OpenSSL's own ossl_unused is
 * an internal spelling that a test has no business depending on.
 * ---------------------------------------------------------------------------
 */
#if defined(__GNUC__) || defined(__clang__)
# define MOCK_CORE_MAYBE_UNUSED __attribute__((unused))
#else
# define MOCK_CORE_MAYBE_UNUSED
#endif

/*
 * ---------------------------------------------------------------------------
 * Call-sequence ordinals.
 *
 * Each stub appends one of these to mock_core_obs.seq as it runs, which is how
 * the evaluation order of the ERR_raise_data() comma expression
 * (include/prov/err.h:49-52) is made visible.  A correct ERR_raise() or
 * ERR_raise_data() through a handle built from a complete table produces
 * exactly:
 *
 *     MOCK_CORE_ORD_NEW_ERROR, MOCK_CORE_ORD_SET_ERROR_DEBUG,
 *     MOCK_CORE_ORD_VSET_ERROR
 *
 * MOCK_CORE_ORD_ALT_NEW_ERROR is the odd one out and is the point of the
 * exercise: the alternate new_error stub has an ordinal of its OWN rather than
 * sharing 1, so a table that resolved to the wrong stub shows up as a wrong
 * ordinal in the sequence instead of being indistinguishable from a correct
 * run.  It must never appear in a passing test.
 * ---------------------------------------------------------------------------
 */
#define MOCK_CORE_ORD_NEW_ERROR       1
#define MOCK_CORE_ORD_SET_ERROR_DEBUG 2
#define MOCK_CORE_ORD_VSET_ERROR      3
#define MOCK_CORE_ORD_ALT_NEW_ERROR   4

/*
 * How many ordinals mock_core_obs.seq holds.  Three per raise is the natural
 * unit, so this is room for ten raises in one case with slack to spare; an
 * overrun is counted in mock_core_obs.seq_dropped rather than silently
 * discarded or written out of bounds.
 */
#define MOCK_CORE_SEQ_MAX 32

/*
 * Capacity of each recorded string copy, NUL included.  The longest string
 * these stubs ever see is the OPENSSL_FILE of a test source, which is a path
 * the build system passes to the compiler, so this is generous rather than
 * tight.  A longer string is truncated, never overrun, and the untruncated
 * pointer is recorded alongside the copy in every case.
 */
#define MOCK_CORE_TEXT_MAX 256

/*
 * A function id the OpenSSL core will never assign, for the unknown-id
 * tolerance table.  Ids 1-1023 are reserved for core-to-provider functions and
 * <openssl/core_dispatch.h> currently defines up to 120 of them, so 9999 is
 * both out of that range and unmistakably deliberate.
 */
#define MOCK_CORE_ID_UNASSIGNED 9999

/*
 * Vararg-consumption modes for the vset_error stub; see section 7 at
 * mock_core_obs below.  MOCK_CORE_VA_NONE is zero on purpose, so that
 * mock_core_reset() restores the safe default without needing to know about
 * it.
 */
#define MOCK_CORE_VA_NONE         0
#define MOCK_CORE_VA_INT_THEN_STR 1

/*
 * ---------------------------------------------------------------------------
 * The test-local core handle.
 *
 * <openssl/core.h> declares "typedef struct ossl_core_handle_st
 * OSSL_CORE_HANDLE;" and never defines the struct: the type is incomplete
 * everywhere outside the OpenSSL core itself.  What follows is therefore a
 * DEFINITION and not a redefinition, and it is exactly what makes a test able
 * to own a core handle without a running provider.
 *
 * The tag member is not read by err.c -- err.c only ever passes the pointer
 * through -- but it gives the two instances below distinct contents as well as
 * distinct addresses, so a failure dump is readable and a debugger session is
 * unambiguous.  The claim tests actually assert is pointer IDENTITY, which is
 * the right claim for a contract that passes a pointer through rather than
 * copying what it points at.
 * ---------------------------------------------------------------------------
 */
struct ossl_core_handle_st {
  int tag;
};

#define MOCK_CORE_TAG_PRIMARY   0x11
#define MOCK_CORE_TAG_ALTERNATE 0x22

/*
 * The handle a test normally passes to proverr_new_handle().  Not const: err.c
 * takes a "const OSSL_CORE_HANDLE *", and a pointer to a non-const object
 * converts to that implicitly, whereas the reverse would force a cast on
 * anyone who ever needs to write to the tag.
 */
MOCK_CORE_MAYBE_UNUSED
static OSSL_CORE_HANDLE mock_core_primary = { MOCK_CORE_TAG_PRIMARY };

/*
 * A second, distinct core handle.  Its purpose is to make "the handle stored
 * the core it was given" a falsifiable claim rather than a vacuous one: a test
 * that builds a handle from &mock_core_primary and asserts pointer identity
 * against it is only meaningful because another core handle existed that the
 * assertion could have caught.  It is also what a duplicated handle is checked
 * against when proving that proverr_dup_handle() copied the core across.
 */
MOCK_CORE_MAYBE_UNUSED
static OSSL_CORE_HANDLE mock_core_alternate = { MOCK_CORE_TAG_ALTERNATE };

/*
 * ---------------------------------------------------------------------------
 * Everything the stubs record.
 *
 * One aggregate rather than a scatter of separate objects, for one reason
 * above all others: "the reset helper clears every field" is then something a
 * reader can verify at a glance instead of having to audit a list.
 *
 * Fields are grouped by the stub that writes them.  All of them are outputs
 * except va_mode, which is the single input a test may set -- see section 7
 * below.
 * ---------------------------------------------------------------------------
 */
struct mock_core_observations {
  /*
   * 1.  The primary new_error stub (err.c:87 forwards to it).
   */
  unsigned long new_error_calls;
  const OSSL_CORE_HANDLE *new_error_core;

  /*
   * 2.  The alternate new_error stub.  A correct run NEVER touches these:
   *     they stay at zero and NULL, which is precisely the assertion the
   *     unknown-id, duplicate-id and after-sentinel tables are built to make.
   */
  unsigned long alt_new_error_calls;
  const OSSL_CORE_HANDLE *alt_new_error_core;

  /*
   * 3.  The set_error_debug stub (err.c:93 forwards to it).
   *
   *     Both the pointer and a copy of each string are kept.  The pointer
   *     settles pass-through: ERR_raise_data() hands over OPENSSL_FILE and
   *     OPENSSL_FUNC, which are compile-time constants at the call site, so a
   *     test can assert identity with its own __FILE__.  The copy settles
   *     content at the moment of the call, independently of anything that
   *     might later happen to the caller's storage.
   *
   *     line is a plain int and is stored verbatim, so INT_MIN and INT_MAX
   *     travel through unchanged and a truncating or widening bug shows up.
   */
  unsigned long set_error_debug_calls;
  const OSSL_CORE_HANDLE *set_error_debug_core;
  const char *file_ptr;
  char file_text[MOCK_CORE_TEXT_MAX];
  int line;
  const char *func_ptr;
  char func_text[MOCK_CORE_TEXT_MAX];

  /*
   * 4.  The vset_error stub (err.c:102 forwards to it).
   *
   *     reason is a uint32_t and is stored verbatim, so 0 and UINT32_MAX
   *     travel through unchanged.
   *
   *     fmt is recorded as a POINTER first and foremost, because its identity
   *     is the contract: ERR_raise() supplies NULL for it
   *     (include/prov/err.h:47) while ERR_raise_data() supplies the caller's
   *     own string, and those two cases have to be distinguishable.  fmt_text
   *     is a convenience for the non-NULL case and is left empty when fmt is
   *     NULL.
   */
  unsigned long vset_error_calls;
  const OSSL_CORE_HANDLE *vset_error_core;
  uint32_t reason;
  const char *fmt_ptr;
  char fmt_text[MOCK_CORE_TEXT_MAX];

  /*
   * 5.  Opt-in vararg recovery.  va_mode is the ONE input field: a test sets
   *     it after mock_core_reset() and before the call.  The rest are outputs.
   *     va_consumed says whether the stub actually traversed the list, so a
   *     test can prove the recovery happened rather than assuming it.
   */
  int va_mode;
  int va_consumed;
  int va_int;
  const char *va_str_ptr;
  char va_str_text[MOCK_CORE_TEXT_MAX];

  /*
   * 6.  The call-sequence recorder: which stub ran, in which order.  seq_len
   *     is how many ordinals were stored; seq_dropped is how many did not fit
   *     and is expected to be zero -- a non-zero value means the case
   *     overflowed the recorder and its order assertion is incomplete, which
   *     is worth knowing rather than hiding.
   */
  int seq[MOCK_CORE_SEQ_MAX];
  size_t seq_len;
  unsigned long seq_dropped;
};

/*
 * The observation state itself.  Internal linkage, so every test executable
 * gets its own; zero-initialised by the language before main() runs, which is
 * the same state mock_core_reset() restores.
 */
MOCK_CORE_MAYBE_UNUSED
static struct mock_core_observations mock_core_obs;

/*
 * ---------------------------------------------------------------------------
 * 7.  Vararg recovery, and why it is opt-in
 * ---------------------------------------------------------------------------
 *
 * A va_list may be traversed once, and only by someone who knows the exact
 * shape of what was passed.  The vset_error stub cannot work that out for
 * itself: it is handed a format string that may legitimately be NULL
 * (include/prov/err.h:47 makes ERR_raise() pass NULL), and even a non-NULL one
 * is not something a stub should be parsing.  Traversing unconditionally would
 * therefore be undefined behaviour on the common case.
 *
 * So the stub consumes nothing unless told to.  A test that raised, say,
 *
 *     ERR_raise_data(handle, 7u, "%d %s", 42, "detail");
 *
 * asks for the two arguments back like this:
 *
 *     mock_core_reset();
 *     mock_core_obs.va_mode = MOCK_CORE_VA_INT_THEN_STR;
 *     ERR_raise_data(handle, 7u, "%d %s", 42, "detail");
 *     TEST_ASSERT_INT_EQ("varargs traversed", mock_core_obs.va_consumed, 1);
 *     TEST_ASSERT_INT_EQ("first vararg", mock_core_obs.va_int, 42);
 *     TEST_ASSERT_STR_EQ("second vararg", mock_core_obs.va_str_text,
 *                        "detail");
 *
 * Set va_mode AFTER the reset, since the reset restores MOCK_CORE_VA_NONE, and
 * set it ONLY when the varargs really are an int followed by a string pointer.
 * Requesting a mode that does not match what was passed is undefined
 * behaviour, exactly as it would be in any other va_arg() consumer.
 * ---------------------------------------------------------------------------
 */

/*
 * Copy a string into fixed storage, truncating rather than overrunning, and
 * always NUL-terminating.  A NULL source yields an empty string; the caller
 * records the pointer separately, so emptiness here is never confused with a
 * NULL argument.
 *
 * memcpy() with an explicit terminator rather than strncpy(): strncpy() would
 * leave the buffer unterminated on an exact-length source, and GCC's
 * -Wstringop-truncation would rightly complain about the usual workarounds.
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
  memcpy(buffer, text, length);
  buffer[length] = '\0';
}

/*
 * Append one ordinal to the call sequence, or count the overflow.  Bounded by
 * construction: seq_len is only ever incremented inside the guarded branch, so
 * it cannot reach MOCK_CORE_SEQ_MAX and index out of range.
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
 * ---------------------------------------------------------------------------
 * Return the observation state to its initial condition.  Call it at the START
 * of every case: that way a case that returns early cannot leak its
 * observations into the next one, which is what keeps the cases inside one
 * executable independent of each other and of their order.
 *
 * The two-step body is deliberate and neither step is redundant:
 *
 *   1. memset() clears the whole object, including any padding and including
 *      any field a later edit adds to the struct but forgets to add here.
 *      That is the completeness guarantee, and it is why <string.h> is
 *      included.
 *
 *   2. The explicit assignments then set the pointer members to NULL and the
 *      scalars to their documented defaults.  All-bits-zero is the null
 *      pointer on every platform this suite will ever see, but C does not
 *      promise it, and a fixture whose correctness rests on an unpromised
 *      representation is a poor foundation for a suite whose whole purpose is
 *      to pin down exact behaviour.
 *
 * Note that va_mode is reset to MOCK_CORE_VA_NONE along with everything else,
 * so a test wanting vararg recovery sets it after calling this.
 * ---------------------------------------------------------------------------
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
 * ===========================================================================
 * The stub callbacks.
 *
 * Each signature matches its OSSL_CORE_MAKE_FUNC declaration in
 * <openssl/core_dispatch.h> exactly.  That is not cosmetic: the dispatch
 * tables below store these as "void (*)(void)", err.c casts the pointer back
 * with OSSL_FUNC_core_new_error() and friends before calling it, and calling a
 * function through a pointer to an incompatible type is undefined behaviour.
 * mock_core_signature_check() below turns a drift in any of these signatures
 * into a compile-time diagnostic rather than a mystery at run time.
 *
 * None of them asserts anything, formats anything, or fails.  Each records
 * what it was handed and returns, so that a consumer decides what the recorded
 * values must be.
 * ===========================================================================
 */

/*
 * OSSL_FUNC_CORE_NEW_ERROR (id 5): the primary stub, and the one every
 * correctly-resolved table ends up bound to.
 */
MOCK_CORE_MAYBE_UNUSED
static void mock_core_new_error(const OSSL_CORE_HANDLE *prov)
{
  mock_core_obs.new_error_calls++;
  mock_core_obs.new_error_core = prov;
  mock_core_record(MOCK_CORE_ORD_NEW_ERROR);
}

/*
 * OSSL_FUNC_CORE_NEW_ERROR (id 5): the ALTERNATE stub.  Interchangeable with
 * the primary as far as err.c is concerned, and distinguishable from it as far
 * as a test is concerned, which is the entire point.  It appears in three
 * tables and a passing test never sees it run:
 *
 *   - mock_dispatch_unknown_ids binds it to ids err.c does not recognise, so
 *     zero calls prove the switch at err.c:35-45 -- which has no default
 *     label -- really does ignore them;
 *
 *   - mock_dispatch_duplicate_ids binds it to an EARLIER id 5 entry than the
 *     primary, so zero calls prove the later assignment at err.c:37 overwrote
 *     the earlier one;
 *
 *   - mock_dispatch_after_sentinel binds it beyond the { 0, NULL } terminator,
 *     so zero calls prove the loop at err.c:34 stopped there.
 */
MOCK_CORE_MAYBE_UNUSED
static void mock_core_alt_new_error(const OSSL_CORE_HANDLE *prov)
{
  mock_core_obs.alt_new_error_calls++;
  mock_core_obs.alt_new_error_core = prov;
  mock_core_record(MOCK_CORE_ORD_ALT_NEW_ERROR);
}

/*
 * OSSL_FUNC_CORE_SET_ERROR_DEBUG (id 6).  Records the core pointer, both
 * string pointers, a copy of each string, and the line number verbatim.
 *
 * The line number is where ERR_raise_data()'s call-site capture becomes
 * checkable: include/prov/err.h:51 passes OPENSSL_LINE, which expands at the
 * macro's call site, so a test records __LINE__ on the same physical line as
 * its ERR_raise() and compares.  On a following line the expectation would be
 * off by one.
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
 * OSSL_FUNC_CORE_VSET_ERROR (id 7).  Records the core pointer, the reason, the
 * format pointer and a copy of the format string, and -- only when a test has
 * asked for it through va_mode -- the varargs themselves.
 *
 * The va_list is traversed here and nowhere else, at most once per call, and
 * only in the mode the test selected.  err.c:101-103 opens the list with
 * va_start() and closes it with va_end() around this call, so this stub must
 * not va_end() what it did not va_start().
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
    mock_core_obs.va_int = va_arg(args, int);
    mock_core_obs.va_str_ptr = va_arg(args, const char *);
    mock_core_capture(mock_core_obs.va_str_text,
                      sizeof(mock_core_obs.va_str_text),
                      mock_core_obs.va_str_ptr);
    mock_core_obs.va_consumed = 1;
  }

  mock_core_record(MOCK_CORE_ORD_VSET_ERROR);
}

/*
 * A compile-time guard, not a run-time one, and it is never meant to be
 * called.  Assigning each stub to a pointer of the matching
 * OSSL_FUNC_core_*_fn type -- the very typedefs OSSL_CORE_MAKE_FUNC emits and
 * err.c stores in its handle -- makes the compiler check every parameter and
 * return type for us.  Should OpenSSL ever change one of these signatures, or
 * should a stub above drift from it, this function stops compiling cleanly
 * instead of leaving err.c to call through a mismatched pointer.
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
 * ===========================================================================
 * The nine dispatch tables -- plus one positive control at the very end, which
 * is what keeps three of the nine from asserting a vacuous zero.
 *
 * These are the fixtures: each one is a table the OpenSSL core could plausibly
 * hand a provider, shaped to make one specific property of err.c's resolution
 * loop observable.  The loop being probed is err.c:34-45, and it has exactly
 * three interesting properties, all three of them silent -- no return value,
 * no diagnostic, nothing a compiler would catch if it changed:
 *
 *   err.c:34     the scan stops at the first entry whose function_id is 0;
 *   err.c:35-45  the switch has no default label, so an id it does not
 *                recognise is skipped rather than rejected;
 *   err.c:36-44  a later entry for an id it does recognise overwrites the
 *                earlier one, so the LAST occurrence is the one that survives.
 *
 * Every table is terminated by a literal { 0, NULL }.  OpenSSL 3.5 offers
 * OSSL_DISPATCH_END for this, but the project's floor is OpenSSL 3.0
 * (CMakeLists.txt asks find_package(OpenSSL 3.0 REQUIRED)) and that macro does
 * not exist there, so the literal is what keeps these fixtures buildable
 * against every OpenSSL the library itself supports.
 *
 * The (void (*)(void)) casts are what an OSSL_DISPATCH entry requires --
 * struct ossl_dispatch_st stores one generic function pointer for signatures
 * of every shape -- and are what OpenSSL's own tables do.  Converting between
 * function pointer types is well-defined provided the pointer is called
 * through its original type, which err.c guarantees by casting back with the
 * OSSL_FUNC_core_* accessors; mock_core_signature_check() above is what proves
 * the original types still line up.  ISO C only forbids converting between
 * function and object pointers, so these are clean at -Wpedantic too.
 * ===========================================================================
 */

/*
 * 1.  Complete, in ascending id order: the happy path, and the table almost
 *     every case starts from.  A handle built from this resolves all three
 *     callbacks, so ERR_raise() through it yields the full sequence
 *     1, 2, 3 and no assertion in err.c:47-49 can fire.
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
 * 2.  The same three entries in a different order (7, 5, 6).  Nothing in the
 *     OpenSSL contract promises a provider an ordered table, and err.c:34-45
 *     is a switch inside a loop, so order genuinely does not matter -- this
 *     table exists to keep that true.  A handle built from it must behave
 *     identically to one built from mock_dispatch_complete, sequence 1, 2, 3
 *     included.
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
 * 3.  Unknown ids interleaved with the three that matter.
 *
 *     The switch at err.c:35-45 has no default label, so ids 8, 9 and 9999 are
 *     skipped in silence.  Ids 8 and 9 are real, adjacent core functions --
 *     OSSL_FUNC_CORE_SET_ERROR_MARK and OSSL_FUNC_CORE_CLEAR_LAST_ERROR_MARK
 *     -- which is what a real core's table would actually contain; 9999 is an
 *     id OpenSSL has not assigned at all.  Together they cover both "an id
 *     this helper does not care about" and "an id nobody has defined".
 *
 *     All three are bound to the alternate new_error stub, so tolerance is not
 *     merely inferred from the handle coming back non-NULL: after a raise,
 *     alt_new_error_calls must still be 0 and the sequence must still be
 *     1, 2, 3 with no ordinal 4 in it.  Were the switch to grow a default that
 *     mis-assigned, or were a case label to change, the alternate stub would
 *     fire and say so.
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
 * 4.  Two entries for OSSL_FUNC_CORE_NEW_ERROR: the alternate stub first, the
 *     primary last.
 *
 *     err.c:37 assigns unconditionally every time the case is taken, so the
 *     last occurrence wins.  A raise through a handle built from this table
 *     must fire the PRIMARY stub -- new_error_calls 1, alt_new_error_calls 0,
 *     sequence 1, 2, 3.  Note that no return value or handle inspection could
 *     reveal this: which of two equally valid callbacks got stored is only
 *     visible by calling it, which is why the two stubs have to be
 *     distinguishable and why the alternate one has an ordinal of its own.
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
 * 5.  A complete table, its { 0, NULL } terminator, and then a fourth entry
 *     that must never be read.
 *
 *     err.c:34 tests function_id != 0 before each iteration, so the scan stops
 *     at the terminator and the trailing entry is unreachable.  Binding that
 *     entry to the alternate new_error stub makes "unreachable" assertable:
 *     alt_new_error_calls must be 0 after a raise.  A loop that walked one
 *     entry too far, or that terminated on something other than a zero id,
 *     would resolve new_error to the alternate stub and be caught.
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
 * ---------------------------------------------------------------------------
 * 6 to 9: the four tables that leave at least one callback unresolved.
 *
 * These are the only fixtures whose outcome depends on how the library was
 * compiled, and the asymmetry is in err.c rather than here.  Both outcomes
 * were confirmed by running each of the four tables through the real
 * proverr_new_handle() in both configurations:
 *
 *   - in a default build the assertions at err.c:47-49 are live, so
 *     proverr_new_handle() ABORTS on any of these.  tests/test_err_death.c
 *     drives them in a forked child and asserts SIGABRT.
 *
 *   - with NDEBUG defined those assertions vanish and the guard at err.c:51-54
 *     becomes reachable, so proverr_new_handle() returns NULL instead.
 *     tests/test_err_guards.c, built a second time with NDEBUG, asserts that.
 *
 * *** THE NDEBUG VARIANT HAS TO COMPILE err.c ITSELF ***
 *
 * That second build is easy to get wrong, and getting it wrong looks like a
 * bug in these tables rather than in the build.  NDEBUG has to reach the
 * translation unit that contains the assert(), which is err.c -- and err.c
 * belongs to the libprov target, not to the test target.  Defining NDEBUG on
 * the test target alone therefore changes which branch the TEST source takes
 * while leaving the assertions in the already-built libprov.a fully live, so
 * the test expects NULL and gets SIGABRT.  Verified: a target wired that way
 * dies with
 *
 *     err.c:47: proverr_new_handle: Assertion `c_new_error != NULL' failed.
 *
 * The variant target must compile err.c into itself instead of linking the
 * default-built archive -- add err.c to its own sources, or link a separate
 * NDEBUG copy of the library.  With err.c in the same target, all four tables
 * return NULL exactly as documented above.
 *
 * One more thing these four are NOT: a null dispatch pointer.  The empty table
 * below is a valid, correctly-terminated OSSL_DISPATCH whose only fault is
 * that it resolves nothing, which reaches err.c:47-49 -- whereas a null
 * pointer would be stopped much earlier, at err.c:27.  Both inputs are worth
 * testing and they are not interchangeable.
 * ---------------------------------------------------------------------------
 */

/*
 * 6.  Empty but well-formed: the terminator and nothing else.  err.c:34 exits
 *     the loop immediately, leaving all three callbacks NULL, so all three
 *     assertions at err.c:47-49 have something to say.
 */
MOCK_CORE_MAYBE_UNUSED
static const OSSL_DISPATCH mock_dispatch_empty[] = {
  { 0, NULL }
};

/*
 * 7.  Everything except OSSL_FUNC_CORE_NEW_ERROR, isolating the assertion at
 *     err.c:47.
 */
MOCK_CORE_MAYBE_UNUSED
static const OSSL_DISPATCH mock_dispatch_no_new_error[] = {
  { OSSL_FUNC_CORE_SET_ERROR_DEBUG,
    (void (*)(void))mock_core_set_error_debug },
  { OSSL_FUNC_CORE_VSET_ERROR, (void (*)(void))mock_core_vset_error },
  { 0, NULL }
};

/*
 * 8.  Everything except OSSL_FUNC_CORE_SET_ERROR_DEBUG, isolating the
 *     assertion at err.c:48.
 */
MOCK_CORE_MAYBE_UNUSED
static const OSSL_DISPATCH mock_dispatch_no_set_error_debug[] = {
  { OSSL_FUNC_CORE_NEW_ERROR, (void (*)(void))mock_core_new_error },
  { OSSL_FUNC_CORE_VSET_ERROR, (void (*)(void))mock_core_vset_error },
  { 0, NULL }
};

/*
 * 9.  Everything except OSSL_FUNC_CORE_VSET_ERROR, isolating the assertion at
 *     err.c:49.
 */
MOCK_CORE_MAYBE_UNUSED
static const OSSL_DISPATCH mock_dispatch_no_vset_error[] = {
  { OSSL_FUNC_CORE_NEW_ERROR, (void (*)(void))mock_core_new_error },
  { OSSL_FUNC_CORE_SET_ERROR_DEBUG,
    (void (*)(void))mock_core_set_error_debug },
  { 0, NULL }
};

/*
 * ---------------------------------------------------------------------------
 * A positive control, over and above the nine variants above.
 *
 * Three of those nine -- unknown_ids, duplicate_ids and after_sentinel -- rest
 * their case on the same claim: that mock_core_obs.alt_new_error_calls is
 * still zero afterwards.  An assertion of zero is only worth making if a
 * non-zero result was possible, and nothing in the nine tables can produce
 * one, because in every one of them the alternate stub sits somewhere err.c is
 * supposed not to reach.  Were mock_core_alt_new_error() ever to increment the
 * wrong counter, all three of those assertions would pass for the wrong reason
 * and go on passing for ever.
 *
 * This table closes that off.  It binds the alternate stub to
 * OSSL_FUNC_CORE_NEW_ERROR as the ONLY entry for that id, so a raise through a
 * handle built from it must show alt_new_error_calls == 1,
 * new_error_calls == 0, and MOCK_CORE_ORD_ALT_NEW_ERROR in the sequence.
 * Assert that once and the other three tables' zeroes become evidence rather
 * than assumption.
 *
 * It is a control, not a scenario: it says nothing about err.c that the nine
 * do not already say, and no err.c behaviour depends on it.
 * ---------------------------------------------------------------------------
 */
MOCK_CORE_MAYBE_UNUSED
static const OSSL_DISPATCH mock_dispatch_alt_new_error[] = {
  { OSSL_FUNC_CORE_NEW_ERROR, (void (*)(void))mock_core_alt_new_error },
  { OSSL_FUNC_CORE_SET_ERROR_DEBUG,
    (void (*)(void))mock_core_set_error_debug },
  { OSSL_FUNC_CORE_VSET_ERROR, (void (*)(void))mock_core_vset_error },
  { 0, NULL }
};

#endif                          /* LIBPROV_TESTS_MOCK_CORE_H */

