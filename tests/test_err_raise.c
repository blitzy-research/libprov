/* CC0 license applied, see LICENSE */

/*
 * Argument-forwarding fidelity for err.c's three raise primitives, the
 * ERR_raise() / ERR_raise_data() macro contract from include/prov/err.h, and
 * the negative compile-time contract that ERR_put_error() stays undefined.
 *
 * WHAT IS BEING ENCODED.  err.c stores the core handle and the three resolved
 * callbacks (err.c:7-12, err.c:56-61), and the three primitives do nothing but
 * forward:
 *
 *     proverr_new_error()       -> core                       (err.c:85-88)
 *     proverr_set_error_debug() -> core, file, line, func     (err.c:90-94)
 *     proverr_set_error()       -> core, reason, fmt, va_list (err.c:96-104)
 *
 * "Forward" is a stronger claim than "pass something equal", so wherever this
 * file supplies a pointer and keeps it, it asserts pointer IDENTITY: a test
 * that compared only string contents would pass against a library that
 * forwarded a strdup()ed copy, which is a real regression -- the caller's
 * string would then be leaked and its lifetime silently changed.
 *
 * include/prov/err.h:49-52 defines ERR_raise_data() as a comma expression, and
 * that evaluation ORDER is the contract: new_error, then set_error_debug, then
 * set_error.  mock_core.h's recorder makes the order observable, so it is
 * asserted as a sequence of ordinals rather than inferred from three call
 * counts -- three counts of one cannot distinguish an order.
 * include/prov/err.h:47 defines ERR_raise(h, r) as ERR_raise_data((h),(r),
 * NULL), which is why fmt arrives as NULL from one macro and as the caller's
 * own pointer from the other.
 *
 * THREE HAZARDS, each of which silently weakens this file if ignored.
 *
 * 1.  OPENSSL_FILE / OPENSSL_LINE / OPENSSL_FUNC, never raw __FILE__ /
 *     __LINE__ / __func__.  include/prov/err.h:51 forwards the OpenSSL
 *     spellings, and <openssl/macros.h> defines OPENSSL_FILE as "" and
 *     OPENSSL_LINE as 0 when OPENSSL_NO_FILENAMES is set, and OPENSSL_FUNC as
 *     "(unknown function)" on a translator that offers neither __func__ nor
 *     __FUNCTION__.  Expectations written in the OpenSSL spellings track those
 *     definitions; hard-coded ones would be a latent failure.  All three
 *     arrive transitively through "prov/err.h" (include/prov/err.h:4-5).
 *
 *     The one thing the spellings cannot rescue is a RELATIONAL claim about
 *     two lines: with OPENSSL_NO_FILENAMES set, OPENSSL_LINE is the constant
 *     0 at every call site, so "the second raise's line is greater than the
 *     first's" is false however it is spelled.  That configuration is not one
 *     this project builds -- the mandated command passes no -D and nothing in
 *     the tree defines the macro -- and the two relational assertions in
 *     test_err_raise_macro() are kept unconditional because they are what
 *     catches a library forwarding a constant line.  Measured, so that a
 *     future reader meets a recorded fact rather than a surprise:
 *     -DOPENSSL_NO_FILENAMES leaves exactly those two assertions failing and
 *     every other one in this file passing.
 *
 * 2.  OPENSSL_LINE expands AT THE CALL SITE, so its expectation must be
 *     captured on the SAME PHYSICAL LINE as the raise.  One line lower and it
 *     is off by one.  Only the line is position-sensitive -- the file string
 *     names the translation unit and OPENSSL_FUNC names the enclosing function
 *     -- so only that one capture shares a line with its raise, and every such
 *     line is marked so it is not reflowed by a later edit.
 *
 * 3.  POINTER IDENTITY IS ASSERTED ONLY FOR STRINGS THIS FILE OWNS.  C99
 *     6.4.5p6 leaves it unspecified whether string literals with the same
 *     contents are distinct objects, and it leaves that unspecified PER
 *     OCCURRENCE: an implementation may fold one pair of occurrences and keep
 *     another pair apart in the same translation unit.  So no run-time probe
 *     can license the claim either -- observing that two expansions of
 *     OPENSSL_FILE happen to compare equal says nothing about the different
 *     pair formed by the expansion this file captured and the expansion
 *     include/prov/err.h:51 forwarded.  Basing an assertion on that inference
 *     would make it unsound rather than conditional, and it could fail on a
 *     conforming implementation that folded the probe's pair and not the
 *     other.  For the values the compiler and <openssl/macros.h> generate --
 *     OPENSSL_FILE and OPENSSL_FUNC as they arrive through ERR_raise() and
 *     ERR_raise_data() -- this file therefore asserts CONTENT and the CALL
 *     SITE LINE, plus the one pointer property that IS a contract rather than
 *     an accident of storage: neither macro can expand to a null pointer, so
 *     a forwarded null is a defect, and it is the one thing content alone
 *     cannot see (mock_core.h records a null string as "", which is exactly
 *     what OPENSSL_FILE expands to under OPENSSL_NO_FILENAMES).  This is the
 *     same policy mock_core.h:150-155 states for its own recorder.
 *
 *     Identity of a forwarded string IS asserted, unconditionally and
 *     soundly, everywhere the pointer belongs to this file and is therefore a
 *     single known object: the file and function markers in
 *     test_set_error_debug_forwarding(), the format string in
 *     test_set_error_forwarding() and both macro cases, and the variadic
 *     string in test_va_list_traversal().  That is where a library forwarding
 *     a copy instead of the caller's pointer is caught, and it is caught for
 *     the SAME err.c function the macros reach: err.c:90-94 has one
 *     implementation, so pinning its pass-through once pins it everywhere.
 *     Measured against a mutant that forwards a malloc()ed copy of both
 *     strings: sixteen assertions in test_set_error_debug_forwarding() fail
 *     and the run exits non-zero, so asserting content rather than identity
 *     for the generated values costs no detection power at all.  Nothing here
 *     compares a pointer against a bare literal in any case: every
 *     expectation is captured into a variable first.
 *
 * THE HANDLE IS OPAQUE.  struct proverr_functions_st is defined only in
 * err.c:7-12 and include/prov/err.h:58 merely forward-declares it, so nothing
 * here can read handle->core.  Every claim about what a handle stored is made
 * behaviourally, from what the stubs were handed.
 *
 * NO ABORTING INPUT MAY BE USED HERE.  This target must link libprov under the
 * project's default flags, which leaves err.c:26-27 and err.c:47-49 as live
 * assert()s: a null core, a null dispatch table, or any table that leaves a
 * callback unresolved, aborts the process.  Every handle here is therefore
 * built from mock_dispatch_complete over a real core handle.  The abort
 * contract belongs to tests/test_err_death.c and the NDEBUG contract to
 * tests/test_err_guards.c.
 *
 * ERR_raise() and ERR_raise_data() name `handle` three times
 * (include/prov/err.h:50-52), so an argument with side effects would be
 * evaluated three times.  Every invocation below passes a plain variable.
 *
 * NO LIBCRYPTO IS CALLED OR LINKED: the core is mock_core.h's hand-built one,
 * the accessors err.c uses expand to static inline definitions, and no function
 * declared by any <openssl/...> header is ever called.  <openssl/params.h> is
 * not included directly by this file, but it does arrive transitively --
 * prov/err.h includes <openssl/core_dispatch.h>, which includes
 * <openssl/indicator.h>, which includes it.  That is the project header's own
 * include graph rather than a choice made here, and it only DECLARES libcrypto
 * functions: a linked test binary's dynamic dependencies remain the vDSO, libc
 * and the loader alone.  What matters is that none of those functions -- the
 * OSSL_PARAM_get_*, set_* and construct_* families the provnum_ family exists
 * to replace -- is ever called.
 *
 * <openssl/err.h> IS INCLUDED DELIBERATELY, and first: it is what seeds
 * ERR_put_error() so the negative compile-time contract below has something to
 * be about.  It is a header, so including it links nothing either.
 */

/*
 * ---------------------------------------------------------------------------
 * SEEDING THE NEGATIVE COMPILE-TIME CONTRACT -- THIS BLOCK MUST STAY FIRST
 * ---------------------------------------------------------------------------
 * include/prov/err.h:43 undefines ERR_put_error(), and the comment at
 * include/prov/err.h:38-41 says why: <openssl/err.h> may have been included,
 * its error-recording macros are thrown away, and ERR_put_error() is
 * deliberately NOT recreated because it is deprecated.  That is a property of
 * the header no runtime assertion can express -- there is no symbol to look for
 * and no value to compare -- so it is asserted at the foot of this block.
 *
 * AN #undef CAN ONLY BE OBSERVED IF SOMETHING WAS DEFINED FIRST.  prov/err.h
 * includes <stdint.h>, <openssl/core.h> and <openssl/core_dispatch.h> and
 * nothing else, so on its own it never sees an ERR_put_error() to remove: a
 * bare "#ifdef ERR_put_error / #error" placed after it would hold just as well
 * with include/prov/err.h:43 deleted, and would therefore assert nothing.  The
 * macro is seeded here, BEFORE the first include that can reach prov/err.h --
 * mock_core.h reaches it, which is why this block precedes even testutil.h.
 *
 * The seed is taken from <openssl/err.h> where that header supplies it, which
 * is the real situation the #undef exists for.  The fallback is not
 * hypothetical: upstream wraps its ERR_put_error() in
 * "#ifndef OPENSSL_NO_DEPRECATED_3_0", so a build that defines that macro --
 * and any future OpenSSL that finishes removing the deprecated spelling --
 * supplies no seed at all.  Defining one here means this contract cannot
 * quietly stop being tested because an upstream header changed.  The
 * intermediate #error is the positive half: it fires if neither source
 * defined the macro, which would mean the seed itself had silently failed.
 *
 * Verified: with include/prov/err.h:43 removed from a scratch copy of the
 * header, this translation unit FAILS to compile on the final #error below.
 */
#include <openssl/err.h>

#ifndef ERR_put_error
/*
 * The fallback seed.  Its replacement text is a deliberately undeclared
 * identifier: nothing in this file expands ERR_put_error(), so the text is
 * never evaluated, and if some future edit did expand it the result would be a
 * compile error naming this macro rather than a silent call.
 */
# define ERR_put_error(lib, func, reason, file, line)                       \
    LIBPROV_TEST_ERR_PUT_ERROR_MUST_NOT_SURVIVE_PROV_ERR_H
#endif

#ifndef ERR_put_error
# error "the ERR_put_error seed above did not take; the contract below is void"
#endif

#include "testutil.h"
#include "mock_core.h"
#include "prov/err.h"
#include <limits.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
 * The negative compile-time contract itself, asserted after every include so
 * that a silent reintroduction of ERR_put_error() -- which would let provider
 * code compile against the legacy API and keep doing so unnoticed -- fails the
 * build here.  It is load-bearing only because of the seed above.
 */
#ifdef ERR_put_error
# error "ERR_put_error must be left undefined by prov/err.h:38-43"
#endif

/*
 * The positive twin: the two macros the header does define
 * (include/prov/err.h:47, :49-52) must be present, so that a header change
 * which dropped them fails the build here instead of silently falling through
 * to whatever <openssl/err.h> may have left behind.
 *
 * "Present" is all the preprocessor can check, and here it is genuinely not
 * enough: <openssl/err.h> defines ERR_raise() and ERR_raise_data() of its own,
 * so this pair of #if tests would hold even if prov/err.h's #undef and
 * redefinition had done nothing and upstream's macros were still in force.
 * WHICH definition won is settled at RUNTIME instead, by
 * test_err_raise_macro() and test_err_raise_data_macro(): both assert the
 * recorded sequence new_error, set_error_debug, set_error, and only
 * prov/err.h's comma expression calls those three.  Upstream's expands to
 * (ERR_new(), ERR_set_debug(...), ERR_set_error), so had it survived this
 * program would not even link -- no libcrypto is linked -- and could record
 * nothing if it did.  That is a property those two functions could not
 * establish before <openssl/err.h> was included above, there having been no
 * competing definition to displace.
 */
#if !defined(ERR_raise) || !defined(ERR_raise_data)
# error "prov/err.h:47-52 must define ERR_raise and ERR_raise_data"
#endif

/*
 * A line number in the ordinary range, between the two extremes.  Its value
 * is arbitrary and deliberately unrelated to any line in this file: what it
 * proves is that proverr_set_error_debug() forwards whatever it is given
 * rather than substituting something derived from its own call site.
 */
#define MIDRANGE_LINE 4711

static int test_new_error_forwarding(void);
static int test_set_error_debug_forwarding(void);
static int test_set_error_forwarding(void);
static int test_va_list_traversal(void);
static int test_err_raise_macro(void);
static int test_err_raise_data_macro(void);

/*
 * proverr_new_error() forwards the handle's stored core and nothing else
 * (err.c:87).
 *
 * Three claims, none of which follows from the others: the callback runs
 * exactly once per call, it receives the very pointer the handle was built
 * with, and the pointer follows the HANDLE rather than some file-scope
 * default -- which is why a second handle over the alternate core is built
 * and shown to forward the alternate core.  Without that last step
 * "new_error_core == &mock_core_primary" would also hold of a library that
 * ignored its core argument and forwarded a constant.
 */
static int test_new_error_forwarding(void)
{
  int ok = 1;
  struct proverr_functions_st *handle;
  struct proverr_functions_st *other;

  mock_core_reset();

  handle = proverr_new_handle(&mock_core_primary, mock_dispatch_complete);
  TEST_ASSERT_PTR_NOT_NULL("new_error: handle from complete table", handle);
  ok &= test;
  if (handle == NULL)
    return 0;                   /* nothing below is safe to dereference */

  /* Call, then read, then assert: never in one expression (C99 6.5.2.2p10
     leaves argument evaluation order unspecified). */
  proverr_new_error(handle);

  TEST_ASSERT_UINT_EQ("new_error: calls after one call",
                      mock_core_obs.new_error_calls, 1UL);
  ok &= test;
  TEST_ASSERT_PTR_EQ("new_error: core identity",
                     mock_core_obs.new_error_core, &mock_core_primary);
  ok &= test;

  /* Exactly one callback ran.  err.c:85-88 touches only core_new_error, so a
     mutation that also raised the other two would show up here. */
  TEST_ASSERT_UINT_EQ("new_error: set_error_debug not invoked",
                      mock_core_obs.set_error_debug_calls, 0UL);
  ok &= test;
  TEST_ASSERT_UINT_EQ("new_error: vset_error not invoked",
                      mock_core_obs.vset_error_calls, 0UL);
  ok &= test;

  /* mock_dispatch_complete binds the primary stub only, so the alternate must
     stay untouched; a table mix-up would otherwise pass unnoticed. */
  TEST_ASSERT_UINT_EQ("new_error: alternate stub not invoked",
                      mock_core_obs.alt_new_error_calls, 0UL);
  ok &= test;

  TEST_ASSERT_SIZE_EQ("new_error: one ordinal recorded",
                      mock_core_obs.seq_len, (size_t)1);
  ok &= test;
  TEST_ASSERT_INT_EQ("new_error: ordinal is new_error",
                     mock_core_obs.seq[0], MOCK_CORE_ORD_NEW_ERROR);
  ok &= test;

  proverr_new_error(handle);

  TEST_ASSERT_UINT_EQ("new_error: calls after two calls",
                      mock_core_obs.new_error_calls, 2UL);
  ok &= test;
  TEST_ASSERT_PTR_EQ("new_error: core identity on the second call",
                     mock_core_obs.new_error_core, &mock_core_primary);
  ok &= test;
  TEST_ASSERT_SIZE_EQ("new_error: two ordinals recorded",
                      mock_core_obs.seq_len, (size_t)2);
  ok &= test;
  TEST_ASSERT_INT_EQ("new_error: second ordinal is new_error",
                     mock_core_obs.seq[1], MOCK_CORE_ORD_NEW_ERROR);
  ok &= test;
  TEST_ASSERT_UINT_EQ("new_error: no ordinal dropped",
                      mock_core_obs.seq_dropped, 0UL);
  ok &= test;

  /*
   * The core follows the handle.  Reset first -- everything above has already
   * been read -- then build a second handle over the OTHER core and prove the
   * forwarded pointer changes with it.  err.c:57 stores what it was given and
   * err.c:87 forwards that; nothing is shared between handles.
   */
  mock_core_reset();

  other = proverr_new_handle(&mock_core_alternate, mock_dispatch_complete);
  TEST_ASSERT_PTR_NOT_NULL("new_error: handle over the alternate core",
                           other);
  ok &= test;

  /*
   * `handle` is still live here, so the second handle has to be a DISTINCT
   * object -- err.c:56 allocates fresh storage per call -- and that is
   * asserted before it is relied on, for two reasons.  It is what this case
   * rests on: if one cached object were handed out twice, "the forwarded core
   * changes with the handle" would be testing nothing.  And it is what makes
   * the cleanup safe: the block below and the tail of this function would
   * otherwise free the same object twice (CWE-415), replacing a clean failure
   * line with heap corruption or an abort that hides it.
   */
  TEST_ASSERT_PTR_NE("new_error: the alternate handle is a distinct object",
                     other, handle);
  ok &= test;

  /*
   * Gated on distinctness, not merely on non-NULL.  When the two pointers are
   * aliased this block is skipped and the single object is released exactly
   * once by the `proverr_free_handle(handle)` at the tail.
   */
  if (other != NULL && other != handle) {
    proverr_new_error(other);

    TEST_ASSERT_UINT_EQ("new_error: alternate handle calls",
                        mock_core_obs.new_error_calls, 1UL);
    ok &= test;
    TEST_ASSERT_PTR_EQ("new_error: alternate handle core identity",
                       mock_core_obs.new_error_core, &mock_core_alternate);
    ok &= test;
    TEST_ASSERT_PTR_NE("new_error: alternate handle did not forward primary",
                       mock_core_obs.new_error_core, &mock_core_primary);
    ok &= test;

    proverr_free_handle(other);
  }

  proverr_free_handle(handle);
  return ok;
}

/*
 * proverr_set_error_debug() forwards core, file, line and func unchanged
 * (err.c:93).
 *
 * This is the case that pins pointer pass-through with no caveat attached:
 * both strings are objects THIS FUNCTION owns, so "the same pointer arrived"
 * is a claim C guarantees is meaningful, unlike a comparison against a string
 * literal, whose address C99 6.4.5p6 leaves unspecified.  A library that
 * forwarded a copy would keep every content assertion passing and fail here.
 *
 * The line values are driven from a table so that the two extremes, the sign
 * transition and an ordinary value are all covered, and the expectations are
 * the <limits.h> macros themselves rather than transcribed digits -- INT_MIN
 * and INT_MAX are not the same numbers on every ABI.  MIDRANGE_LINE is
 * unrelated to any line in this file, so forwarding the callee's own line
 * number instead of the caller's would fail rather than coincide.
 */
static int test_set_error_debug_forwarding(void)
{
  /*
   * Distinct objects with recognisable contents: distinct so that swapping
   * the file and func arguments is detectable, recognisable so that a failure
   * dump reads unambiguously.  static, so their addresses are stable for the
   * whole run and cannot be reused by a later frame.
   */
  static const char file_marker[] = "tests/test_err_raise.c[file-marker]";
  static const char func_marker[] = "test_err_raise_func_marker";

  static const struct {
    int line;
    const char *label;
  } line_cases[] = {
    { INT_MIN,       "set_error_debug: line INT_MIN"     },
    { INT_MIN + 1,   "set_error_debug: line INT_MIN + 1" },
    { -1,            "set_error_debug: line -1"          },
    { 0,             "set_error_debug: line 0"           },
    { 1,             "set_error_debug: line 1"           },
    { MIDRANGE_LINE, "set_error_debug: line mid-range"   },
    { INT_MAX - 1,   "set_error_debug: line INT_MAX - 1" },
    { INT_MAX,       "set_error_debug: line INT_MAX"     }
  };
  const size_t line_case_count = sizeof line_cases / sizeof line_cases[0];

  int ok = 1;
  struct proverr_functions_st *handle;
  size_t index;

  mock_core_reset();

  handle = proverr_new_handle(&mock_core_primary, mock_dispatch_complete);
  TEST_ASSERT_PTR_NOT_NULL("set_error_debug: handle from complete table",
                           handle);
  ok &= test;
  if (handle == NULL)
    return 0;

  /*
   * A fixture precondition, not a library claim: mock_core.h copies each
   * recorded string into MOCK_CORE_TEXT_MAX bytes and truncates a longer one.
   * Asserting the markers fit turns "the content assertion failed" into "the
   * marker outgrew the recorder" at a glance, instead of leaving a future
   * reader to discover the truncation the hard way.
   */
  TEST_ASSERT(strlen(file_marker) < (size_t)MOCK_CORE_TEXT_MAX);
  ok &= test;
  TEST_ASSERT(strlen(func_marker) < (size_t)MOCK_CORE_TEXT_MAX);
  ok &= test;

  for (index = 0; index < line_case_count; index++) {
    mock_core_reset();

    proverr_set_error_debug(handle, file_marker, line_cases[index].line,
                            func_marker);

    TEST_ASSERT_INT_EQ(line_cases[index].label, mock_core_obs.line,
                       line_cases[index].line);
    ok &= test;

    TEST_ASSERT_UINT_EQ("set_error_debug: calls",
                        mock_core_obs.set_error_debug_calls, 1UL);
    ok &= test;
    TEST_ASSERT_PTR_EQ("set_error_debug: core identity",
                       mock_core_obs.set_error_debug_core,
                       &mock_core_primary);
    ok &= test;

    /* Pass-through, asserted as identity first and content second: identity
       is the contract, content is what makes a failure readable. */
    TEST_ASSERT_PTR_EQ("set_error_debug: file pointer identity",
                       mock_core_obs.file_ptr, file_marker);
    ok &= test;
    TEST_ASSERT_STR_EQ("set_error_debug: file content",
                       mock_core_obs.file_text, file_marker);
    ok &= test;
    TEST_ASSERT_PTR_EQ("set_error_debug: func pointer identity",
                       mock_core_obs.func_ptr, func_marker);
    ok &= test;
    TEST_ASSERT_STR_EQ("set_error_debug: func content",
                       mock_core_obs.func_text, func_marker);
    ok &= test;

    /* The two strings must not have been transposed on the way through. */
    TEST_ASSERT_PTR_NE("set_error_debug: file is not the func marker",
                       mock_core_obs.file_ptr, func_marker);
    ok &= test;

    TEST_ASSERT_UINT_EQ("set_error_debug: new_error not invoked",
                        mock_core_obs.new_error_calls, 0UL);
    ok &= test;
    TEST_ASSERT_UINT_EQ("set_error_debug: vset_error not invoked",
                        mock_core_obs.vset_error_calls, 0UL);
    ok &= test;
    TEST_ASSERT_UINT_EQ("set_error_debug: alternate stub not invoked",
                        mock_core_obs.alt_new_error_calls, 0UL);
    ok &= test;

    TEST_ASSERT_SIZE_EQ("set_error_debug: one ordinal recorded",
                        mock_core_obs.seq_len, (size_t)1);
    ok &= test;
    TEST_ASSERT_INT_EQ("set_error_debug: ordinal is set_error_debug",
                       mock_core_obs.seq[0], MOCK_CORE_ORD_SET_ERROR_DEBUG);
    ok &= test;
  }

  /*
   * A null file and a null func are forwarded as null rather than replaced.
   * err.c:93 does not inspect either pointer, so this is the contract; the
   * recorder keeps the pointer and the copy apart precisely so that "null"
   * and "empty string" stay distinguishable here.
   */
  mock_core_reset();

  proverr_set_error_debug(handle, NULL, MIDRANGE_LINE, NULL);

  TEST_ASSERT_UINT_EQ("set_error_debug: null strings, calls",
                      mock_core_obs.set_error_debug_calls, 1UL);
  ok &= test;
  TEST_ASSERT_PTR_NULL("set_error_debug: null file forwarded as null",
                       mock_core_obs.file_ptr);
  ok &= test;
  TEST_ASSERT_PTR_NULL("set_error_debug: null func forwarded as null",
                       mock_core_obs.func_ptr);
  ok &= test;
  TEST_ASSERT_STR_EQ("set_error_debug: null file recorded as empty",
                     mock_core_obs.file_text, "");
  ok &= test;
  TEST_ASSERT_INT_EQ("set_error_debug: null strings, line still forwarded",
                     mock_core_obs.line, MIDRANGE_LINE);
  ok &= test;

  proverr_free_handle(handle);
  return ok;
}

/*
 * proverr_set_error() forwards core, reason and fmt, and hands the callee the
 * va_list it started (err.c:96-104).
 *
 * reason is a uint32_t, so both extremes are asserted through
 * TEST_ASSERT_UINT_EQ, which compares at uintmax_t width: a mutation routing
 * the value through an int would turn UINT32_MAX into -1 and be caught here
 * rather than wrapping silently.  fmt is asserted by IDENTITY, including the
 * null case, because include/prov/err.h:47 makes "fmt is NULL" the observable
 * difference between the two raise macros -- a callee that substituted "" for
 * NULL would break that distinction while keeping every content check happy.
 *
 * No vararg is passed and mock_core.h's consumption mode is left at its
 * MOCK_CORE_VA_NONE default throughout, so the stub does not traverse the
 * list.  Traversal is the subject of test_va_list_traversal().
 */
static int test_set_error_forwarding(void)
{
  /*
   * Named as err.c:97 names its own parameter, and an object THIS FUNCTION
   * owns, so "the caller's pointer arrived" is soundly checkable -- unlike a
   * comparison against a bare literal, whose address C99 6.4.5p6 leaves
   * unspecified.  Its contents look like a real format string because a
   * plausible fixture is what a reader has to trust; nothing here formats it.
   */
  static const char fmt[] = "%s: detail %d";

  /*
   * The two rows above UINT32_MAX / 2 are not decoration.  The realistic bug
   * here is a reason that gets treated as signed somewhere on its way through,
   * which clears the top bit: that corruption is invisible to every row up to
   * and including UINT32_MAX / 2 and observable only at UINT32_MAX - 1 and
   * UINT32_MAX.  A round trip through an int of the same width, by contrast,
   * is value preserving for all 2^32 inputs wherever int is 32 bits, so no
   * input can distinguish it.
   */
  static const struct {
    uint32_t reason;
    const char *label;
  } reason_cases[] = {
    { 0u,                "set_error: reason 0"              },
    { 1u,                "set_error: reason 1"              },
    { 42u,               "set_error: reason 42"             },
    { UINT32_MAX / 2u,   "set_error: reason UINT32_MAX / 2"  },
    { UINT32_MAX - 1u,   "set_error: reason UINT32_MAX - 1"  },
    { UINT32_MAX,        "set_error: reason UINT32_MAX"      }
  };
  const size_t reason_case_count =
    sizeof reason_cases / sizeof reason_cases[0];

  int ok = 1;
  struct proverr_functions_st *handle;
  size_t index;

  mock_core_reset();

  handle = proverr_new_handle(&mock_core_primary, mock_dispatch_complete);
  TEST_ASSERT_PTR_NOT_NULL("set_error: handle from complete table", handle);
  ok &= test;
  if (handle == NULL)
    return 0;

  TEST_ASSERT(strlen(fmt) < (size_t)MOCK_CORE_TEXT_MAX);
  ok &= test;

  for (index = 0; index < reason_case_count; index++) {
    mock_core_reset();

    proverr_set_error(handle, reason_cases[index].reason, fmt);

    TEST_ASSERT_UINT_EQ(reason_cases[index].label, mock_core_obs.reason,
                        reason_cases[index].reason);
    ok &= test;

    TEST_ASSERT_UINT_EQ("set_error: calls", mock_core_obs.vset_error_calls,
                        1UL);
    ok &= test;
    TEST_ASSERT_PTR_EQ("set_error: core identity",
                       mock_core_obs.vset_error_core, &mock_core_primary);
    ok &= test;
    TEST_ASSERT_PTR_EQ("set_error: fmt pointer identity",
                       mock_core_obs.fmt_ptr, fmt);
    ok &= test;
    TEST_ASSERT_STR_EQ("set_error: fmt content", mock_core_obs.fmt_text,
                       fmt);
    ok &= test;

    TEST_ASSERT_INT_EQ("set_error: va_list not traversed",
                       mock_core_obs.va_consumed, 0);
    ok &= test;

    TEST_ASSERT_UINT_EQ("set_error: new_error not invoked",
                        mock_core_obs.new_error_calls, 0UL);
    ok &= test;
    TEST_ASSERT_UINT_EQ("set_error: set_error_debug not invoked",
                        mock_core_obs.set_error_debug_calls, 0UL);
    ok &= test;
    TEST_ASSERT_UINT_EQ("set_error: alternate stub not invoked",
                        mock_core_obs.alt_new_error_calls, 0UL);
    ok &= test;

    TEST_ASSERT_SIZE_EQ("set_error: one ordinal recorded",
                        mock_core_obs.seq_len, (size_t)1);
    ok &= test;
    TEST_ASSERT_INT_EQ("set_error: ordinal is vset_error",
                       mock_core_obs.seq[0], MOCK_CORE_ORD_VSET_ERROR);
    ok &= test;
  }

  /*
   * A null fmt stays null.  This is the shape ERR_raise() produces
   * (include/prov/err.h:47), reached here directly so the primitive's own
   * contract is pinned independently of the macro that relies on it.
   */
  mock_core_reset();

  proverr_set_error(handle, 42u, NULL);

  TEST_ASSERT_UINT_EQ("set_error: null fmt, calls",
                      mock_core_obs.vset_error_calls, 1UL);
  ok &= test;
  TEST_ASSERT_PTR_NULL("set_error: null fmt forwarded as null",
                       mock_core_obs.fmt_ptr);
  ok &= test;
  TEST_ASSERT_STR_EQ("set_error: null fmt recorded as empty",
                     mock_core_obs.fmt_text, "");
  ok &= test;
  TEST_ASSERT_UINT_EQ("set_error: null fmt, reason still forwarded",
                      mock_core_obs.reason, 42u);
  ok &= test;
  TEST_ASSERT_PTR_EQ("set_error: null fmt, core identity",
                     mock_core_obs.vset_error_core, &mock_core_primary);
  ok &= test;

  proverr_free_handle(handle);
  return ok;
}

/*
 * The va_list survives the trip: err.c:101-103 wraps the callee's invocation
 * in va_start()/va_end(), and the callee must be able to walk the arguments
 * the caller passed.
 *
 * A va_list may be traversed ONCE, and only by code that knows the shape of
 * what was passed, which is why mock_core.h makes traversal opt-in and why
 * the mode is selected here and cleared immediately after the call.  It stays
 * off everywhere else, and it must: ERR_raise() supplies fmt == NULL
 * (include/prov/err.h:47) with no variadic argument at all, so traversing
 * that list would be undefined behaviour rather than a stricter test.
 *
 * MOCK_CORE_VA_INT_THEN_STR names the types exactly -- an int, then a
 * char * -- so the string argument is a char array, whose decayed type is
 * char *.  A const char * variable would make the stub's va_arg() request an
 * incompatible type, which C99 7.15.1.1 leaves undefined.
 *
 * proverr_set_error() is called DIRECTLY here rather than through a macro, so
 * that a traversal failure is attributable to the primitive and not to the
 * macro's expansion.
 */
static int test_va_list_traversal(void)
{
  /* Owned by this function, so fmt's pointer identity is soundly checkable;
     see test_set_error_forwarding().  Nothing here formats it -- it is
     forwarded verbatim, which is the whole contract of err.c:102. */
  static const char fmt[] = "%d %s";

  /*
   * char, not const char: the decayed type must be exactly the char * that
   * MOCK_CORE_VA_INT_THEN_STR documents.  Two distinct payloads, so the
   * second traversal cannot pass on the first one's leftovers, and both are
   * objects this function owns, so pointer identity of the recovered string
   * is soundly checkable.
   */
  char detail_first[] = "hi";
  char detail_second[] = "second detail payload";

  int ok = 1;
  struct proverr_functions_st *handle;

  mock_core_reset();

  handle = proverr_new_handle(&mock_core_primary, mock_dispatch_complete);
  TEST_ASSERT_PTR_NOT_NULL("va_list: handle from complete table", handle);
  ok &= test;
  if (handle == NULL)
    return 0;

  mock_core_reset();
  mock_core_obs.va_mode = MOCK_CORE_VA_INT_THEN_STR;
  proverr_set_error(handle, 7u, fmt, 99, detail_first);
  mock_core_obs.va_mode = MOCK_CORE_VA_NONE;   /* opt out again at once */

  TEST_ASSERT_INT_EQ("va_list: traversal happened",
                     mock_core_obs.va_consumed, 1);
  ok &= test;
  TEST_ASSERT_INT_EQ("va_list: int argument recovered", mock_core_obs.va_int,
                     99);
  ok &= test;
  TEST_ASSERT_PTR_EQ("va_list: string argument pointer identity",
                     mock_core_obs.va_str_ptr, detail_first);
  ok &= test;
  TEST_ASSERT_STR_EQ("va_list: string argument content",
                     mock_core_obs.va_str_text, detail_first);
  ok &= test;

  TEST_ASSERT_UINT_EQ("va_list: reason alongside varargs",
                      mock_core_obs.reason, 7u);
  ok &= test;
  TEST_ASSERT_PTR_EQ("va_list: fmt pointer identity alongside varargs",
                     mock_core_obs.fmt_ptr, fmt);
  ok &= test;
  TEST_ASSERT_STR_EQ("va_list: fmt content alongside varargs",
                     mock_core_obs.fmt_text, fmt);
  ok &= test;
  TEST_ASSERT_PTR_EQ("va_list: core identity alongside varargs",
                     mock_core_obs.vset_error_core, &mock_core_primary);
  ok &= test;
  TEST_ASSERT_UINT_EQ("va_list: calls", mock_core_obs.vset_error_calls, 1UL);
  ok &= test;
  TEST_ASSERT_SIZE_EQ("va_list: one ordinal recorded", mock_core_obs.seq_len,
                      (size_t)1);
  ok &= test;
  TEST_ASSERT_INT_EQ("va_list: ordinal is vset_error", mock_core_obs.seq[0],
                     MOCK_CORE_ORD_VSET_ERROR);
  ok &= test;

  /* Selecting the mode is what enables traversal; clearing it must disable
     traversal again rather than latching on. */
  TEST_ASSERT_INT_EQ("va_list: mode cleared after the call",
                     mock_core_obs.va_mode, MOCK_CORE_VA_NONE);
  ok &= test;

  mock_core_reset();
  mock_core_obs.va_mode = MOCK_CORE_VA_INT_THEN_STR;
  proverr_set_error(handle, 0u, fmt, INT_MIN, detail_second);
  mock_core_obs.va_mode = MOCK_CORE_VA_NONE;

  TEST_ASSERT_INT_EQ("va_list: traversal happened at INT_MIN",
                     mock_core_obs.va_consumed, 1);
  ok &= test;
  TEST_ASSERT_INT_EQ("va_list: INT_MIN argument recovered",
                     mock_core_obs.va_int, INT_MIN);
  ok &= test;
  TEST_ASSERT_PTR_EQ("va_list: second string pointer identity",
                     mock_core_obs.va_str_ptr, detail_second);
  ok &= test;
  TEST_ASSERT_STR_EQ("va_list: second string content",
                     mock_core_obs.va_str_text, detail_second);
  ok &= test;
  TEST_ASSERT_PTR_NE("va_list: second string is not the first",
                     mock_core_obs.va_str_ptr, detail_first);
  ok &= test;
  TEST_ASSERT_UINT_EQ("va_list: reason 0 alongside varargs",
                      mock_core_obs.reason, 0u);
  ok &= test;

  mock_core_reset();
  mock_core_obs.va_mode = MOCK_CORE_VA_INT_THEN_STR;
  proverr_set_error(handle, UINT32_MAX, fmt, INT_MAX, detail_first);
  mock_core_obs.va_mode = MOCK_CORE_VA_NONE;

  TEST_ASSERT_INT_EQ("va_list: INT_MAX argument recovered",
                     mock_core_obs.va_int, INT_MAX);
  ok &= test;
  TEST_ASSERT_UINT_EQ("va_list: UINT32_MAX reason alongside varargs",
                      mock_core_obs.reason, UINT32_MAX);
  ok &= test;
  TEST_ASSERT_PTR_EQ("va_list: first string pointer identity again",
                     mock_core_obs.va_str_ptr, detail_first);
  ok &= test;

  mock_core_reset();
  proverr_set_error(handle, 7u, fmt, 99, detail_first);

  TEST_ASSERT_INT_EQ("va_list: no traversal without the mode",
                     mock_core_obs.va_consumed, 0);
  ok &= test;
  TEST_ASSERT_INT_EQ("va_list: no int recovered without the mode",
                     mock_core_obs.va_int, 0);
  ok &= test;
  TEST_ASSERT_PTR_NULL("va_list: no string recovered without the mode",
                       mock_core_obs.va_str_ptr);
  ok &= test;
  TEST_ASSERT_UINT_EQ("va_list: named arguments still forwarded",
                      mock_core_obs.reason, 7u);
  ok &= test;

  proverr_free_handle(handle);
  return ok;
}

/*
 * ERR_raise() -- include/prov/err.h:47, which delegates to
 * include/prov/err.h:49-52 with NULL as the sole variadic argument.
 *
 * Four claims:
 *
 *   - the comma expression runs all three primitives, in the order written;
 *   - reason reaches proverr_set_error() unchanged;
 *   - fmt is NULL, which is what distinguishes this macro from the other one;
 *   - the call site is captured, not some other location.
 *
 * The last one is why an OPENSSL_LINE capture shares a physical line with its
 * raise, and why two raises at different lines are compared against each
 * other: a mutation forwarding a constant line, or the callee's own __LINE__,
 * satisfies neither.
 *
 * Consumption stays at MOCK_CORE_VA_NONE for every case in this function.
 * There is no variadic argument to walk -- NULL is consumed as fmt -- so
 * enabling it would be undefined behaviour.
 */
static int test_err_raise_macro(void)
{
  /*
   * The two position-independent expectations, captured once: OPENSSL_FILE
   * names the translation unit and OPENSSL_FUNC names this function, so
   * neither has to share a physical line with a raise -- only the
   * OPENSSL_LINE capture does.  They are const to make it plain that this one
   * capture serves every case below, and they are captured into variables
   * rather than used inline so that no assertion ever compares against a bare
   * literal.  What they are compared BY is content, not address; hazard 3 at
   * the head of this file says why an address comparison is not available for
   * a value this file does not own.
   */
  const char *const expected_file = OPENSSL_FILE;
  const char *const expected_func = OPENSSL_FUNC;

  int ok = 1;
  struct proverr_functions_st *handle;
  int expected_line_first;
  int expected_line_second;

  mock_core_reset();

  handle = proverr_new_handle(&mock_core_primary, mock_dispatch_complete);
  TEST_ASSERT_PTR_NOT_NULL("ERR_raise: handle from complete table", handle);
  ok &= test;
  if (handle == NULL)
    return 0;

  /*
   * Fixture preconditions, as in test_set_error_debug_forwarding(), and they
   * matter more here: OPENSSL_FILE is whatever path the compiler was handed,
   * so a deep build tree really can outgrow the recorder's MOCK_CORE_TEXT_MAX
   * bytes.  Asserting the fit turns "the content assertion failed" into "the
   * source path was truncated" without a debugging session.  They are checked
   * on the same captures the content assertions use, so a fit proved here is
   * a fit for the value actually asserted later.
   */
  TEST_ASSERT(strlen(expected_file) < (size_t)MOCK_CORE_TEXT_MAX);
  ok &= test;
  TEST_ASSERT(strlen(expected_func) < (size_t)MOCK_CORE_TEXT_MAX);
  ok &= test;

  mock_core_reset();

  /* DO NOT REFLOW THE NEXT LINE.  OPENSSL_LINE expands at the call site
     (include/prov/err.h:51), so the capture and the raise must stay on ONE
     physical line; split them and the expectation is off by one. */
  expected_line_first = OPENSSL_LINE; ERR_raise(handle, 42u);

  TEST_ASSERT_SIZE_EQ("ERR_raise: three primitives ran",
                      mock_core_obs.seq_len, (size_t)3);
  ok &= test;
  TEST_ASSERT_INT_EQ("ERR_raise: first is new_error", mock_core_obs.seq[0],
                     MOCK_CORE_ORD_NEW_ERROR);
  ok &= test;
  TEST_ASSERT_INT_EQ("ERR_raise: second is set_error_debug",
                     mock_core_obs.seq[1], MOCK_CORE_ORD_SET_ERROR_DEBUG);
  ok &= test;
  TEST_ASSERT_INT_EQ("ERR_raise: third is set_error", mock_core_obs.seq[2],
                     MOCK_CORE_ORD_VSET_ERROR);
  ok &= test;
  TEST_ASSERT_UINT_EQ("ERR_raise: no ordinal dropped",
                      mock_core_obs.seq_dropped, 0UL);
  ok &= test;

  TEST_ASSERT_UINT_EQ("ERR_raise: new_error calls",
                      mock_core_obs.new_error_calls, 1UL);
  ok &= test;
  TEST_ASSERT_UINT_EQ("ERR_raise: set_error_debug calls",
                      mock_core_obs.set_error_debug_calls, 1UL);
  ok &= test;
  TEST_ASSERT_UINT_EQ("ERR_raise: vset_error calls",
                      mock_core_obs.vset_error_calls, 1UL);
  ok &= test;
  TEST_ASSERT_UINT_EQ("ERR_raise: alternate stub not invoked",
                      mock_core_obs.alt_new_error_calls, 0UL);
  ok &= test;

  TEST_ASSERT_PTR_EQ("ERR_raise: new_error core identity",
                     mock_core_obs.new_error_core, &mock_core_primary);
  ok &= test;
  TEST_ASSERT_PTR_EQ("ERR_raise: set_error_debug core identity",
                     mock_core_obs.set_error_debug_core, &mock_core_primary);
  ok &= test;
  TEST_ASSERT_PTR_EQ("ERR_raise: set_error core identity",
                     mock_core_obs.vset_error_core, &mock_core_primary);
  ok &= test;

  TEST_ASSERT_UINT_EQ("ERR_raise: reason", mock_core_obs.reason, 42u);
  ok &= test;

  /* include/prov/err.h:47 passes NULL as the only variadic argument, so a
     null fmt is the observable signature of this macro. */
  TEST_ASSERT_PTR_NULL("ERR_raise: fmt is null", mock_core_obs.fmt_ptr);
  ok &= test;
  TEST_ASSERT_STR_EQ("ERR_raise: fmt recorded as empty",
                     mock_core_obs.fmt_text, "");
  ok &= test;
  TEST_ASSERT_INT_EQ("ERR_raise: va_list not traversed",
                     mock_core_obs.va_consumed, 0);
  ok &= test;

  TEST_ASSERT_INT_EQ("ERR_raise: captured line is the call site",
                     mock_core_obs.line, expected_line_first);
  ok &= test;
  TEST_ASSERT_STR_EQ("ERR_raise: captured file content",
                     mock_core_obs.file_text, expected_file);
  ok &= test;
  TEST_ASSERT_STR_EQ("ERR_raise: captured function is the enclosing one",
                     mock_core_obs.func_text, expected_func);
  ok &= test;
  /* The one pointer claim that is a contract rather than an accident of
     literal storage: <openssl/macros.h> defines OPENSSL_FILE as either
     __FILE__ or "" and OPENSSL_FUNC as either a function-name macro or
     "(unknown function)", so both always expand to a string and never to a
     null pointer.  Content cannot see a forwarded null on its own --
     mock_core.h records one as "", which is precisely what OPENSSL_FILE
     expands to under OPENSSL_NO_FILENAMES -- so the two checks together are
     what content plus a null forwarding cannot both satisfy.  Identity is not
     asserted here; hazard 3 at the head of this file says why, and names
     where it is asserted instead. */
  TEST_ASSERT_PTR_NOT_NULL("ERR_raise: captured file is not null",
                           mock_core_obs.file_ptr);
  ok &= test;
  TEST_ASSERT_PTR_NOT_NULL("ERR_raise: captured function is not null",
                           mock_core_obs.func_ptr);
  ok &= test;

  mock_core_reset();

  /* DO NOT REFLOW THE NEXT LINE -- see the note above. */
  expected_line_second = OPENSSL_LINE; ERR_raise(handle, 43u);

  TEST_ASSERT_INT_EQ("ERR_raise: second captured line is its own call site",
                     mock_core_obs.line, expected_line_second);
  ok &= test;
  TEST_ASSERT(expected_line_second > expected_line_first);
  ok &= test;
  TEST_ASSERT(mock_core_obs.line != expected_line_first);
  ok &= test;
  TEST_ASSERT_UINT_EQ("ERR_raise: second reason", mock_core_obs.reason, 43u);
  ok &= test;
  TEST_ASSERT_STR_EQ("ERR_raise: second captured file content",
                     mock_core_obs.file_text, expected_file);
  ok &= test;
  TEST_ASSERT_STR_EQ("ERR_raise: second captured function",
                     mock_core_obs.func_text, expected_func);
  ok &= test;

  mock_core_reset();

  ERR_raise(handle, 44u);
  ERR_raise(handle, 45u);

  TEST_ASSERT_SIZE_EQ("ERR_raise: two raises record six ordinals",
                      mock_core_obs.seq_len, (size_t)6);
  ok &= test;
  TEST_ASSERT_INT_EQ("ERR_raise: repeat ordinal 4 is new_error",
                     mock_core_obs.seq[3], MOCK_CORE_ORD_NEW_ERROR);
  ok &= test;
  TEST_ASSERT_INT_EQ("ERR_raise: repeat ordinal 5 is set_error_debug",
                     mock_core_obs.seq[4], MOCK_CORE_ORD_SET_ERROR_DEBUG);
  ok &= test;
  TEST_ASSERT_INT_EQ("ERR_raise: repeat ordinal 6 is set_error",
                     mock_core_obs.seq[5], MOCK_CORE_ORD_VSET_ERROR);
  ok &= test;
  TEST_ASSERT_UINT_EQ("ERR_raise: two raises, new_error twice",
                      mock_core_obs.new_error_calls, 2UL);
  ok &= test;
  TEST_ASSERT_UINT_EQ("ERR_raise: two raises, set_error_debug twice",
                      mock_core_obs.set_error_debug_calls, 2UL);
  ok &= test;
  TEST_ASSERT_UINT_EQ("ERR_raise: two raises, set_error twice",
                      mock_core_obs.vset_error_calls, 2UL);
  ok &= test;
  /* The last raise wins the single-valued observations. */
  TEST_ASSERT_UINT_EQ("ERR_raise: last reason of the pair",
                      mock_core_obs.reason, 45u);
  ok &= test;
  TEST_ASSERT_UINT_EQ("ERR_raise: two raises, nothing dropped",
                      mock_core_obs.seq_dropped, 0UL);
  ok &= test;

  proverr_free_handle(handle);
  return ok;
}

/*
 * ERR_raise_data() -- include/prov/err.h:49-52.
 *
 * The same three-step order as ERR_raise(), plus the two things only this
 * macro can show: the caller's format string arrives by identity rather than
 * as a copy, and the variadic arguments behind it survive the trip.
 *
 * HAZARD: __VA_ARGS__ must not be empty.  include/prov/err.h:52 pastes it
 * straight after "reason, ", so ERR_raise_data(handle, reason) alone would
 * expand to a trailing comma and not compile.  The minimum legal invocation
 * passes the format string and nothing more, and that minimum is exercised
 * below so the boundary is documented by a test rather than by a comment
 * alone.
 *
 * The final case asserts the equivalence include/prov/err.h:47 asserts of
 * itself: ERR_raise(h, r) is ERR_raise_data(h, r, NULL).  Driving the
 * expansion directly proves the delegation rather than assuming it.
 */
static int test_err_raise_data_macro(void)
{
  /* Owned by this function, so fmt's pointer identity is soundly checkable;
     see test_set_error_forwarding(). */
  static const char fmt[] = "%d %s";

  /* char, not const char: the decayed type must be the char * that
     MOCK_CORE_VA_INT_THEN_STR documents (see test_va_list_traversal()). */
  char detail[] = "hi";

  /* The position-independent expectations, captured once, for the reasons
     given in test_err_raise_macro(). */
  const char *const expected_file = OPENSSL_FILE;
  const char *const expected_func = OPENSSL_FUNC;

  int ok = 1;
  struct proverr_functions_st *handle;
  int expected_line;

  mock_core_reset();

  handle = proverr_new_handle(&mock_core_primary, mock_dispatch_complete);
  TEST_ASSERT_PTR_NOT_NULL("ERR_raise_data: handle from complete table",
                           handle);
  ok &= test;
  if (handle == NULL)
    return 0;

  TEST_ASSERT(strlen(expected_file) < (size_t)MOCK_CORE_TEXT_MAX);
  ok &= test;
  TEST_ASSERT(strlen(expected_func) < (size_t)MOCK_CORE_TEXT_MAX);
  ok &= test;
  TEST_ASSERT(strlen(fmt) < (size_t)MOCK_CORE_TEXT_MAX);
  ok &= test;
  TEST_ASSERT(strlen(detail) < (size_t)MOCK_CORE_TEXT_MAX);
  ok &= test;

  mock_core_reset();
  mock_core_obs.va_mode = MOCK_CORE_VA_INT_THEN_STR;

  /* DO NOT REFLOW THE NEXT LINE.  OPENSSL_LINE expands at the call site
     (include/prov/err.h:51), so the capture and the raise must stay on ONE
     physical line; split them and the expectation is off by one. */
  expected_line = OPENSSL_LINE; ERR_raise_data(handle, 7u, fmt, 99, detail);

  mock_core_obs.va_mode = MOCK_CORE_VA_NONE;   /* opt out again at once */

  TEST_ASSERT_SIZE_EQ("ERR_raise_data: three primitives ran",
                      mock_core_obs.seq_len, (size_t)3);
  ok &= test;
  TEST_ASSERT_INT_EQ("ERR_raise_data: first is new_error",
                     mock_core_obs.seq[0], MOCK_CORE_ORD_NEW_ERROR);
  ok &= test;
  TEST_ASSERT_INT_EQ("ERR_raise_data: second is set_error_debug",
                     mock_core_obs.seq[1], MOCK_CORE_ORD_SET_ERROR_DEBUG);
  ok &= test;
  TEST_ASSERT_INT_EQ("ERR_raise_data: third is set_error",
                     mock_core_obs.seq[2], MOCK_CORE_ORD_VSET_ERROR);
  ok &= test;
  TEST_ASSERT_UINT_EQ("ERR_raise_data: no ordinal dropped",
                      mock_core_obs.seq_dropped, 0UL);
  ok &= test;

  TEST_ASSERT_UINT_EQ("ERR_raise_data: new_error calls",
                      mock_core_obs.new_error_calls, 1UL);
  ok &= test;
  TEST_ASSERT_UINT_EQ("ERR_raise_data: set_error_debug calls",
                      mock_core_obs.set_error_debug_calls, 1UL);
  ok &= test;
  TEST_ASSERT_UINT_EQ("ERR_raise_data: vset_error calls",
                      mock_core_obs.vset_error_calls, 1UL);
  ok &= test;
  TEST_ASSERT_UINT_EQ("ERR_raise_data: alternate stub not invoked",
                      mock_core_obs.alt_new_error_calls, 0UL);
  ok &= test;

  TEST_ASSERT_PTR_EQ("ERR_raise_data: new_error core identity",
                     mock_core_obs.new_error_core, &mock_core_primary);
  ok &= test;
  TEST_ASSERT_PTR_EQ("ERR_raise_data: set_error_debug core identity",
                     mock_core_obs.set_error_debug_core, &mock_core_primary);
  ok &= test;
  TEST_ASSERT_PTR_EQ("ERR_raise_data: set_error core identity",
                     mock_core_obs.vset_error_core, &mock_core_primary);
  ok &= test;

  TEST_ASSERT_UINT_EQ("ERR_raise_data: reason", mock_core_obs.reason, 7u);
  ok &= test;

  /* The distinguishing claim: the caller's own string, not a copy of it. */
  TEST_ASSERT_PTR_EQ("ERR_raise_data: fmt pointer identity",
                     mock_core_obs.fmt_ptr, fmt);
  ok &= test;
  TEST_ASSERT_STR_EQ("ERR_raise_data: fmt content", mock_core_obs.fmt_text,
                     fmt);
  ok &= test;
  TEST_ASSERT_PTR_NOT_NULL("ERR_raise_data: fmt is not null",
                           mock_core_obs.fmt_ptr);
  ok &= test;

  TEST_ASSERT_INT_EQ("ERR_raise_data: traversal happened",
                     mock_core_obs.va_consumed, 1);
  ok &= test;
  TEST_ASSERT_INT_EQ("ERR_raise_data: int argument recovered",
                     mock_core_obs.va_int, 99);
  ok &= test;
  TEST_ASSERT_PTR_EQ("ERR_raise_data: string argument pointer identity",
                     mock_core_obs.va_str_ptr, detail);
  ok &= test;
  TEST_ASSERT_STR_EQ("ERR_raise_data: string argument content",
                     mock_core_obs.va_str_text, detail);
  ok &= test;

  TEST_ASSERT_INT_EQ("ERR_raise_data: captured line is the call site",
                     mock_core_obs.line, expected_line);
  ok &= test;
  TEST_ASSERT_STR_EQ("ERR_raise_data: captured file content",
                     mock_core_obs.file_text, expected_file);
  ok &= test;
  TEST_ASSERT_STR_EQ("ERR_raise_data: captured function is the enclosing one",
                     mock_core_obs.func_text, expected_func);
  ok &= test;
  /* Neither macro can expand to a null pointer -- see the same pair in
     test_err_raise_macro() for why this is the one pointer property content
     cannot cover on its own. */
  TEST_ASSERT_PTR_NOT_NULL("ERR_raise_data: captured file is not null",
                           mock_core_obs.file_ptr);
  ok &= test;
  TEST_ASSERT_PTR_NOT_NULL("ERR_raise_data: captured function is not null",
                           mock_core_obs.func_ptr);
  ok &= test;

  /*
   * --- the minimum legal __VA_ARGS__: the format string and nothing else ---
   * Consumption stays off, because there is no argument behind fmt to walk.
   */
  mock_core_reset();

  /* DO NOT REFLOW THE NEXT LINE -- see the note above. */
  expected_line = OPENSSL_LINE; ERR_raise_data(handle, 9u, fmt);

  TEST_ASSERT_SIZE_EQ("ERR_raise_data: bare fmt, three primitives ran",
                      mock_core_obs.seq_len, (size_t)3);
  ok &= test;
  TEST_ASSERT_UINT_EQ("ERR_raise_data: bare fmt, reason",
                      mock_core_obs.reason, 9u);
  ok &= test;
  TEST_ASSERT_PTR_EQ("ERR_raise_data: bare fmt, pointer identity",
                     mock_core_obs.fmt_ptr, fmt);
  ok &= test;
  TEST_ASSERT_INT_EQ("ERR_raise_data: bare fmt, va_list not traversed",
                     mock_core_obs.va_consumed, 0);
  ok &= test;
  TEST_ASSERT_INT_EQ("ERR_raise_data: bare fmt, captured line",
                     mock_core_obs.line, expected_line);
  ok &= test;

  /*
   * --- the delegation at include/prov/err.h:47 ---
   * ERR_raise(h, r) is defined AS ERR_raise_data((h),(r),NULL), so driving
   * the general macro with an explicit NULL must produce exactly what the
   * convenience macro produces: the same sequence and a null fmt.
   */
  mock_core_reset();

  ERR_raise_data(handle, 11u, NULL);

  TEST_ASSERT_SIZE_EQ("ERR_raise_data: explicit null fmt, three primitives",
                      mock_core_obs.seq_len, (size_t)3);
  ok &= test;
  TEST_ASSERT_INT_EQ("ERR_raise_data: explicit null fmt, first is new_error",
                     mock_core_obs.seq[0], MOCK_CORE_ORD_NEW_ERROR);
  ok &= test;
  TEST_ASSERT_INT_EQ("ERR_raise_data: explicit null fmt, second is debug",
                     mock_core_obs.seq[1], MOCK_CORE_ORD_SET_ERROR_DEBUG);
  ok &= test;
  TEST_ASSERT_INT_EQ("ERR_raise_data: explicit null fmt, third is set_error",
                     mock_core_obs.seq[2], MOCK_CORE_ORD_VSET_ERROR);
  ok &= test;
  TEST_ASSERT_UINT_EQ("ERR_raise_data: explicit null fmt, reason",
                      mock_core_obs.reason, 11u);
  ok &= test;
  TEST_ASSERT_PTR_NULL("ERR_raise_data: explicit null fmt is null",
                       mock_core_obs.fmt_ptr);
  ok &= test;
  TEST_ASSERT_STR_EQ("ERR_raise_data: explicit null fmt recorded as empty",
                     mock_core_obs.fmt_text, "");
  ok &= test;
  TEST_ASSERT_INT_EQ("ERR_raise_data: explicit null fmt, no traversal",
                     mock_core_obs.va_consumed, 0);
  ok &= test;

  proverr_free_handle(handle);
  return ok;
}

/*
 * The exit status is derived twice over and agreement is required.
 *
 * testutil.h's counters are the primary authority -- a run that asserted
 * nothing fails, and any mismatch fails -- so reaching the end of main()
 * cannot manufacture a pass.  The accumulated per-case verdicts are the
 * secondary authority: they would still fail the process if a future edit
 * ever loosened the counters.  Either one failing fails the run.
 */
int main(void)
{
  int ok = 1;
  int status;

  ok &= test_new_error_forwarding();
  ok &= test_set_error_debug_forwarding();
  ok &= test_set_error_forwarding();
  ok &= test_va_list_traversal();
  ok &= test_err_raise_macro();
  ok &= test_err_raise_data_macro();

  status = TEST_REPORT("test_err_raise");
  return status != 0 || !ok ? 1 : 0;
}
