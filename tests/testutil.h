/* CC0 license applied, see LICENCE.md */

#ifndef LIBPROV_TESTS_TESTUTIL_H
#define LIBPROV_TESTS_TESTUTIL_H

/*
 * ===========================================================================
 * tests/testutil.h -- shared assertion machinery for the libprov test suite
 * ===========================================================================
 *
 * Every test program under tests/ includes this header FIRST.  It is
 * deliberately self-contained: it pulls in nothing but the C standard library,
 * so it can be included ahead of any project or OpenSSL header without
 * perturbing them, and it needs no library beyond libc to link.
 *
 * No user-specified rules exist for this project -- the rules facility reports
 * "No user rules provided" -- so this header is held to ordinary
 * enterprise-standard C practice.  The constraints it does honour come from
 * the project's testing requirements and are spelled out in the numbered
 * sections below, each next to the code that implements it.
 *
 * ---------------------------------------------------------------------------
 * 1.  NO SMOKE TESTS -- the exit-status contract, which this header enforces
 * ---------------------------------------------------------------------------
 *
 * A test that merely calls library code and observes that nothing crashed
 * proves nothing at all.  This header makes such a test structurally unable to
 * report success: every assertion below bumps a per-program counter pair, and
 * the exit status is derived from those counters and from nothing else.
 *
 *     exit status is non-zero  if and only if
 *         (mismatches > 0)  or  (assertions executed == 0)
 *
 * A program that asserts nothing therefore FAILS, loudly, with the reason
 * printed.  Reaching the end of main() cannot manufacture a pass.
 *
 * ---------------------------------------------------------------------------
 * 2.  The project's own test idiom is preserved
 * ---------------------------------------------------------------------------
 *
 * libprov's test programs are standalone C99 executables that accumulate a
 * success flag and use a TEST_ASSERT() macro recording the truth of the
 * asserted expression in a variable named `test`, used like this:
 *
 *     TEST_ASSERT(expr); ret &= test;
 *
 * That spelling is preserved verbatim, and both `test` and `ret` are supplied
 * here so a test program can use the idiom without declaring anything.
 *
 * ONE DELIBERATE DIVERGENCE: the original macro prints and continues,
 * accumulating results.  Continue-on-failure is kept -- one run then diagnoses
 * every problem rather than only the first -- but the exit status is no longer
 * a free-standing flag that a test could forget to maintain.  `ret` is
 * refreshed from the counters by every assertion, so it means precisely "at
 * least one assertion has run and none of them has failed".  Both exit idioms
 * are consequently counter-derived and both honour section 1:
 *
 *     return TEST_REPORT("test_num_get");   preferred, also prints a summary
 *     return !ret;                          the project's original spelling
 *
 * ---------------------------------------------------------------------------
 * 3.  CALL, STORE, THEN ASSERT -- read this before writing a single test
 * ---------------------------------------------------------------------------
 *
 * C does not specify the order in which function-call arguments are
 * evaluated.  Reading an output of the function under test inside the SAME
 * expression that calls it is therefore a bug, not a style preference.  This
 * was observed for real while this suite was being designed: a probe shaped
 * like
 *
 *     printf("rc=%d val=%zu\n", provnum_get_size_t(&val, &p), val);
 *
 * printed val=0 for cases that had in fact succeeded, because `val` was read
 * before the call that fills it had run.  Always do it in three steps:
 *
 *     rc = provnum_get_size_t(&val, &p);          1. call, store the result
 *     rs = p.return_size;                         2. read the side effects
 *     TEST_ASSERT_INT_EQ("get rc", rc, 1);        3. assert stored values
 *     TEST_ASSERT_SIZE_EQ("get val", val, (size_t)5);
 *
 * Every value-comparing macro here accepts ALREADY-COMPUTED values for exactly
 * that reason, and each one expands to a single function call, so every
 * argument is evaluated exactly once.  TEST_ASSERT() is the only macro that
 * must evaluate an expression of its own, and it evaluates it once.
 *
 * ---------------------------------------------------------------------------
 * 4.  Include guards, and why the project's public headers have none
 * ---------------------------------------------------------------------------
 *
 * include/prov/num.h and include/prov/err.h deliberately carry NO include
 * guards, and both get away with it: err.h precedes each of its #defines with
 * a matching #undef, and num.h contains only declarations and object-like
 * macros, so each is idempotent by construction.  The test fixtures take the
 * opposite and ordinary position and DO guard, because they define objects
 * with internal linkage and would otherwise break on a second inclusion.  The
 * guard above this comment is that guard.
 *
 * ---------------------------------------------------------------------------
 * 5.  Passing PROVNUM_E_* codes to these macros is safe
 * ---------------------------------------------------------------------------
 *
 * include/prov/num.h spells its error codes UNPARENTHESISED:
 *
 *     #define PROVNUM_E_TOOBIG        -2
 *
 * A macro that pasted such a parameter next to an operator could therefore
 * emit something like "x--2".  Nothing here does: every macro parameter is
 * used parenthesised, and the only operations applied to an expected value are
 * a cast and an equality comparison.  So
 *
 *     TEST_ASSERT_INT_EQ("rc", rc, PROVNUM_E_TOOBIG);
 *
 * is well-formed, and so is the same call with any of the other three codes.
 *
 * ---------------------------------------------------------------------------
 * 6.  Isolation, and no dependency on libcrypto
 * ---------------------------------------------------------------------------
 *
 * All state here has internal linkage, so every test executable owns its own
 * counters and no two executables can interfere: running the suite with
 * "ctest -j N" is safe.  Nothing here allocates, opens a file, reads the
 * environment, forks, or calls into libcrypto.  That last point is
 * load-bearing: libprov's provnum_ family exists precisely to replace
 * libcrypto's OSSL_PARAM_get_ and OSSL_PARAM_set_ helpers, so a test that
 * called those would be measuring upstream OpenSSL instead of libprov.
 * <openssl/params.h> is not included here, and must not be included by any
 * test.
 *
 * ---------------------------------------------------------------------------
 * 7.  Colour
 * ---------------------------------------------------------------------------
 *
 * Verdicts are colourised with two short ANSI escapes, matching the project's
 * existing test output.  Compile with -DTESTUTIL_COLOUR=0 for escape-free
 * output.  isatty() is deliberately NOT used: it would drag POSIX headers into
 * a header that has to compile as strict C99.
 */

#include <stdio.h>              /* printf, fflush, stdout                   */
#include <string.h>             /* memcmp, strcmp                           */
#include <stddef.h>             /* size_t, NULL                             */
#include <inttypes.h>           /* intmax_t, uintmax_t, PRIdMAX, PRIuMAX,   */
                                /* and, transitively, <stdint.h> so that    */
                                /* tests get SIZE_MAX and UINT32_MAX        */

/*
 * ---------------------------------------------------------------------------
 * Colour control (section 7)
 * ---------------------------------------------------------------------------
 */
#ifndef TESTUTIL_COLOUR
# define TESTUTIL_COLOUR 1
#endif

#if TESTUTIL_COLOUR
# define TESTUTIL_GREEN "\033[32m"
# define TESTUTIL_RED   "\033[31m"
# define TESTUTIL_OFF   "\033[0m"
#else
# define TESTUTIL_GREEN ""
# define TESTUTIL_RED   ""
# define TESTUTIL_OFF   ""
#endif

/*
 * How many bytes of each buffer a failing TEST_ASSERT_MEM_EQ() dumps.  The
 * suite's fixtures are a handful of bytes wide, so this only ever matters as a
 * guard against one pathological call flooding the CTest log; the offset of
 * the first difference is always reported, in bounds or not.
 */
#ifndef TESTUTIL_HEXDUMP_MAX
# define TESTUTIL_HEXDUMP_MAX 64
#endif

/*
 * How many differing offsets a failing TEST_ASSERT_MEM_EQ() lists numerically
 * before it elides the rest.  The caret line still marks every difference
 * within the dump.
 */
#ifndef TESTUTIL_OFFSETS_MAX
# define TESTUTIL_OFFSETS_MAX 16
#endif

/*
 * ---------------------------------------------------------------------------
 * Per-program state.  Every object below has internal linkage: each test
 * executable owns its own copy, which is what makes "ctest -j N" safe.
 *
 * These are TENTATIVE definitions -- no initialisers -- and that is
 * deliberate, for two independent reasons:
 *
 *   1. Zero is exactly the right starting state.  `ret` therefore starts
 *      false, so a program that asserts nothing fails even through the
 *      "return !ret;" idiom of section 2, not merely through TEST_REPORT().
 *
 *   2. A tentative definition may legally be repeated, so a test source that
 *      declares `static int ret;` or `static int test = 1;` of its own still
 *      compiles.  An initialiser here would turn that into a redefinition
 *      error.
 *
 * They are referenced by testutil_count() below, and that reference is what
 * keeps -Wunused-variable quiet in a translation unit that happens never to
 * touch them directly.  Please do not "tidy it away".
 * ---------------------------------------------------------------------------
 */

/* Truth of the most recent assertion: the project's `test` variable. */
static int test;

/*
 * "At least one assertion has run and none has failed."  Refreshed by every
 * assertion so that "TEST_ASSERT(e); ret &= test;" stays literal while the
 * value itself stays derived from the counters below rather than from a flag a
 * test could forget to clear.
 */
static int ret;

/* The authoritative state: how many assertions ran, and how many disagreed. */
static unsigned long testutil_asserted;
static unsigned long testutil_mismatched;

/*
 * ---------------------------------------------------------------------------
 * Internal plumbing.  Everything is "static inline" rather than plain
 * "static": an unused static inline function draws no -Wunused-function
 * diagnostic, so a test that uses only two of these macros still compiles
 * warning-free.
 *
 * Note the absence of single-letter identifiers below.  A one-letter parameter
 * or local in a shared header shadows any file-scope object a test happens to
 * give the same name, and -Wshadow then reports the collision against THIS
 * file, which is a confusing place for a reader to land.  Including this header
 * first, as every test does, already avoids that -- the test's own objects do
 * not exist yet at this point -- but spelling the names out makes the header
 * immune to include order as well as easier to read.
 * ---------------------------------------------------------------------------
 */

/* Never hand a null label to printf("%s"); say so instead. */
static inline const char *testutil_text(const char *str)
{
    return str == NULL ? "(null)" : str;
}

/*
 * Record one verdict.  This is the single place where the counters, `test` and
 * `ret` are updated, so the exit-status contract of section 1 has exactly one
 * implementation.
 */
static inline void testutil_count(int ok)
{
    testutil_asserted++;
    if (!ok)
        testutil_mismatched++;
    test = ok ? 1 : 0;
    ret = testutil_mismatched == 0UL ? 1 : 0;
}

/* Print the coloured verdict tag that opens every result line. */
static inline void testutil_tag(int ok)
{
    printf("%s[%s]%s ", ok ? TESTUTIL_GREEN : TESTUTIL_RED,
           ok ? "PASS" : "FAIL", TESTUTIL_OFF);
}

/* Print a string as a quoted literal, or as (null) when there is none. */
static inline void testutil_print_str(const char *str)
{
    if (str == NULL)
        printf("(null)");
    else
        printf("\"%s\"", str);
}

/*
 * Dump one buffer as space-separated two-digit uppercase hex, aligned under a
 * short field name so the actual, expected and marker rows line up column for
 * column.  `shown` is the caller's already-clamped byte count.
 */
static inline void testutil_print_hex(const char *field,
                                      const unsigned char *bytes,
                                      size_t shown, size_t len)
{
    size_t pos;

    printf("           %-8s :", field);
    for (pos = 0; pos < shown; pos++)
        printf(" %02X", (unsigned int)bytes[pos]);
    if (shown < len)
        printf(" ...  (%zu of %zu bytes shown)", shown, len);
    printf("\n");
}

/*
 * Mark the differing byte positions underneath the two hex rows: "^^" where
 * the buffers disagree, ".." where they agree.
 */
static inline void testutil_print_marks(const unsigned char *pact,
                                        const unsigned char *pexp,
                                        size_t shown)
{
    size_t pos;

    printf("           %-8s :", "diff");
    for (pos = 0; pos < shown; pos++)
        printf(" %s", pact[pos] == pexp[pos] ? ".." : "^^");
    printf("\n");
}

/*
 * ---------------------------------------------------------------------------
 * The assertion workers.  Each one records the verdict, prints a single
 * self-diagnosing line, and returns the verdict so that an assertion may also
 * be used in an expression.  A failing line always carries the label, the
 * actual value AND the expected value, so a CTest failure is diagnosable
 * straight from the log, with no debugger and no rerun.
 * ---------------------------------------------------------------------------
 */

/* Backs TEST_ASSERT(): `expr` is the stringified expression. */
static inline int testutil_check_bool(const char *expr, int ok)
{
    testutil_count(ok);
    testutil_tag(ok);
    printf("%s\n", testutil_text(expr));
    return ok;
}

/* Backs TEST_ASSERT_INT_EQ(): signed comparison at maximum width. */
static inline int testutil_check_int(const char *label, intmax_t actual,
                                     intmax_t expected)
{
    int ok = actual == expected;

    testutil_count(ok);
    testutil_tag(ok);
    if (ok)
        printf("%s: %" PRIdMAX "\n", testutil_text(label), actual);
    else
        printf("%s: actual %" PRIdMAX ", expected %" PRIdMAX "\n",
               testutil_text(label), actual, expected);
    return ok;
}

/*
 * Backs TEST_ASSERT_UINT_EQ(): unsigned comparison at maximum width.  Values
 * such as UINT32_MAX travel through as themselves, with no sign extension,
 * because the macro casts to uintmax_t before the call.
 */
static inline int testutil_check_uint(const char *label, uintmax_t actual,
                                      uintmax_t expected)
{
    int ok = actual == expected;

    testutil_count(ok);
    testutil_tag(ok);
    if (ok)
        printf("%s: %" PRIuMAX "\n", testutil_text(label), actual);
    else
        printf("%s: actual %" PRIuMAX ", expected %" PRIuMAX "\n",
               testutil_text(label), actual, expected);
    return ok;
}

/*
 * Backs TEST_ASSERT_SIZE_EQ().  size_t has its own worker and its own "%zu"
 * conversion on purpose: "%lu" is wrong wherever size_t is not unsigned long,
 * and a cast down to some other width could silently hide a mismatch.
 */
static inline int testutil_check_size(const char *label, size_t actual,
                                      size_t expected)
{
    int ok = actual == expected;

    testutil_count(ok);
    testutil_tag(ok);
    if (ok)
        printf("%s: %zu\n", testutil_text(label), actual);
    else
        printf("%s: actual %zu, expected %zu\n", testutil_text(label),
               actual, expected);
    return ok;
}

/*
 * Backs TEST_ASSERT_PTR_EQ(): pointer IDENTITY, which is a different claim
 * from value equality and is the right one wherever a contract says a pointer
 * is passed through rather than copied.
 */
static inline int testutil_check_ptr_eq(const char *label, const void *actual,
                                        const void *expected)
{
    int ok = actual == expected;

    testutil_count(ok);
    testutil_tag(ok);
    if (ok)
        printf("%s: %p\n", testutil_text(label), actual);
    else
        printf("%s: actual %p, expected %p\n", testutil_text(label),
               actual, expected);
    return ok;
}

/* Backs TEST_ASSERT_PTR_NE(): the two pointers must NOT be the same object. */
static inline int testutil_check_ptr_ne(const char *label, const void *actual,
                                        const void *other)
{
    int ok = actual != other;

    testutil_count(ok);
    testutil_tag(ok);
    if (ok)
        printf("%s: %p, distinct from %p\n", testutil_text(label),
               actual, other);
    else
        printf("%s: actual %p, expected any pointer other than %p\n",
               testutil_text(label), actual, other);
    return ok;
}

/* Backs TEST_ASSERT_PTR_NULL(). */
static inline int testutil_check_ptr_null(const char *label,
                                          const void *actual)
{
    int ok = actual == NULL;

    testutil_count(ok);
    testutil_tag(ok);
    if (ok)
        printf("%s: (null)\n", testutil_text(label));
    else
        printf("%s: actual %p, expected (null)\n", testutil_text(label),
               actual);
    return ok;
}

/* Backs TEST_ASSERT_PTR_NOT_NULL(). */
static inline int testutil_check_ptr_not_null(const char *label,
                                              const void *actual)
{
    int ok = actual != NULL;

    testutil_count(ok);
    testutil_tag(ok);
    if (ok)
        printf("%s: %p\n", testutil_text(label), actual);
    else
        printf("%s: actual (null), expected a non-null pointer\n",
               testutil_text(label));
    return ok;
}

/*
 * Backs TEST_ASSERT_STR_EQ().  Null-safe on both sides: two null pointers
 * compare equal, one null pointer never matches a string, and neither case
 * reaches strcmp().
 */
static inline int testutil_check_str_eq(const char *label, const char *actual,
                                        const char *expected)
{
    int ok;

    if (actual == NULL || expected == NULL)
        ok = actual == expected;
    else
        ok = strcmp(actual, expected) == 0;

    testutil_count(ok);
    testutil_tag(ok);
    printf("%s: ", testutil_text(label));
    if (ok) {
        testutil_print_str(actual);
    } else {
        printf("actual ");
        testutil_print_str(actual);
        printf(", expected ");
        testutil_print_str(expected);
    }
    printf("\n");
    return ok;
}

/*
 * Backs TEST_ASSERT_MEM_EQ(): byte-level comparison with a readable hex diff.
 *
 * Two deliberate choices worth knowing about:
 *
 *   - A null buffer with a non-zero length is reported as a mismatch, never
 *     passed to memcmp().  A fixture bug must produce a diagnosis, not a
 *     segmentation fault in the harness.
 *
 *   - A zero-length comparison PASSES, with the vacuity spelled out in the
 *     output.  Comparing zero bytes is a legitimate thing for a test of a
 *     zero-capacity destination to do, so failing it would break a real case;
 *     printing "0 bytes compared" keeps the vacuity visible in the log
 *     instead of hiding it behind a bare PASS.
 */
static inline int testutil_check_mem_eq(const char *label, const void *actual,
                                        const void *expected, size_t len)
{
    const unsigned char *pact = (const unsigned char *)actual;
    const unsigned char *pexp = (const unsigned char *)expected;
    size_t shown = len > (size_t)TESTUTIL_HEXDUMP_MAX
                   ? (size_t)TESTUTIL_HEXDUMP_MAX : len;
    size_t differing = 0;
    size_t first = 0;
    size_t listed = 0;
    size_t pos;
    int ok;

    if (len == 0) {
        testutil_count(1);
        testutil_tag(1);
        printf("%s: 0 bytes compared\n", testutil_text(label));
        return 1;
    }

    if (pact == NULL || pexp == NULL) {
        testutil_count(0);
        testutil_tag(0);
        printf("%s: cannot compare %zu bytes, actual is %s and expected is"
               " %s\n", testutil_text(label), len,
               pact == NULL ? "(null)" : "a buffer",
               pexp == NULL ? "(null)" : "a buffer");
        return 0;
    }

    ok = memcmp(pact, pexp, len) == 0;
    if (!ok)
        for (pos = 0; pos < len; pos++)
            if (pact[pos] != pexp[pos]) {
                if (differing == 0)
                    first = pos;
                differing++;
            }

    testutil_count(ok);
    testutil_tag(ok);
    if (ok) {
        printf("%s: %zu bytes match\n", testutil_text(label), len);
        return ok;
    }

    printf("%s: %zu of %zu bytes differ, first at offset %zu\n",
           testutil_text(label), differing, len, first);
    testutil_print_hex("actual", pact, shown, len);
    testutil_print_hex("expected", pexp, shown, len);
    testutil_print_marks(pact, pexp, shown);
    printf("           %-8s :", "offsets");
    for (pos = 0; pos < len && listed < (size_t)TESTUTIL_OFFSETS_MAX; pos++)
        if (pact[pos] != pexp[pos]) {
            printf(" %zu", pos);
            listed++;
        }
    if (listed < differing)
        printf(" ...  (%zu of %zu offsets listed)", listed, differing);
    printf("\n");
    return ok;
}

/*
 * ---------------------------------------------------------------------------
 * The reporter.  This is where section 1's contract is cashed in: the returned
 * exit status is a function of the counters and of nothing else.
 * ---------------------------------------------------------------------------
 */
static inline int testutil_report(const char *name)
{
    int failed = testutil_mismatched != 0UL || testutil_asserted == 0UL;

    if (testutil_asserted == 0UL)
        printf("%s[FAIL]%s %s: no assertions executed -- a test that asserts"
               " nothing cannot pass\n", TESTUTIL_RED, TESTUTIL_OFF,
               testutil_text(name));

    printf("%s%s: %lu assertions, %lu mismatches%s\n",
           failed ? TESTUTIL_RED : TESTUTIL_GREEN, testutil_text(name),
           testutil_asserted, testutil_mismatched, TESTUTIL_OFF);
    fflush(stdout);
    return failed ? 1 : 0;
}

/*
 * ===========================================================================
 * The public interface.
 *
 * Each macro expands to exactly one function call.  That is what makes every
 * argument evaluated exactly once, and it is why none of them needs a
 * do { ... } while (0) wrapper to behave as a statement: all of
 *
 *     TEST_ASSERT(rc == 1); ret &= test;
 *     if (verbose) TEST_ASSERT_INT_EQ("rc", rc, 1); else record(rc);
 *     failed = !TEST_ASSERT_PTR_NULL("handle", h);
 *
 * do what they look like.  Every parameter is used parenthesised, so the
 * unparenthesised PROVNUM_E_* codes of section 5 are safe to pass.
 *
 * Pointer arguments are cast to "const void *" rather than to "void *": %p is
 * clean with a const-qualified void pointer, and casting the qualifier away
 * would be a gratuitous lie about the caller's data.
 * ===========================================================================
 */

/*
 * The project's own assertion: records the truth of `e` in `test` and prints
 * the stringified expression.  This is also the universal escape hatch -- any
 * claim at all can be phrased as TEST_ASSERT(claim) -- but prefer a typed
 * macro below when there is one, because those print the actual and the
 * expected value, and this one can only print the source text.
 */
#define TEST_ASSERT(e)                                                      \
    testutil_check_bool(#e, (e) ? 1 : 0)

/* Signed integers, up to intmax_t: return codes, line numbers, wait status. */
#define TEST_ASSERT_INT_EQ(label, actual, expected)                         \
    testutil_check_int((label), (intmax_t)(actual), (intmax_t)(expected))

/* Unsigned integers, up to uintmax_t: reason codes, flags, counters. */
#define TEST_ASSERT_UINT_EQ(label, actual, expected)                        \
    testutil_check_uint((label), (uintmax_t)(actual), (uintmax_t)(expected))

/* size_t specifically: sizes, capacities, and OSSL_PARAM return_size. */
#define TEST_ASSERT_SIZE_EQ(label, actual, expected)                        \
    testutil_check_size((label), (size_t)(actual), (size_t)(expected))

/* Pointer identity, for contracts that pass a pointer through unchanged. */
#define TEST_ASSERT_PTR_EQ(label, actual, expected)                         \
    testutil_check_ptr_eq((label), (const void *)(actual),                  \
                          (const void *)(expected))

/* Pointer distinctness, for contracts that must hand back a fresh object. */
#define TEST_ASSERT_PTR_NE(label, actual, other)                            \
    testutil_check_ptr_ne((label), (const void *)(actual),                  \
                          (const void *)(other))

/* The pointer must be null. */
#define TEST_ASSERT_PTR_NULL(label, actual)                                 \
    testutil_check_ptr_null((label), (const void *)(actual))

/* The pointer must not be null. */
#define TEST_ASSERT_PTR_NOT_NULL(label, actual)                             \
    testutil_check_ptr_not_null((label), (const void *)(actual))

/* String contents, null-safe on both sides. */
#define TEST_ASSERT_STR_EQ(label, actual, expected)                         \
    testutil_check_str_eq((label), (actual), (expected))

/* Byte-for-byte buffer equality, with a hex diff on mismatch. */
#define TEST_ASSERT_MEM_EQ(label, actual, expected, len)                    \
    testutil_check_mem_eq((label), (const void *)(actual),                  \
                          (const void *)(expected), (size_t)(len))

/*
 * Print the one-line summary and yield the process exit status.  Use it as the
 * final statement of main():
 *
 *     int main(void)
 *     {
 *         int rc;
 *         size_t val = 0;
 *         OSSL_PARAM p = { NULL, OSSL_PARAM_UNSIGNED_INTEGER, buf, 1, 0 };
 *
 *         rc = provnum_get_size_t(&val, &p);
 *         TEST_ASSERT_INT_EQ("1-byte source rc", rc, 1); ret &= test;
 *         TEST_ASSERT_SIZE_EQ("1-byte source value", val, (size_t)5);
 *
 *         return TEST_REPORT("test_num_get");
 *     }
 */
#define TEST_REPORT(name)                                                   \
    testutil_report(name)

#endif                          /* LIBPROV_TESTS_TESTUTIL_H */

