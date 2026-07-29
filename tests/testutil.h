/* CC0 license applied, see LICENSE */

#ifndef LIBPROV_TESTS_TESTUTIL_H
#define LIBPROV_TESTS_TESTUTIL_H

/*
 * Shared assertion machinery for the libprov test suite.  Include it first:
 * it pulls in nothing but the C standard library.
 *
 * EXIT STATUS IS DERIVED FROM THE COUNTERS, NEVER FROM CONTROL FLOW.  Every
 * assertion bumps testutil_asserted and a failing one bumps
 * testutil_mismatched; the status is non-zero on a mismatch OR when no
 * assertion ran at all, so reaching the end of main() cannot manufacture a
 * pass.  Only an assertion that actually INSPECTED a value counts, which is
 * why TEST_ASSERT_MEM_EQ() over zero bytes is recorded as a mismatch;
 * testutil_check_mem_eq() says what a zero-capacity case should assert
 * instead.
 *
 * CALL, STORE, THEN ASSERT.  C does not specify the order in which
 * function-call arguments are evaluated, so reading an output of the function
 * under test inside the same expression that calls it is a bug:
 *
 *     rc = provnum_get_size_t(&val, &p);        1. call, store the result
 *     rs = p.return_size;                       2. read the side effects
 *     TEST_ASSERT_INT_EQ("get rc", rc, 1);      3. assert stored values
 *
 * Every value-comparing macro takes already-computed values for that reason,
 * and each expands to a single function call, so no argument is evaluated
 * twice and each assigns its verdict to the `test` visible at the call site --
 * which is what keeps "TEST_ASSERT(expr); ret &= test;" literal.
 *
 * EVERY FAILURE NAMES ITS SOURCE LINE.  Each macro forwards its own call
 * site's __FILE__ and __LINE__ -- the reason these are macros rather than
 * functions -- and prints "<file>:<line>: <label>: actual ..., expected ..."
 * on failures only.  The captured line is the line the MACRO NAME is on, and
 * __FILE__ is whatever path the compiler was handed, so it is relative to the
 * build's working directory.
 *
 * THIS HEADER ITSELF allocates nothing, opens no file, reads no environment
 * variable, forks no process and includes no OpenSSL header at all: the four
 * includes below are the whole of its dependencies.
 *
 * The suite-wide rule it exists to serve is about CALLS, not includes:
 * libprov's provnum_ family exists precisely to replace libcrypto's
 * OSSL_PARAM_get_, OSSL_PARAM_set_ and OSSL_PARAM_construct_ helpers, so a
 * test that called one of those would be measuring upstream OpenSSL instead of
 * libprov.  NO TEST CALLS ONE, and no test includes <openssl/params.h>
 * directly.  It is nevertheless reached transitively by the five tests that
 * include prov/err.h, whose <openssl/core_dispatch.h> pulls in
 * <openssl/indicator.h>, which includes it -- the project header's own include
 * graph, not a choice any test makes.  A declaration links nothing, which is
 * why every test binary's dynamic dependencies are still the vDSO, libc and
 * the loader alone.
 *
 * include/prov/num.h spells its error codes unparenthesised
 * ("#define PROVNUM_E_TOOBIG -2"), so every macro parameter below is used
 * parenthesised and any PROVNUM_E_ code is safe to pass.
 */

#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <inttypes.h>

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
 * cap only matters as a guard against one pathological call flooding the log;
 * the offset of the first difference is always reported, in bounds or not.
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
 * Internal linkage, so each test executable owns its own counters and
 * separate executables cannot interfere.  No initialiser, so all four start
 * at zero: that is what makes "return !ret;" fail a program which asserted
 * nothing.
 */

static int test;

/*
 * "At least one assertion has run and none has failed."  Refreshed by every
 * assertion so that "TEST_ASSERT(e); ret &= test;" stays literal while the
 * value itself stays derived from the counters rather than from a flag a test
 * could forget to clear.
 */
static int ret;

static unsigned long testutil_asserted;
static unsigned long testutil_mismatched;

/*
 * The helpers below are "static inline" rather than plain "static" so that an
 * unused one draws no -Wunused-function diagnostic: a test using only two of
 * these macros still compiles warning-free.
 */

static inline const char *testutil_text(const char *str)
{
    return str == NULL ? "(null)" : str;
}

/*
 * Record one verdict.  The single place where the counters, `test` and `ret`
 * are updated, so the exit-status contract has exactly one implementation.
 */
static inline void testutil_count(int ok)
{
    testutil_asserted++;
    if (!ok)
        testutil_mismatched++;
    test = ok ? 1 : 0;
    ret = testutil_asserted != 0UL && testutil_mismatched == 0UL ? 1 : 0;
}

static inline void testutil_tag(int ok)
{
    printf("%s[%s]%s ", ok ? TESTUTIL_GREEN : TESTUTIL_RED,
           ok ? "PASS" : "FAIL", TESTUTIL_OFF);
}

/*
 * Open a result line: the verdict tag, then -- on a failure only -- the
 * "file:line: " the assertion was written at.  Every worker below starts here,
 * so that rule has one implementation and cannot drift between assertion
 * kinds.
 */
static inline void testutil_tag_at(int ok, const char *file, int line)
{
    testutil_tag(ok);
    if (!ok)
        printf("%s:%d: ", testutil_text(file), line);
}

/*
 * C99 7.19.6.1 defines the %p conversion for an argument of type "void *",
 * a variadic argument gets no implicit conversion, and "const void *" is a
 * different type.  The cast therefore happens here, once, which lets the
 * workers keep "const void *" parameters instead of stripping const from the
 * caller's own data; printf formats the pointer's value and never
 * dereferences it.
 */
static inline void testutil_print_ptr(const void *ptr)
{
    printf("%p", (void *)ptr);
}

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
 * The assertion workers.  Each records the verdict, prints one self-diagnosing
 * line -- source location, label, actual value and expected value -- and
 * returns the verdict, so an assertion may also be used in an expression.
 * `file` and `line` are always the caller's own, supplied by the TEST_ASSERT_
 * macros at the foot of this file and used for nothing but the failure line;
 * a null `file` degrades to "(null)".
 */

static inline int testutil_check_bool(const char *file, int line,
                                      const char *expr, int ok)
{
    testutil_count(ok);
    testutil_tag_at(ok, file, line);
    printf("%s\n", testutil_text(expr));
    return ok;
}

static inline int testutil_check_int(const char *file, int line,
                                     const char *label, intmax_t actual,
                                     intmax_t expected)
{
    int ok = actual == expected;

    testutil_count(ok);
    testutil_tag_at(ok, file, line);
    if (ok)
        printf("%s: %" PRIdMAX "\n", testutil_text(label), actual);
    else
        printf("%s: actual %" PRIdMAX ", expected %" PRIdMAX "\n",
               testutil_text(label), actual, expected);
    return ok;
}

/*
 * Unsigned comparison at maximum width.  Values such as UINT32_MAX travel
 * through as themselves, with no sign extension, because the macro casts to
 * uintmax_t before the call.
 */
static inline int testutil_check_uint(const char *file, int line,
                                      const char *label, uintmax_t actual,
                                      uintmax_t expected)
{
    int ok = actual == expected;

    testutil_count(ok);
    testutil_tag_at(ok, file, line);
    if (ok)
        printf("%s: %" PRIuMAX "\n", testutil_text(label), actual);
    else
        printf("%s: actual %" PRIuMAX ", expected %" PRIuMAX "\n",
               testutil_text(label), actual, expected);
    return ok;
}

/*
 * size_t has its own worker and its own "%zu" conversion on purpose: "%lu" is
 * wrong wherever size_t is not unsigned long, and a cast down to some other
 * width could silently hide a mismatch.
 */
static inline int testutil_check_size(const char *file, int line,
                                      const char *label, size_t actual,
                                      size_t expected)
{
    int ok = actual == expected;

    testutil_count(ok);
    testutil_tag_at(ok, file, line);
    if (ok)
        printf("%s: %zu\n", testutil_text(label), actual);
    else
        printf("%s: actual %zu, expected %zu\n", testutil_text(label),
               actual, expected);
    return ok;
}

/*
 * Pointer IDENTITY, which is a different claim from value equality and is the
 * right one wherever a contract says a pointer is passed through rather than
 * copied.
 */
static inline int testutil_check_ptr_eq(const char *file, int line,
                                        const char *label, const void *actual,
                                        const void *expected)
{
    int ok = actual == expected;

    testutil_count(ok);
    testutil_tag_at(ok, file, line);
    printf("%s: ", testutil_text(label));
    if (ok) {
        testutil_print_ptr(actual);
    } else {
        printf("actual ");
        testutil_print_ptr(actual);
        printf(", expected ");
        testutil_print_ptr(expected);
    }
    printf("\n");
    return ok;
}

static inline int testutil_check_ptr_ne(const char *file, int line,
                                        const char *label, const void *actual,
                                        const void *other)
{
    int ok = actual != other;

    testutil_count(ok);
    testutil_tag_at(ok, file, line);
    printf("%s: ", testutil_text(label));
    if (ok) {
        testutil_print_ptr(actual);
        printf(", distinct from ");
        testutil_print_ptr(other);
    } else {
        printf("actual ");
        testutil_print_ptr(actual);
        printf(", expected any pointer other than ");
        testutil_print_ptr(other);
    }
    printf("\n");
    return ok;
}

static inline int testutil_check_ptr_null(const char *file, int line,
                                          const char *label,
                                          const void *actual)
{
    int ok = actual == NULL;

    testutil_count(ok);
    testutil_tag_at(ok, file, line);
    printf("%s: ", testutil_text(label));
    if (ok) {
        printf("(null)");
    } else {
        printf("actual ");
        testutil_print_ptr(actual);
        printf(", expected (null)");
    }
    printf("\n");
    return ok;
}

static inline int testutil_check_ptr_not_null(const char *file, int line,
                                              const char *label,
                                              const void *actual)
{
    int ok = actual != NULL;

    testutil_count(ok);
    testutil_tag_at(ok, file, line);
    printf("%s: ", testutil_text(label));
    if (ok)
        testutil_print_ptr(actual);
    else
        printf("actual (null), expected a non-null pointer");
    printf("\n");
    return ok;
}

/*
 * Null-safe on both sides: two null pointers compare equal, one null pointer
 * never matches a string, and neither case reaches strcmp().
 */
static inline int testutil_check_str_eq(const char *file, int line,
                                        const char *label, const char *actual,
                                        const char *expected)
{
    int ok;

    if (actual == NULL || expected == NULL)
        ok = actual == expected;
    else
        ok = strcmp(actual, expected) == 0;

    testutil_count(ok);
    testutil_tag_at(ok, file, line);
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
 * Byte-level comparison with a readable hex diff.  Two deliberate choices:
 *
 *   - A null buffer with a non-zero length is reported as a mismatch, never
 *     passed to memcmp(), so a fixture bug produces a diagnosis rather than a
 *     segmentation fault in the harness.
 *
 *   - A zero-length comparison FAILS.  It is the one call here that inspects
 *     neither operand, so counting it as a pass would let a binary whose only
 *     assertion compared no bytes exit zero having proved nothing.  A
 *     zero-capacity destination is still a real fixture; what it asserts is
 *     the return code, the return_size and -- where a buffer exists at all --
 *     that its bytes still hold the sentinel they were seeded with.
 */
static inline int testutil_check_mem_eq(const char *file, int line,
                                        const char *label, const void *actual,
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
        testutil_count(0);
        testutil_tag_at(0, file, line);
        printf("%s: a comparison of 0 bytes inspects neither buffer and is"
               " therefore not an assertion; assert the return code, the"
               " return_size and the sentinel contents instead\n",
               testutil_text(label));
        return 0;
    }

    if (pact == NULL || pexp == NULL) {
        testutil_count(0);
        testutil_tag_at(0, file, line);
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
    testutil_tag_at(ok, file, line);
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
 * Where the exit-status contract is cashed in: the returned status is a
 * function of the counters and of nothing else.  It takes `file` and `line`
 * for the reason the workers do -- the zero-assertion verdict is a failure,
 * and here the location is the TEST_REPORT() call site at the end of main().
 */
static inline int testutil_report(const char *file, int line, const char *name)
{
    int failed = testutil_mismatched != 0UL || testutil_asserted == 0UL;

    if (testutil_asserted == 0UL) {
        testutil_tag_at(0, file, line);
        printf("%s: no assertions executed -- a test that asserts nothing"
               " cannot pass\n", testutil_text(name));
    }

    printf("%s%s: %lu assertions, %lu mismatches%s\n",
           failed ? TESTUTIL_RED : TESTUTIL_GREEN, testutil_text(name),
           testutil_asserted, testutil_mismatched, TESTUTIL_OFF);
    fflush(stdout);
    return failed ? 1 : 0;
}

/*
 * The public interface.  Each macro expands to exactly one function call, so
 * every argument is evaluated exactly once and none needs a
 * do { ... } while (0) wrapper to behave as either a statement or an
 * expression.
 */

/*
 * Records the truth of `e` in `test` and prints the stringified expression.
 * Also the universal escape hatch -- any claim at all can be phrased as
 * TEST_ASSERT(claim) -- but prefer a typed macro below when there is one,
 * because those print the actual and the expected value and this one can only
 * print the source text.
 */
#define TEST_ASSERT(e)                                                      \
    (test = testutil_check_bool(__FILE__, __LINE__, #e, (e) ? 1 : 0))

#define TEST_ASSERT_INT_EQ(label, actual, expected)                         \
    (test = testutil_check_int(__FILE__, __LINE__, (label),                 \
                               (intmax_t)(actual), (intmax_t)(expected)))

#define TEST_ASSERT_UINT_EQ(label, actual, expected)                        \
    (test = testutil_check_uint(__FILE__, __LINE__, (label),                \
                                (uintmax_t)(actual),                        \
                                (uintmax_t)(expected)))

#define TEST_ASSERT_SIZE_EQ(label, actual, expected)                        \
    (test = testutil_check_size(__FILE__, __LINE__, (label),                \
                                (size_t)(actual), (size_t)(expected)))

#define TEST_ASSERT_PTR_EQ(label, actual, expected)                         \
    (test = testutil_check_ptr_eq(__FILE__, __LINE__, (label),              \
                                  (const void *)(actual),                   \
                                  (const void *)(expected)))

#define TEST_ASSERT_PTR_NE(label, actual, other)                            \
    (test = testutil_check_ptr_ne(__FILE__, __LINE__, (label),              \
                                  (const void *)(actual),                   \
                                  (const void *)(other)))

#define TEST_ASSERT_PTR_NULL(label, actual)                                 \
    (test = testutil_check_ptr_null(__FILE__, __LINE__, (label),            \
                                    (const void *)(actual)))

#define TEST_ASSERT_PTR_NOT_NULL(label, actual)                             \
    (test = testutil_check_ptr_not_null(__FILE__, __LINE__, (label),        \
                                        (const void *)(actual)))

#define TEST_ASSERT_STR_EQ(label, actual, expected)                         \
    (test = testutil_check_str_eq(__FILE__, __LINE__, (label),              \
                                  (actual), (expected)))

/*
 * Byte-for-byte buffer equality, with a hex diff on mismatch.  A `len` of
 * zero is a FAILURE and not a vacuous pass: testutil_check_mem_eq() says why
 * and what a zero-capacity case should assert instead.
 */
#define TEST_ASSERT_MEM_EQ(label, actual, expected, len)                    \
    (test = testutil_check_mem_eq(__FILE__, __LINE__, (label),              \
                                  (const void *)(actual),                   \
                                  (const void *)(expected),                 \
                                  (size_t)(len)))

#define TEST_REPORT(name)                                                   \
    testutil_report(__FILE__, __LINE__, (name))

#endif                          /* LIBPROV_TESTS_TESTUTIL_H */
