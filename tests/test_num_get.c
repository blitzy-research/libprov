/* CC0 license applied, see LICENSE */

/*
 * Contract, boundary and error-precedence tests for provnum_get_size_t() and
 * provnum_get_int(), the two conversions num.c generates from
 * implement_provnum() at num.c:185 and num.c:186.  Every case here asserts a
 * SPECIFIC value -- an exact return code, an exact destination value, or an
 * exact byte-level side effect -- because a test that only observes the
 * absence of a crash proves nothing about a conversion helper.  A plausible
 * single-edit bug in num.c is meant to break at least one line below.
 *
 * NO USER-SPECIFIED RULES EXIST FOR THIS PROJECT.  review_rules reports "No
 * user rules provided", so this file is held to enterprise-standard best
 * practice and to the constraints carried in the task itself: do not modify a
 * non-test source, do not weaken an existing assertion, no smoke tests, and
 * where the intended behaviour is genuinely ambiguous say so in a comment
 * rather than asserting whatever the code happens to emit.
 *
 * ---------------------------------------------------------------------------
 * SUCCESS IS EXACTLY 1, AND ONLY num.c SAYS SO
 * ---------------------------------------------------------------------------
 * num.c:61 initialises `struct resultdesc result = { dest.size, 1, };`, so
 * every successful conversion returns 1.  include/prov/num.h defines the four
 * failure codes and never states the success value, so a caller testing
 * "> 0" and a caller testing "== 1" would both compile today.  Every success
 * below is therefore asserted as the literal 1.  Never >= 0, never != 0,
 * never > 0: those would accept a whole class of mutation, and pinning the
 * value is the only way this suite can notice if num.c:61 ever changes.
 *
 * ---------------------------------------------------------------------------
 * THE GUARD CHAIN, IN THE ORDER provnum_copy() EVALUATES IT
 * ---------------------------------------------------------------------------
 * Line numbers are for num.c AS IT STANDS, after the three memory-safety
 * repairs; the numbering the project's own planning documents use, from
 * before those repairs, is given in parentheses so either can be followed.
 *
 *     wrong-type rejection        num.c:63-67    (54-58)
 *     empty-source shortcut       num.c:69-73    (60-64)   returns SUCCESS
 *     null-data rejection         num.c:75-78    (66-69)
 *     padding-strip loop          num.c:101-106  (86-91)
 *     oversize rejection          num.c:108-111  (93-96)
 *     null-destination rejection  num.c:115-118  (100-103)
 *     simple-case copy            num.c:120-147  (106-125)
 *     unsupported fallthrough     num.c:150      (128)
 *
 * SEVERAL OF THOSE GUARDS ARE MUTUALLY SATISFIABLE, so an input can satisfy
 * two at once and the answer is then decided by nothing but evaluation order.
 * test_get_precedence() exists for exactly those inputs.  It is the part of
 * this file that survives a refactoring mutation: reordering the guard block
 * changes no line's reachability, so coverage cannot see it, yet it silently
 * changes what the API answers.
 *
 * Also relevant, and cited where used:
 *
 *     paramsign()                 num.c:16-35    (16-26)
 *       its null/zero-size guard  num.c:24-25    (none: this is the repair)
 *       unsigned short-circuit    num.c:30-31    (21)
 *       the source dereference    num.c:32       (23)
 *     padding offset (padstart)   num.c:134      (112)
 *
 * ---------------------------------------------------------------------------
 * *** USE OSSL_PARAM_INTEGER FOR EVERY NULL-DATA AND ZERO-SIZE FIXTURE ***
 * ---------------------------------------------------------------------------
 * THIS IS THE SINGLE MOST IMPORTANT CONSTRAINT IN THIS FILE.  Do not "tidy"
 * the fixtures in test_get_null_and_empty() to OSSL_PARAM_UNSIGNED_INTEGER.
 *
 * paramsign() is called from the argument list at num.c:163, so it runs
 * BEFORE provnum_copy() validates anything.  At num.c:30-31 it returns
 * POSITIVE immediately when the data type is OSSL_PARAM_UNSIGNED_INTEGER, and
 * only otherwise reaches the source dereference at num.c:32.  A null-data
 * fixture typed OSSL_PARAM_UNSIGNED_INTEGER therefore never drives execution
 * as far as that dereference: it is STRUCTURALLY INCAPABLE of detecting a
 * missing null check, however correct its expected return code looks.
 *
 * That is measured, not theorised.  Deleting the guard at num.c:24-25 leaves
 * an unsigned-typed null-data test PASSING, while the same assertions written
 * with OSSL_PARAM_INTEGER fail immediately -- the process dies of SIGSEGV,
 * which CTest reports as a failure.  Both spellings are kept below, the
 * signed one first and labelled, because only one of them can see the bug.
 *
 * ---------------------------------------------------------------------------
 * CALL, STORE, THEN ASSERT
 * ---------------------------------------------------------------------------
 * C does not specify the order in which function-call arguments are
 * evaluated, so reading a destination inside the same expression that calls
 * the function writing it is a bug and not a matter of taste; during
 * investigation such an expression twice reported a destination of 0 for a
 * conversion that had in fact succeeded.  call_get_size_t() and
 * call_get_int() below make the discipline structural: each performs the call
 * first, then captures the destination, the parameter's return_size and
 * whether the parameter's representation survived, and returns all of it in a
 * struct.  Nothing in this file asserts anything but an already-captured
 * value.
 *
 * ---------------------------------------------------------------------------
 * WHAT EVERY CASE ASSERTS, AND WHAT NO CASE ASSERTS
 * ---------------------------------------------------------------------------
 * Success cases assert the return code AND the exact destination value.
 * Error cases assert the return code AND that the destination still holds the
 * sentinel it was seeded with, since "the output was not modified" is a real
 * part of the contract and is otherwise untested.  Every case, success or
 * failure, asserts that the const OSSL_PARAM is byte-identical across the
 * call: the type system forbids the getters writing to it, and this checks
 * the claim underneath, where a cast could have discarded the qualifier.
 *
 * Boundary values are DERIVED from sizeof(T) and CHAR_BIT through
 * param_util.h, never transcribed, so the fixtures describe the contract
 * rather than this host's ABI; four assertions tie the derivations to
 * SIZE_MAX, SIZE_MAX / 2, INT_MAX and INT_MIN so a derivation bug cannot make
 * a case vacuous.  Byte layout likewise comes from param_util.h, which
 * reproduces num.c's nativeendian() rather than assuming an order, so every
 * expectation holds on either endianness.  Boundaries come in PAIRS -- the
 * largest value that fits and the smallest that does not -- so an off-by-one
 * in either direction fails.
 *
 * Exactly one behaviour is deliberately NOT asserted, and it is marked
 * "CLASS C" in test_get_edge_cases().  It is not a gap, and it must not be
 * "completed" by asserting the value the code currently emits.
 *
 * provnum_get_size_t() and provnum_get_int() dereference their `param`
 * argument unconditionally at num.c:162-163, so passing a null OSSL_PARAM *
 * is undefined behaviour rather than a documented error.  There is no fixture
 * for it: undefined behaviour is not a result a test may legitimately assert.
 *
 * ---------------------------------------------------------------------------
 * NO LIBCRYPTO, NO PROVIDER, NO FILES
 * ---------------------------------------------------------------------------
 * OSSL_PARAM is a plain public struct, so every fixture here is built by hand
 * over test-owned automatic storage through param_util.h.  <openssl/params.h>
 * is never included: its OSSL_PARAM_get_*, OSSL_PARAM_set_* and
 * OSSL_PARAM_construct_* families are libcrypto functions, they are precisely
 * what libprov's provnum_ family replaces, and calling them would both add
 * the dependency the task forbids and measure upstream OpenSSL instead of
 * this library.  Nothing here allocates, forks, reads the environment or
 * touches a file, every fixture is an automatic object, and no case depends
 * on another, so this program is safe under `ctest -j N`.
 *
 * ---------------------------------------------------------------------------
 * TWO DIAGNOSTICS THAT ARE NOT DEFECTS
 * ---------------------------------------------------------------------------
 * This file is clean at -std=c99 -Wall -Wextra -Wpedantic and at -std=gnu99,
 * and clean under -fsanitize=address,undefined.  Two warnings do appear if
 * further options are added, and neither should be "fixed":
 *
 *   -Wshadow      every group declares the project's own "int ret = 1, test;",
 *                 which shadows the tentative definitions testutil.h provides
 *                 at file scope.  That is the idiom testutil.h documents and
 *                 exists to support, and the macros deliberately assign to the
 *                 `test` visible at the call site, so the shadowing is the
 *                 mechanism rather than an accident.  cppcheck reports the
 *                 same thing as `style: shadowVariable`, and it is the ONLY
 *                 finding cppcheck reports for this file.
 *   -Wredundant-  include/prov/num.h carries no include guard and arrives both
 *    decls        directly and through param_util.h, so its four prototypes
 *                 are seen twice.  Repeating a function declaration is valid
 *                 C, the header is a non-test source this file may not
 *                 modify, and including the header under test directly is the
 *                 whole point of a test for that header's contract.
 */

#include "testutil.h"
#include "param_util.h"
#include "prov/num.h"

#include <limits.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
 * EVERY FIXTURE GETS ITS OWN BUFFER, SIZED EXACTLY TO THE CASE.  Each case
 * below is a block declaring `unsigned char src[<width>];` with the width
 * written as a constant expression over sizeof(size_t) or sizeof(int), never
 * as a number.  Two reasons, and the first is why one shared buffer would be
 * a mistake: a read or write one byte outside an exactly-sized automatic
 * object lands outside a DISTINCT object, where AddressSanitizer sees it,
 * whereas the same access inside a larger shared buffer is invisible -- and
 * out-of-bounds access on these very inputs is what num.c's memory-safety
 * repairs removed, so hiding it is the one thing these fixtures must not do.
 * Second, a per-case block keeps each case independent, which is what makes
 * the order they run in irrelevant.
 */

/*
 * Everything one provnum_get_size_t() call reveals, captured in the order the
 * call makes it available and asserted only afterwards.  `param_unchanged`
 * carries param_identical()'s verdict against a snapshot taken before the
 * call, and `return_size` is captured because the getters must NOT write it:
 * only the provnum_set_ half of implement_provnum() assigns return_size, at
 * num.c:181.
 */
struct size_t_result {
    int rc;
    size_t value;
    size_t return_size;
    int param_unchanged;
};

/* The same for provnum_get_int(), whose destination is a signed int. */
struct int_result {
    int rc;
    int value;
    size_t return_size;
    int param_unchanged;
};

/*
 * Call provnum_get_size_t() and capture everything about the outcome.  The
 * order of the five statements below is the contract of this helper: snapshot,
 * CALL, read the destination, read return_size, compare the snapshot.  A
 * caller asserting on the returned struct cannot accidentally read a
 * destination in the same expression that filled it.
 *
 * A null `dest` is a legitimate fixture -- provnum_get_size_t(NULL, &param)
 * exercises the null-destination guard at num.c:115-118 and the empty-source
 * shortcut that precedes it -- so `value` is reported as 0 in that case and
 * such cases assert the return code instead.  There is nothing else to read:
 * a destination that does not exist cannot be shown to be unmodified.
 */
static struct size_t_result call_get_size_t(size_t *dest,
                                            const OSSL_PARAM *param)
{
    OSSL_PARAM snapshot;
    struct size_t_result out;

    param_snapshot(&snapshot, param);
    out.rc = provnum_get_size_t(dest, param);
    out.value = dest == NULL ? (size_t)0 : *dest;
    out.return_size = param->return_size;
    out.param_unchanged = param_identical(param, &snapshot);

    return out;
}

/* provnum_get_int()'s counterpart, identical in discipline. */
static struct int_result call_get_int(int *dest, const OSSL_PARAM *param)
{
    OSSL_PARAM snapshot;
    struct int_result out;

    param_snapshot(&snapshot, param);
    out.rc = provnum_get_int(dest, param);
    out.value = dest == NULL ? 0 : *dest;
    out.return_size = param->return_size;
    out.param_unchanged = param_identical(param, &snapshot);

    return out;
}

/*
 * ---------------------------------------------------------------------------
 * How the labels below read, so a failing CTest line identifies its fixture
 * without a reader coming back to this file:
 *
 *     U[n]      an OSSL_PARAM_UNSIGNED_INTEGER source of n bytes
 *     I[n]      an OSSL_PARAM_INTEGER source of n bytes
 *     SZ, IN    sizeof(size_t) and sizeof(int)
 *     =AA BB    the source's bytes, MOST SIGNIFICANT FIRST, whatever this
 *               host's byte order; ".." continues the preceding byte
 *
 * and each fixture contributes up to four assertions, suffixed "fixture" (the
 * builders reported the fixture was well formed), "rc" (the return code),
 * "value" (the destination) and "param" (the const OSSL_PARAM survived the
 * call byte for byte).  Error cases replace "value" with "untouched".
 * ---------------------------------------------------------------------------
 */

/*
 * ===========================================================================
 * provnum_get_size_t() -- success paths
 * ===========================================================================
 */
static int test_get_size_t_happy(void)
{
    int ret = 1, test;

    /*
     * The two derived size_t edges every boundary case below is built from,
     * tied here to the standard macros.  param_max_unsigned_in() and
     * param_max_signed_in() compute from a width and CHAR_BIT, so a mistake
     * in the derivation would quietly turn a boundary case into a tautology;
     * these two assertions make it a reported failure instead.
     */
    TEST_ASSERT_SIZE_EQ("derivation: every bit of a size_t",
                        (size_t)param_max_unsigned_in(sizeof(size_t)),
                        SIZE_MAX);
    ret &= test;
    TEST_ASSERT_SIZE_EQ("derivation: a size_t with its top bit clear",
                        (size_t)param_max_signed_in(sizeof(size_t)),
                        SIZE_MAX / 2);
    ret &= test;

    {
        /*
         * One byte holding 5, the narrowest source there is, and a D3
         * REGRESSION GUARD: src.size < dest.size, so the padding branch at
         * num.c:126-138 runs.  With the pre-repair offset at num.c:134
         * (dest.size - src.size instead of src.size) the significant byte
         * went to dest[0] while the padding started at dest[SZ - 1], leaving
         * the seeded sentinel in between -- measured as 0x00AAAAAAAAAAAA05
         * rather than 5.  A wrong offset is therefore a wrong VALUE here, not
         * merely an out-of-bounds write.
         */
        unsigned char src[1];
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;
        int ok;

        ok = param_put_host_order(src, sizeof src, (uintmax_t)5);
        param_build_unsigned(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("U[1]=05 fixture", ok, 1); ret &= test;

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("U[1]=05 rc", got.rc, 1); ret &= test;
        TEST_ASSERT_SIZE_EQ("U[1]=05 value", got.value, (size_t)5);
        ret &= test;
        TEST_ASSERT_INT_EQ("U[1]=05 param", got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * Two bytes, every bit set: still narrower than the destination, so
         * this is the second D3 regression guard -- measured as
         * 0x0000AAAAAAAAFFFF before the repair, where the contract is 65535.
         */
        unsigned char src[2];
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;
        int ok;

        ok = param_fill(src, sizeof src, (unsigned char)0xFFU);
        param_build_unsigned(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("U[2]=FF FF fixture", ok, 1); ret &= test;

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("U[2]=FF FF rc", got.rc, 1); ret &= test;
        TEST_ASSERT_SIZE_EQ("U[2]=FF FF value", got.value,
                            (size_t)param_max_unsigned_in(2));
        ret &= test;
        TEST_ASSERT_INT_EQ("U[2]=FF FF param", got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * A source exactly as wide as the destination, every bit set: the
         * largest value a size_t can hold, and the case where src.size ==
         * dest.size so no padding is written at all and the strip loop at
         * num.c:101-106 runs zero times.
         */
        unsigned char src[sizeof(size_t)];
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;
        int ok;

        ok = param_fill(src, sizeof src, (unsigned char)0xFFU);
        param_build_unsigned(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("U[SZ]=FF.. fixture", ok, 1); ret &= test;

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("U[SZ]=FF.. rc", got.rc, 1); ret &= test;
        TEST_ASSERT_SIZE_EQ("U[SZ]=FF.. value", got.value, SIZE_MAX);
        ret &= test;
        TEST_ASSERT_INT_EQ("U[SZ]=FF.. param", got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * One byte WIDER than the destination, and legitimately so: the most
         * significant byte is 0x00, which equals the positive padding value,
         * and the next byte's high bit is clear, so both of the padding rules
         * num.c:90-93 documents are satisfied and the strip loop at
         * num.c:101-106 discards exactly one byte.  What is left is a size_t
         * with its top bit clear, so the conversion succeeds.
         */
        unsigned char src[sizeof(size_t) + 1];
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;
        int ok;

        ok = param_expect_pattern(src, sizeof src,
                                  param_max_signed_in(sizeof(size_t)),
                                  sizeof(size_t), (unsigned char)0x00U);
        param_build_unsigned(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("U[SZ+1]=00 7F FF.. fixture", ok, 1); ret &= test;

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("U[SZ+1]=00 7F FF.. rc", got.rc, 1); ret &= test;
        TEST_ASSERT_SIZE_EQ("U[SZ+1]=00 7F FF.. value", got.value,
                            SIZE_MAX / 2);
        ret &= test;
        TEST_ASSERT_INT_EQ("U[SZ+1]=00 7F FF.. param", got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * A getter must not write the parameter's return_size.  Only the
         * provnum_set_ half of implement_provnum() assigns it, at num.c:181;
         * param_build() leaves it 0, so a getter that acquired that
         * assignment -- the obvious result of unifying the two halves -- would
         * be caught here rather than by a downstream caller's buffer sizing.
         */
        unsigned char src[1];
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;
        int ok;

        ok = param_put_host_order(src, sizeof src, (uintmax_t)5);
        param_build_unsigned(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("U[1]=05 return_size fixture", ok, 1); ret &= test;

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("U[1]=05 return_size rc", got.rc, 1); ret &= test;
        TEST_ASSERT_SIZE_EQ("U[1]=05 return_size untouched", got.return_size,
                            (size_t)0);
        ret &= test;
    }

    return ret;
}

/*
 * ===========================================================================
 * provnum_get_int() -- success paths, including sign extension
 * ===========================================================================
 */
static int test_get_int_happy(void)
{
    int ret = 1, test;

    /*
     * The derived int edges, tied to <limits.h> exactly as the size_t ones
     * are above.  The second assertion also states this file's one
     * representational premise: that the bit pattern one past the largest
     * positive value denotes INT_MIN, which is two's complement.  num.c
     * presupposes it too -- num.c:90-91 calls sign_t "the 2's complement
     * padding value" -- so a host where this failed would be a host where the
     * library's own padding rules do not hold, and the failure names the
     * premise rather than hiding it.
     */
    TEST_ASSERT_INT_EQ("derivation: largest positive int",
                       (intmax_t)param_max_signed_in(sizeof(int)), INT_MAX);
    ret &= test;
    TEST_ASSERT_INT_EQ("derivation: most negative int",
                       -(intmax_t)param_max_signed_in(sizeof(int)) - 1,
                       INT_MIN);
    ret &= test;

    {
        /*
         * One byte, every bit set, read as a signed source: paramsign()
         * reaches its dereference at num.c:32, finds the high bit set and
         * answers NEGATIVE, so the padding at num.c:136 fills the remaining
         * bytes with 0xFF and -1 comes out sign extended.
         *
         * THE PRIMARY D3 REGRESSION GUARD.  Before the repair this returned
         * -16776961 (0xFF0000FF): the significant byte landed at dest[0] and
         * the sign padding began at dest[IN - 1], so the two bytes between
         * them kept whatever the destination had held.  A single wrong offset
         * turned an ordinary one-byte conversion into a wrong number.
         */
        unsigned char src[1];
        OSSL_PARAM param;
        int dest = param_sentinel_int();
        struct int_result got;
        int ok;

        ok = param_fill(src, sizeof src, (unsigned char)0xFFU);
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("I[1]=FF fixture", ok, 1); ret &= test;

        got = call_get_int(&dest, &param);
        TEST_ASSERT_INT_EQ("I[1]=FF rc", got.rc, 1); ret &= test;
        TEST_ASSERT_INT_EQ("I[1]=FF value", got.value, -1); ret &= test;
        TEST_ASSERT_INT_EQ("I[1]=FF param", got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * Two bytes holding the most negative two-byte value, 0x80 0x00.  The
         * expectation is derived: one past the largest two-byte positive
         * value, negated.  Narrower than the destination, so this is another
         * padding-offset guard.
         */
        unsigned char src[2];
        OSSL_PARAM param;
        int dest = param_sentinel_int();
        struct int_result got;
        int ok;

        ok = param_put_host_order(src, sizeof src,
                                  param_max_signed_in(2) + (uintmax_t)1);
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("I[2]=80 00 fixture", ok, 1); ret &= test;

        got = call_get_int(&dest, &param);
        TEST_ASSERT_INT_EQ("I[2]=80 00 rc", got.rc, 1); ret &= test;
        TEST_ASSERT_INT_EQ("I[2]=80 00 value", got.value,
                           -(intmax_t)param_max_signed_in(2) - 1);
        ret &= test;
        TEST_ASSERT_INT_EQ("I[2]=80 00 param", got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * Three bytes -- a width no integer type has -- holding -2 in two's
         * complement.  Sign extension has to fill the remaining byte for the
         * result to be -2, so this case fails both if the padding is written
         * at the wrong offset (measured pre-repair as -2130706434) and if it
         * is written with the wrong fill byte.
         */
        unsigned char src[3];
        OSSL_PARAM param;
        int dest = param_sentinel_int();
        struct int_result got;
        int ok;

        ok = param_put_host_order(src, sizeof src,
                                  param_max_unsigned_in(3) - (uintmax_t)1);
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("I[3]=FF FF FE fixture", ok, 1); ret &= test;

        got = call_get_int(&dest, &param);
        TEST_ASSERT_INT_EQ("I[3]=FF FF FE rc", got.rc, 1); ret &= test;
        TEST_ASSERT_INT_EQ("I[3]=FF FF FE value", got.value, -2); ret &= test;
        TEST_ASSERT_INT_EQ("I[3]=FF FF FE param", got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * Five bytes past the destination's width, every bit set: -1 written
         * with the maximum possible redundancy.  Both padding rules hold at
         * every step, so the strip loop at num.c:101-106 runs until src.size
         * reaches dest.size exactly -- five iterations here -- and the copy
         * then needs no padding at all.
         *
         * This case is a FULL-STRIP assertion and deliberately not labelled a
         * D3 guard: because it strips to exactly sizeof(int), src.size ==
         * dest.size and the padding branch at num.c:126-138 never runs, so it
         * measured -1 both before and after the repair.  The narrow-source
         * cases above are what catch a wrong padding offset.
         */
        unsigned char src[sizeof(int) + 5];
        OSSL_PARAM param;
        int dest = param_sentinel_int();
        struct int_result got;
        int ok;

        ok = param_fill(src, sizeof src, (unsigned char)0xFFU);
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("I[IN+5]=FF.. fixture", ok, 1); ret &= test;

        got = call_get_int(&dest, &param);
        TEST_ASSERT_INT_EQ("I[IN+5]=FF.. rc", got.rc, 1); ret &= test;
        TEST_ASSERT_INT_EQ("I[IN+5]=FF.. value", got.value, -1); ret &= test;
        TEST_ASSERT_INT_EQ("I[IN+5]=FF.. param", got.param_unchanged, 1);
        ret &= test;
    }

    {
        /* The largest positive value, at the destination's natural width. */
        unsigned char src[sizeof(int)];
        OSSL_PARAM param;
        int dest = param_sentinel_int();
        struct int_result got;
        int ok;

        ok = param_put_host_order(src, sizeof src,
                                  param_max_signed_in(sizeof(int)));
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("I[IN]=INT_MAX fixture", ok, 1); ret &= test;

        got = call_get_int(&dest, &param);
        TEST_ASSERT_INT_EQ("I[IN]=INT_MAX rc", got.rc, 1); ret &= test;
        TEST_ASSERT_INT_EQ("I[IN]=INT_MAX value", got.value, INT_MAX);
        ret &= test;
        TEST_ASSERT_INT_EQ("I[IN]=INT_MAX param", got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * The most negative value, at the destination's natural width: the
         * pattern one past the largest positive value, which is where the
         * sign bit is set and every value bit clear.
         */
        unsigned char src[sizeof(int)];
        OSSL_PARAM param;
        int dest = param_sentinel_int();
        struct int_result got;
        int ok;

        ok = param_put_host_order(src, sizeof src,
                                  param_max_signed_in(sizeof(int))
                                  + (uintmax_t)1);
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("I[IN]=INT_MIN fixture", ok, 1); ret &= test;

        got = call_get_int(&dest, &param);
        TEST_ASSERT_INT_EQ("I[IN]=INT_MIN rc", got.rc, 1); ret &= test;
        TEST_ASSERT_INT_EQ("I[IN]=INT_MIN value", got.value, INT_MIN);
        ret &= test;
        TEST_ASSERT_INT_EQ("I[IN]=INT_MIN param", got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * An UNSIGNED source into the signed destination, which is the other
         * half of the type matrix and takes a different route through
         * num.c:121-124: paramsign() short-circuits to POSITIVE at
         * num.c:30-31, so the padding is written with 0x00 rather than 0xFF
         * and the simple-case condition is satisfied by its second disjunct
         * instead of its first.
         */
        unsigned char src[1];
        OSSL_PARAM param;
        int dest = param_sentinel_int();
        struct int_result got;
        int ok;

        ok = param_put_host_order(src, sizeof src, (uintmax_t)5);
        param_build_unsigned(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("U[1]=05->int fixture", ok, 1); ret &= test;

        got = call_get_int(&dest, &param);
        TEST_ASSERT_INT_EQ("U[1]=05->int rc", got.rc, 1); ret &= test;
        TEST_ASSERT_INT_EQ("U[1]=05->int value", got.value, 5); ret &= test;
        TEST_ASSERT_INT_EQ("U[1]=05->int param", got.param_unchanged, 1);
        ret &= test;
    }

    return ret;
}

/*
 * ===========================================================================
 * Width and signedness boundaries, asserted in PAIRS
 * ===========================================================================
 * Every pair below is "the largest value that fits" beside "the smallest that
 * does not", at the same width and differing in as little as one bit, so an
 * off-by-one in EITHER direction fails: a guard that accepted one value too
 * many breaks the second half, and one that rejected one too few breaks the
 * first.  A lone edge case cannot do that, which is why they come in twos.
 *
 * Every value is derived from sizeof(T) and CHAR_BIT through param_util.h.
 * Not one is transcribed: a suite spelling 127, 32767 or 2147483647 as
 * literals asserts this host's ABI rather than the library's contract.
 */
static int test_get_boundaries(void)
{
    int ret = 1, test;

    {
        /*
         * PAIR 1a -- the largest value a size_t destination can hold, at its
         * own width.  The strip loop cannot run (src.size == dest.size) and
         * the oversize test at num.c:108 must not fire on equality, which is
         * the mutation this half of the pair catches: a `>=` there rejects
         * every exact-width source.
         */
        unsigned char src[sizeof(size_t)];
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;
        int ok;

        ok = param_fill(src, sizeof src, (unsigned char)0xFFU);
        param_build_unsigned(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("fits: U[SZ]=FF.. fixture", ok, 1); ret &= test;

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("fits: U[SZ]=FF.. rc", got.rc, 1); ret &= test;
        TEST_ASSERT_SIZE_EQ("fits: U[SZ]=FF.. value", got.value, SIZE_MAX);
        ret &= test;
        TEST_ASSERT_INT_EQ("fits: U[SZ]=FF.. param", got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * PAIR 1b -- the smallest value that does NOT fit, which is SIZE_MAX
         * + 1: a one in the byte just past the destination's width and zeros
         * below it.  The first padding rule at num.c:103 fails at once, since
         * 0x01 is not the positive pad byte, so the loop breaks at full width
         * and num.c:108-111 answers PROVNUM_E_TOOBIG.
         */
        unsigned char src[sizeof(size_t) + 1];
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;
        int ok;

        ok = param_expect_pattern(src, sizeof src, (uintmax_t)0,
                                  sizeof(size_t), (unsigned char)0x01U);
        param_build_unsigned(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("over: U[SZ+1]=01 00.. fixture", ok, 1);
        ret &= test;

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("over: U[SZ+1]=01 00.. rc", got.rc,
                           PROVNUM_E_TOOBIG);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("over: U[SZ+1]=01 00.. untouched", got.value,
                            param_sentinel_size_t());
        ret &= test;
        TEST_ASSERT_INT_EQ("over: U[SZ+1]=01 00.. param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * PAIR 2a -- INT_MAX carried in one byte more than the destination,
         * with a redundant 0x00 on top.  Both padding rules hold, the extra
         * byte is stripped, and the largest positive int comes through.
         */
        unsigned char src[sizeof(int) + 1];
        OSSL_PARAM param;
        int dest = param_sentinel_int();
        struct int_result got;
        int ok;

        ok = param_expect_pattern(src, sizeof src,
                                  param_max_signed_in(sizeof(int)),
                                  sizeof(int), (unsigned char)0x00U);
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("fits: I[IN+1]=00 7F FF.. fixture", ok, 1);
        ret &= test;

        got = call_get_int(&dest, &param);
        TEST_ASSERT_INT_EQ("fits: I[IN+1]=00 7F FF.. rc", got.rc, 1);
        ret &= test;
        TEST_ASSERT_INT_EQ("fits: I[IN+1]=00 7F FF.. value", got.value,
                           INT_MAX);
        ret &= test;
        TEST_ASSERT_INT_EQ("fits: I[IN+1]=00 7F FF.. param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * PAIR 2b -- INT_MAX + 1, at the same width and differing from PAIR
         * 2a in ONE BIT: the high bit of the byte below the padding.  That
         * bit is exactly what the second padding rule at num.c:104-105
         * inspects, so the strip is refused, the source stays a byte too wide
         * and the answer is PROVNUM_E_TOOBIG.  This half of the pair is what
         * a suite must have to notice a dropped rule (b): without it, the
         * strip would proceed and a positive value would be delivered as a
         * negative int.
         */
        unsigned char src[sizeof(int) + 1];
        OSSL_PARAM param;
        int dest = param_sentinel_int();
        struct int_result got;
        int ok;

        ok = param_expect_pattern(src, sizeof src,
                                  param_max_signed_in(sizeof(int))
                                  + (uintmax_t)1,
                                  sizeof(int), (unsigned char)0x00U);
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("over: I[IN+1]=00 80 00.. fixture", ok, 1);
        ret &= test;

        got = call_get_int(&dest, &param);
        TEST_ASSERT_INT_EQ("over: I[IN+1]=00 80 00.. rc", got.rc,
                           PROVNUM_E_TOOBIG);
        ret &= test;
        TEST_ASSERT_INT_EQ("over: I[IN+1]=00 80 00.. untouched", got.value,
                           param_sentinel_int());
        ret &= test;
        TEST_ASSERT_INT_EQ("over: I[IN+1]=00 80 00.. param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * PAIR 3a -- the negative edge: INT_MIN carried in one byte more than
         * the destination, padded with 0xFF.  Rule (a) holds because 0xFF is
         * the negative pad byte and rule (b) holds because the byte below it
         * has its high bit set, so the redundant byte is stripped and the
         * most negative int survives.
         */
        unsigned char src[sizeof(int) + 1];
        OSSL_PARAM param;
        int dest = param_sentinel_int();
        struct int_result got;
        int ok;

        ok = param_expect_pattern(src, sizeof src,
                                  param_max_signed_in(sizeof(int))
                                  + (uintmax_t)1,
                                  sizeof(int), (unsigned char)0xFFU);
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("fits: I[IN+1]=FF 80 00.. fixture", ok, 1);
        ret &= test;

        got = call_get_int(&dest, &param);
        TEST_ASSERT_INT_EQ("fits: I[IN+1]=FF 80 00.. rc", got.rc, 1);
        ret &= test;
        TEST_ASSERT_INT_EQ("fits: I[IN+1]=FF 80 00.. value", got.value,
                           INT_MIN);
        ret &= test;
        TEST_ASSERT_INT_EQ("fits: I[IN+1]=FF 80 00.. param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * PAIR 3b -- INT_MIN - 1, one bit away from PAIR 3a: the byte below
         * the 0xFF padding now has its high bit CLEAR, which contradicts the
         * negative sign the padding claims, so rule (b) refuses the strip and
         * the value is rejected as too big.  Note that "too big" is the right
         * answer for a value too NEGATIVE as well; num.c has one code for
         * both, and pinning it here is what would catch a mutation that
         * answered PROVNUM_E_UNSUPPORTED instead.
         */
        unsigned char src[sizeof(int) + 1];
        OSSL_PARAM param;
        int dest = param_sentinel_int();
        struct int_result got;
        int ok;

        ok = param_expect_pattern(src, sizeof src,
                                  param_max_signed_in(sizeof(int)),
                                  sizeof(int), (unsigned char)0xFFU);
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("over: I[IN+1]=FF 7F FF.. fixture", ok, 1);
        ret &= test;

        got = call_get_int(&dest, &param);
        TEST_ASSERT_INT_EQ("over: I[IN+1]=FF 7F FF.. rc", got.rc,
                           PROVNUM_E_TOOBIG);
        ret &= test;
        TEST_ASSERT_INT_EQ("over: I[IN+1]=FF 7F FF.. untouched", got.value,
                           param_sentinel_int());
        ret &= test;
        TEST_ASSERT_INT_EQ("over: I[IN+1]=FF 7F FF.. param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * PAIR 4a -- the one-byte sign boundary, positive half: 0x7F is the
         * largest one-byte value whose high bit is clear, so paramsign()
         * answers POSITIVE at num.c:32-34 and the destination is zero padded.
         */
        unsigned char src[1];
        OSSL_PARAM param;
        int dest = param_sentinel_int();
        struct int_result got;
        int ok;

        ok = param_put_host_order(src, sizeof src, param_max_signed_in(1));
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("sign: I[1]=7F fixture", ok, 1); ret &= test;

        got = call_get_int(&dest, &param);
        TEST_ASSERT_INT_EQ("sign: I[1]=7F rc", got.rc, 1); ret &= test;
        TEST_ASSERT_INT_EQ("sign: I[1]=7F value", got.value,
                           (intmax_t)param_max_signed_in(1));
        ret &= test;
        TEST_ASSERT_INT_EQ("sign: I[1]=7F param", got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * PAIR 4b -- the same width, one greater: 0x80 sets the high bit, so
         * the very same bytes now denote a negative number and the padding
         * flips from 0x00 to 0xFF.  Nothing but paramsign()'s dereference at
         * num.c:32 distinguishes the two halves of this pair, which makes it
         * the tightest test of sign detection in this file.
         */
        unsigned char src[1];
        OSSL_PARAM param;
        int dest = param_sentinel_int();
        struct int_result got;
        int ok;

        ok = param_put_host_order(src, sizeof src,
                                  param_max_signed_in(1) + (uintmax_t)1);
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("sign: I[1]=80 fixture", ok, 1); ret &= test;

        got = call_get_int(&dest, &param);
        TEST_ASSERT_INT_EQ("sign: I[1]=80 rc", got.rc, 1); ret &= test;
        TEST_ASSERT_INT_EQ("sign: I[1]=80 value", got.value,
                           -(intmax_t)param_max_signed_in(1) - 1);
        ret &= test;
        TEST_ASSERT_INT_EQ("sign: I[1]=80 param", got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * PAIR 5a -- the same one-byte sign boundary seen from the UNSIGNED
         * destination, positive half: a signed source whose sign bit is clear
         * is POSITIVE, so the second disjunct of num.c:124 holds and the
         * conversion into a size_t succeeds.
         */
        unsigned char src[1];
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;
        int ok;

        ok = param_put_host_order(src, sizeof src, param_max_signed_in(1));
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("sign: I[1]=7F->size_t fixture", ok, 1);
        ret &= test;

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("sign: I[1]=7F->size_t rc", got.rc, 1); ret &= test;
        TEST_ASSERT_SIZE_EQ("sign: I[1]=7F->size_t value", got.value,
                            (size_t)param_max_signed_in(1));
        ret &= test;
        TEST_ASSERT_INT_EQ("sign: I[1]=7F->size_t param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * PAIR 5b -- one greater, and the whole answer changes: with the sign
         * bit set the source is NEGATIVE, neither disjunct of num.c:124
         * holds, and control reaches the fallthrough at num.c:150.  This is
         * the boundary at which a signed source stops being convertible to an
         * unsigned destination, and the pair pins it to the bit rather than to
         * the type: the same width, the same destination, one bit apart, two
         * different outcomes.
         */
        unsigned char src[1];
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;
        int ok;

        ok = param_put_host_order(src, sizeof src,
                                  param_max_signed_in(1) + (uintmax_t)1);
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("sign: I[1]=80->size_t fixture", ok, 1);
        ret &= test;

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("sign: I[1]=80->size_t rc", got.rc,
                           PROVNUM_E_UNSUPPORTED);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("sign: I[1]=80->size_t untouched", got.value,
                            param_sentinel_size_t());
        ret &= test;
        TEST_ASSERT_INT_EQ("sign: I[1]=80->size_t param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * The two-byte positive edge, for a width between the one-byte and
         * natural-width cases: the largest two-byte value with its high bit
         * clear, delivered without alteration.
         */
        unsigned char src[2];
        OSSL_PARAM param;
        int dest = param_sentinel_int();
        struct int_result got;
        int ok;

        ok = param_put_host_order(src, sizeof src, param_max_signed_in(2));
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("sign: I[2]=7F FF fixture", ok, 1); ret &= test;

        got = call_get_int(&dest, &param);
        TEST_ASSERT_INT_EQ("sign: I[2]=7F FF rc", got.rc, 1); ret &= test;
        TEST_ASSERT_INT_EQ("sign: I[2]=7F FF value", got.value,
                           (intmax_t)param_max_signed_in(2));
        ret &= test;
        TEST_ASSERT_INT_EQ("sign: I[2]=7F FF param", got.param_unchanged, 1);
        ret &= test;
    }

    return ret;
}

/*
 * ===========================================================================
 * The padding-strip rules, and the one behaviour this file will not assert
 * ===========================================================================
 * num.c:90-93 documents both rules the strip loop applies to a source wider
 * than its destination:
 *
 *   (a) the most significant byte must equal the sign pad byte, which for
 *       num.c's sign_t at num.c:7 is 0xFF when negative and 0x00 when
 *       positive -- the two's complement padding values;
 *   (b) the high bit of the NEXT byte down must match the high bit of that
 *       same pad byte.
 *
 * Neither rule is written to care whether the source's declared type is
 * signed, and the pair of fixtures below proves that it does not: two
 * UNSIGNED sources of identical width, differing in nothing but the high bit
 * that rule (b) inspects, get opposite answers.
 */
static int test_get_edge_cases(void)
{
    int ret = 1, test;

    {
        /*
         * Rule (b) PERMITS the strip: 0x00 on top satisfies rule (a), and the
         * byte below it has its high bit clear, so the redundant byte goes and
         * what is left fits exactly.
         */
        unsigned char src[sizeof(size_t) + 1];
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;
        int ok;

        ok = param_expect_pattern(src, sizeof src,
                                  param_max_signed_in(1)
                                  << ((sizeof(size_t) - 1) * CHAR_BIT),
                                  sizeof(size_t), (unsigned char)0x00U);
        param_build_unsigned(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("rule b: U[SZ+1]=00 7F 00.. fixture", ok, 1);
        ret &= test;

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("rule b: U[SZ+1]=00 7F 00.. rc", got.rc, 1);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("rule b: U[SZ+1]=00 7F 00.. value", got.value,
                            (size_t)(param_max_signed_in(1)
                                     << ((sizeof(size_t) - 1) * CHAR_BIT)));
        ret &= test;
        TEST_ASSERT_INT_EQ("rule b: U[SZ+1]=00 7F 00.. param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * Rule (b) BLOCKS the strip, on an UNSIGNED source, and that is the
         * point of this case: the fixture differs from the one above in
         * exactly one bit -- 0xFF where it had 0x7F -- and the answer changes
         * from success to PROVNUM_E_TOOBIG.  Rule (b) is therefore applied to
         * unsigned sources too, not only to signed ones, so a mutation
         * restricting it to signed sources fails here.
         *
         * Worth knowing, and a consequence of the same rule: it makes the
         * strip deliberately conservative rather than arithmetic.  A source of
         * SZ + 1 bytes reading 00 FF FF .. FF denotes SIZE_MAX, which would
         * fit the destination perfectly, and is still refused, because rule
         * (b) sees a set high bit under a positive pad byte.  That is what
         * num.c:90-93 specifies; no separate assertion is made for it, since
         * the fixture below already pins the rule that decides it.
         */
        unsigned char src[sizeof(size_t) + 1];
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;
        int ok;

        ok = param_expect_pattern(src, sizeof src,
                                  param_max_unsigned_in(1)
                                  << ((sizeof(size_t) - 1) * CHAR_BIT),
                                  sizeof(size_t), (unsigned char)0x00U);
        param_build_unsigned(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("rule b: U[SZ+1]=00 FF 00.. fixture", ok, 1);
        ret &= test;

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("rule b: U[SZ+1]=00 FF 00.. rc", got.rc,
                           PROVNUM_E_TOOBIG);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("rule b: U[SZ+1]=00 FF 00.. untouched", got.value,
                            param_sentinel_size_t());
        ret &= test;
        TEST_ASSERT_INT_EQ("rule b: U[SZ+1]=00 FF 00.. param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * A signed source exactly as wide as the unsigned destination, with
         * its sign bit clear: the widest positive value that can cross from a
         * signed source into a size_t.  It complements the negative
         * exact-width case in test_get_unsupported_and_complement(), which
         * differs only in that bit and is refused.
         */
        unsigned char src[sizeof(size_t)];
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;
        int ok;

        ok = param_put_host_order(src, sizeof src,
                                  param_max_signed_in(sizeof(size_t)));
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("I[SZ]=7F FF..->size_t fixture", ok, 1);
        ret &= test;

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("I[SZ]=7F FF..->size_t rc", got.rc, 1); ret &= test;
        TEST_ASSERT_SIZE_EQ("I[SZ]=7F FF..->size_t value", got.value,
                            SIZE_MAX / 2);
        ret &= test;
        TEST_ASSERT_INT_EQ("I[SZ]=7F FF..->size_t param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    /*
     * -----------------------------------------------------------------------
     * CLASS C -- A DELIBERATE NON-ASSERTION.  THIS IS NOT A GAP.
     * -----------------------------------------------------------------------
     * The behaviour: provnum_get_int() given an OSSL_PARAM_UNSIGNED_INTEGER
     * source exactly sizeof(int) bytes wide with every bit set.  paramsign()
     * short-circuits to POSITIVE at num.c:30-31, the simple-case condition at
     * num.c:121-124 is satisfied, src.size == dest.size so the bytes are
     * copied verbatim, and the signed destination ends up holding a NEGATIVE
     * number even though the source was declared unsigned.
     *
     * Two readings of the contract are defensible and include/prov/num.h
     * settles neither:
     *
     *   (a) an unsigned value larger than INT_MAX does not fit a signed
     *       destination and should be refused as PROVNUM_E_TOOBIG, on the
     *       same principle by which a source one byte wider is refused;
     *
     *   (b) the source's byte width matches the destination's exactly, so
     *       nothing is lost or padded and the copy is legitimate; how the
     *       caller interprets a full-width bit pattern is the caller's
     *       business, and libprov is being asked to move bytes.
     *
     * The normative OpenSSL prose for the upstream conversions this family
     * replaces was not retrievable in this environment, so neither reading can
     * be shown to be the intended one.  NO ASSERTION IS THEREFORE MADE about
     * this input, in either direction.  Asserting whatever the code currently
     * emits -- rc 1 with a wrapped negative value, which is what it does
     * emit -- would enshrine one reading as the contract on no authority, and
     * asserting the other would fail against code that is not known to be
     * wrong.
     *
     * Do NOT "complete" this by adding an assertion.  If the intended
     * behaviour is ever settled -- by upstream documentation, by a maintainer
     * decision, or by a change to include/prov/num.h -- then assert it, and
     * delete this comment.  Until then the honest record is that the question
     * is open, and this comment is the record.  The related setter-side
     * ambiguity is documented by param_util.h at param_expect_zero_padded().
     */

    return ret;
}

/*
 * ===========================================================================
 * The type whitelist -- every data type that is not an integer is refused
 * ===========================================================================
 * num.c:63-67 admits OSSL_PARAM_INTEGER and OSSL_PARAM_UNSIGNED_INTEGER and
 * rejects everything else.  <openssl/core.h> defines exactly five other data
 * types, and all five are exercised below, individually, so a failure names
 * the type that slipped through.  Testing one type would leave the check
 * indistinguishable from a comparison against that single value.
 */
static int test_get_wrong_types(void)
{
    int ret = 1, test;
    /*
     * Labels are pre-composed rather than formatted at run time: a table of
     * literals cannot truncate, needs no buffer and keeps every label
     * greppable in this source.
     */
    const struct {
        unsigned int data_type;
        const char *rc_label;
        const char *untouched_label;
        const char *param_label;
    } wrong[] = {
        { OSSL_PARAM_REAL,
          "REAL rc", "REAL untouched", "REAL param" },
        { OSSL_PARAM_UTF8_STRING,
          "UTF8_STRING rc", "UTF8_STRING untouched", "UTF8_STRING param" },
        { OSSL_PARAM_OCTET_STRING,
          "OCTET_STRING rc", "OCTET_STRING untouched", "OCTET_STRING param" },
        { OSSL_PARAM_UTF8_PTR,
          "UTF8_PTR rc", "UTF8_PTR untouched", "UTF8_PTR param" },
        { OSSL_PARAM_OCTET_PTR,
          "OCTET_PTR rc", "OCTET_PTR untouched", "OCTET_PTR param" }
    };
    /*
     * One buffer serves every iteration: the bytes are irrelevant to a
     * rejection that happens before they are read, and building it once means
     * its verdict is asserted once rather than five identical times.  It holds
     * a pattern that is neither the sentinel nor a plausible result, so a
     * conversion that wrongly went ahead could not accidentally produce the
     * value the destination already had.
     */
    unsigned char src[sizeof(int)];
    size_t k;
    int ok;

    ok = param_fill(src, sizeof src, (unsigned char)0x01U);
    TEST_ASSERT_INT_EQ("wrong type: shared fixture", ok, 1); ret &= test;

    for (k = 0; k < sizeof wrong / sizeof wrong[0]; k++) {
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;

        param_build(&param, wrong[k].data_type, src, sizeof src);

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ(wrong[k].rc_label, got.rc, PROVNUM_E_WRONG_TYPE);
        ret &= test;
        TEST_ASSERT_SIZE_EQ(wrong[k].untouched_label, got.value,
                            param_sentinel_size_t());
        ret &= test;
        TEST_ASSERT_INT_EQ(wrong[k].param_label, got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * The same rejection through the other instantiation, proving the
         * whitelist belongs to provnum_copy() rather than to one generated
         * function: implement_provnum() at num.c:154-183 produces both from
         * one body, and num.c:186 instantiates this one with
         * OSSL_PARAM_INTEGER as the DESTINATION type -- which must not be
         * mistaken for permission to accept a REAL source.
         */
        OSSL_PARAM param;
        int dest = param_sentinel_int();
        struct int_result got;

        param_build(&param, OSSL_PARAM_REAL, src, sizeof src);

        got = call_get_int(&dest, &param);
        TEST_ASSERT_INT_EQ("REAL->int rc", got.rc, PROVNUM_E_WRONG_TYPE);
        ret &= test;
        TEST_ASSERT_INT_EQ("REAL->int untouched", got.value,
                           param_sentinel_int());
        ret &= test;
        TEST_ASSERT_INT_EQ("REAL->int param", got.param_unchanged, 1);
        ret &= test;
    }

    return ret;
}

/*
 * ===========================================================================
 * Absent inputs: a null source buffer, an empty source, a null destination
 * ===========================================================================
 *
 * *** THE FIXTURES BELOW MUST STAY OSSL_PARAM_INTEGER.  READ THIS FIRST. ***
 *
 * provnum_get_size_t() and provnum_get_int() both compute paramsign(param) in
 * the argument list at num.c:163, so paramsign() runs BEFORE provnum_copy()
 * has validated anything at all.  Inside it, num.c:30-31 returns POSITIVE the
 * moment the data type is OSSL_PARAM_UNSIGNED_INTEGER, and only a source of
 * any other type reaches the dereference at num.c:32 -- indexed with
 * data_size - 1, which for a size of zero wraps and reads before the buffer.
 *
 * The consequence is not obvious and it is the reason for this warning: a
 * null-data or zero-size fixture typed OSSL_PARAM_UNSIGNED_INTEGER never
 * drives execution past that short circuit, so it CANNOT detect a missing
 * guard, no matter how right its expected return code looks.  Measured:
 * deleting the guard at num.c:24-25 leaves an unsigned-typed null-data test
 * passing, while the signed-typed cases below die of SIGSEGV -- which CTest
 * reports as a failure -- and the zero-size case reads outside its buffer,
 * which a sanitizer reports.
 *
 * So: the signed cases come first, they are labelled, and they are the ones
 * that matter.  An unsigned-typed null-data case is kept as well, because
 * PROVNUM_E_NULL is genuinely its documented answer too, but it is a
 * companion, not a substitute.  Retyping the signed cases to unsigned would
 * leave every assertion in this file still passing and reopen the hole.
 *
 * One thing these cases deliberately do NOT pin, and why: the guard answers
 * POSITIVE, and nothing observable depends on that choice.  src.sign is read
 * at exactly four places -- the two strip rules at num.c:103 and
 * num.c:104-105, the sign clause at num.c:124, and the pad fill at
 * num.c:136 -- and every input that reaches the guard leaves provnum_copy()
 * before any of them: a zero data_size takes the empty-source shortcut at
 * num.c:69-73, and a null data pointer with a non-zero size takes the
 * rejection at num.c:75-78.  The value the guard returns is therefore dead
 * on every path that can produce it, so changing it to NEGATIVE alters no
 * return code and no destination byte anywhere in this file's reach --
 * confirmed by an 88-million-input differential sweep across both generated
 * functions.  No assertion could distinguish the two, so none is written;
 * this is an equivalence, not a gap.
 */
static int test_get_null_and_empty(void)
{
    int ret = 1, test;

    {
        /*
         * A null source with a signed type, into the signed destination: the
         * fixture that reaches paramsign()'s dereference.  The documented
         * answer is PROVNUM_E_NULL, from num.c:75-78.
         */
        OSSL_PARAM param;
        int dest = param_sentinel_int();
        struct int_result got;

        param_build_null_data(&param, OSSL_PARAM_INTEGER, sizeof(int));

        got = call_get_int(&dest, &param);
        TEST_ASSERT_INT_EQ("I[IN]=NULL->int rc", got.rc, PROVNUM_E_NULL);
        ret &= test;
        TEST_ASSERT_INT_EQ("I[IN]=NULL->int untouched", got.value,
                           param_sentinel_int());
        ret &= test;
        TEST_ASSERT_INT_EQ("I[IN]=NULL->int param", got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * The same null source with a signed type, into the unsigned
         * destination: the other instantiation reaches the same dereference,
         * so both generated functions are covered rather than one.
         */
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;

        param_build_null_data(&param, OSSL_PARAM_INTEGER, sizeof(size_t));

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("I[SZ]=NULL->size_t rc", got.rc, PROVNUM_E_NULL);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("I[SZ]=NULL->size_t untouched", got.value,
                            param_sentinel_size_t());
        ret &= test;
        TEST_ASSERT_INT_EQ("I[SZ]=NULL->size_t param", got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * The unsigned companion: a legitimate assertion in its own right --
         * PROVNUM_E_NULL is the documented answer whatever the integer type --
         * and blind to the dereference, for the reason given at the head of
         * this group.  It is here to pin the contract, not to guard it.
         */
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;

        param_build_null_data(&param, OSSL_PARAM_UNSIGNED_INTEGER,
                              sizeof(size_t));

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("U[SZ]=NULL->size_t rc", got.rc, PROVNUM_E_NULL);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("U[SZ]=NULL->size_t untouched", got.value,
                            param_sentinel_size_t());
        ret &= test;
        TEST_ASSERT_INT_EQ("U[SZ]=NULL->size_t param", got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * An empty source: a real buffer, a declared size of zero, and a
         * signed type.  Two things are surprising and both are asserted.  The
         * shortcut at num.c:69-73 returns SUCCESS rather than an error, and it
         * zeroes the WHOLE destination on the way out at num.c:71 -- so an
         * empty number converts to 0 and the sentinel is gone.  A refactor
         * that turned an empty source into an error, or that stopped clearing
         * the destination, would break here.
         *
         * This is also the zero-size half of the pre-validation dereference:
         * with the guard at num.c:24-25 removed, paramsign() computes
         * data_size - 1, wraps, and reads the byte BEFORE this buffer.  The
         * buffer is a separate automatic object sized exactly to the fixture
         * precisely so that a sanitizer can see that read.
         */
        unsigned char src[sizeof(int)];
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;
        int ok;

        ok = param_fill(src, sizeof src, (unsigned char)0xFFU);
        ok = param_build_empty(&param, OSSL_PARAM_INTEGER, src) && ok;
        TEST_ASSERT_INT_EQ("I[0]->size_t fixture", ok, 1); ret &= test;

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("I[0]->size_t rc", got.rc, 1); ret &= test;
        TEST_ASSERT_SIZE_EQ("I[0]->size_t value", got.value, (size_t)0);
        ret &= test;
        TEST_ASSERT_INT_EQ("I[0]->size_t param", got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * The same empty source into the signed destination, and typed
         * unsigned to show the shortcut does not depend on the sign: success,
         * destination cleared, whichever way the two vary.
         */
        unsigned char src[sizeof(int)];
        OSSL_PARAM param;
        int dest = param_sentinel_int();
        struct int_result got;
        int ok;

        ok = param_fill(src, sizeof src, (unsigned char)0xFFU);
        ok = param_build_empty(&param, OSSL_PARAM_UNSIGNED_INTEGER, src) && ok;
        TEST_ASSERT_INT_EQ("U[0]->int fixture", ok, 1); ret &= test;

        got = call_get_int(&dest, &param);
        TEST_ASSERT_INT_EQ("U[0]->int rc", got.rc, 1); ret &= test;
        TEST_ASSERT_INT_EQ("U[0]->int value", got.value, 0); ret &= test;
        TEST_ASSERT_INT_EQ("U[0]->int param", got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * A null DESTINATION with a source that is present and fits.  Nothing
         * can be stripped (the source is already one byte), nothing is too
         * big, so control reaches num.c:115-118 and PROVNUM_E_NULL comes back.
         * There is no destination to inspect afterwards, so the return code is
         * the whole of the observable contract here -- which is why the empty
         * source case in test_get_precedence() matters: it is the one input
         * for which a null destination is NOT an error.
         */
        unsigned char src[1];
        OSSL_PARAM param;
        struct size_t_result got;
        int ok;

        ok = param_put_host_order(src, sizeof src, (uintmax_t)5);
        param_build_unsigned(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("U[1]=05 null dest fixture", ok, 1); ret &= test;

        got = call_get_size_t(NULL, &param);
        TEST_ASSERT_INT_EQ("U[1]=05 null dest rc", got.rc, PROVNUM_E_NULL);
        ret &= test;
        TEST_ASSERT_INT_EQ("U[1]=05 null dest param", got.param_unchanged, 1);
        ret &= test;
    }

    {
        /* The same null destination through the signed instantiation. */
        unsigned char src[1];
        OSSL_PARAM param;
        struct int_result got;
        int ok;

        ok = param_put_host_order(src, sizeof src, (uintmax_t)5);
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("I[1]=05 null dest fixture", ok, 1); ret &= test;

        got = call_get_int(NULL, &param);
        TEST_ASSERT_INT_EQ("I[1]=05 null dest rc", got.rc, PROVNUM_E_NULL);
        ret &= test;
        TEST_ASSERT_INT_EQ("I[1]=05 null dest param", got.param_unchanged, 1);
        ret &= test;
    }

    /*
     * -------------------------------------------------------------------
     * Null DESTINATION with a source made ENTIRELY of pad bytes.
     *
     * These look redundant beside the two cases above.  They are not, and
     * the reason is worth spelling out because it is not visible from the
     * return codes alone.
     *
     * A null destination clamps the padding-strip loop's floor to one byte
     * (num.c:101).  When every source byte equals the sign pad byte, both
     * strip rules hold at every position, so the loop walks the source all
     * the way down and stops at a single byte -- src.size > end is false
     * once src.size reaches 1 (num.c:102).  The oversize test at num.c:108
     * then sees the stripped width, so even a source wider than the
     * destination is not too big, and the answer is PROVNUM_E_NULL from
     * num.c:115-118.  The sign pad byte is the type's two's-complement
     * fill (num.c:7), so "all pad bytes" means all 0x00 for a positive
     * source and all 0xff for a negative one.
     *
     * WHY THESE CASES EXIST: they are the only inputs that pin the strip
     * loop's FLOOR.  Relaxing the bound at num.c:102 from > to >= lets the
     * loop run one iteration too many at src.size == 1.  There rule (a)
     * holds -- the byte equals the sign pad -- so the || does not
     * short-circuit and rule (b) indexes srcmsb + srcmsb2lsb, which is one
     * byte BEFORE the start of the source.  That relaxation changes no
     * return code and no destination value for any provnum_get_* input
     * whatsoever, so it is observable only as an out-of-bounds read.
     *
     * Consequences for whoever maintains this block:
     *   - every buffer below is sized EXACTLY, and none is shared, so the
     *     sanitizer build in the project's validation recipe reports a
     *     stack-buffer-overflow READ against the mutated library and this
     *     test fails.  Widening a buffer, padding it, or hoisting it into
     *     a shared array would hide the very defect these cases exist to
     *     expose.
     *   - the fixtures must stay OSSL_PARAM_INTEGER except where an
     *     unsigned type is named explicitly, for the reason given at the
     *     head of this function.
     * -------------------------------------------------------------------
     */
    {
        /*
         * One byte, 0x00, signed.  paramsign() reads the byte at num.c:32,
         * finds the high bit clear and answers POSITIVE, so the single byte
         * IS the pad byte and the loop is asked to strip it.
         */
        unsigned char src[1];
        OSSL_PARAM param;
        struct size_t_result got;
        int ok;

        ok = param_fill(src, sizeof src, (unsigned char)0x00U);
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("I[1]=00 null dest fixture", ok, 1); ret &= test;

        got = call_get_size_t(NULL, &param);
        TEST_ASSERT_INT_EQ("I[1]=00 null dest rc", got.rc, PROVNUM_E_NULL);
        ret &= test;
        TEST_ASSERT_INT_EQ("I[1]=00 null dest param", got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * One byte, 0xff, signed: paramsign() answers NEGATIVE (num.c:32),
         * whose pad byte is 0xff, so again the only byte present is a pad
         * byte.  This is the negative half of the pair -- the two together
         * prove the floor holds for both sign values, not just for zero.
         */
        unsigned char src[1];
        OSSL_PARAM param;
        struct size_t_result got;
        int ok;

        ok = param_fill(src, sizeof src, (unsigned char)0xFFU);
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("I[1]=FF null dest fixture", ok, 1); ret &= test;

        got = call_get_size_t(NULL, &param);
        TEST_ASSERT_INT_EQ("I[1]=FF null dest rc", got.rc, PROVNUM_E_NULL);
        ret &= test;
        TEST_ASSERT_INT_EQ("I[1]=FF null dest param", got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * The unsigned type reaches the same floor by a different route:
         * paramsign() short-circuits to POSITIVE at num.c:30-31 without
         * reading anything, and 0x00 is the positive pad byte, so the loop
         * is again asked to strip the only byte there is.
         */
        unsigned char src[1];
        OSSL_PARAM param;
        struct size_t_result got;
        int ok;

        ok = param_fill(src, sizeof src, (unsigned char)0x00U);
        param_build_unsigned(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("U[1]=00 null dest fixture", ok, 1); ret &= test;

        got = call_get_size_t(NULL, &param);
        TEST_ASSERT_INT_EQ("U[1]=00 null dest rc", got.rc, PROVNUM_E_NULL);
        ret &= test;
        TEST_ASSERT_INT_EQ("U[1]=00 null dest param", got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * A full-width all-zero signed source: the loop strips
         * sizeof(size_t) - 1 bytes before reaching the floor, so this case
         * proves the floor is reached by walking rather than by luck.
         */
        unsigned char src[sizeof(size_t)];
        OSSL_PARAM param;
        struct size_t_result got;
        int ok;

        ok = param_fill(src, sizeof src, (unsigned char)0x00U);
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("I[SZ]=00.. null dest fixture", ok, 1);
        ret &= test;

        got = call_get_size_t(NULL, &param);
        TEST_ASSERT_INT_EQ("I[SZ]=00.. null dest rc", got.rc, PROVNUM_E_NULL);
        ret &= test;
        TEST_ASSERT_INT_EQ("I[SZ]=00.. null dest param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * The negative twin of the case above, and also the one input in
         * this group that would otherwise answer PROVNUM_E_UNSUPPORTED: a
         * negative source into the unsigned instantiation normally fails
         * the sign clause at num.c:124.  It does not get that far, because
         * the null-destination guard at num.c:115-118 comes first.  So this
         * fixture pins a precedence fact as well as the loop floor.
         */
        unsigned char src[sizeof(size_t)];
        OSSL_PARAM param;
        struct size_t_result got;
        int ok;

        ok = param_fill(src, sizeof src, (unsigned char)0xFFU);
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("I[SZ]=FF.. null dest fixture", ok, 1);
        ret &= test;

        got = call_get_size_t(NULL, &param);
        TEST_ASSERT_INT_EQ("I[SZ]=FF.. null dest rc", got.rc, PROVNUM_E_NULL);
        ret &= test;
        TEST_ASSERT_INT_EQ("I[SZ]=FF.. null dest param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * One byte WIDER than the destination, and entirely pad: with a
         * null destination the floor is one byte rather than
         * sizeof(size_t), so the loop strips past the destination width and
         * the oversize test at num.c:108 never fires.  PROVNUM_E_TOOBIG
         * would be the wrong answer here; PROVNUM_E_NULL is the right one.
         */
        unsigned char src[sizeof(size_t) + 1];
        OSSL_PARAM param;
        struct size_t_result got;
        int ok;

        ok = param_fill(src, sizeof src, (unsigned char)0x00U);
        param_build_unsigned(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("U[SZ+1]=00.. null dest fixture", ok, 1);
        ret &= test;

        got = call_get_size_t(NULL, &param);
        TEST_ASSERT_INT_EQ("U[SZ+1]=00.. null dest rc", got.rc,
                           PROVNUM_E_NULL);
        ret &= test;
        TEST_ASSERT_INT_EQ("U[SZ+1]=00.. null dest param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * The same floor through the signed instantiation, so neither
         * expansion of implement_provnum() is left unexercised: an
         * int-width all-0xff source with a null int destination.
         */
        unsigned char src[sizeof(int)];
        OSSL_PARAM param;
        struct int_result got;
        int ok;

        ok = param_fill(src, sizeof src, (unsigned char)0xFFU);
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("I[IN]=FF.. null dest fixture", ok, 1);
        ret &= test;

        got = call_get_int(NULL, &param);
        TEST_ASSERT_INT_EQ("I[IN]=FF.. null dest rc", got.rc, PROVNUM_E_NULL);
        ret &= test;
        TEST_ASSERT_INT_EQ("I[IN]=FF.. null dest param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    return ret;
}

/*
 * ===========================================================================
 * Sources wider than the destination -- when the extra bytes are padding and
 * when they are not
 * ===========================================================================
 * The boundary pairs above take the width edge one byte at a time.  This
 * group covers the rest of the strip loop's behaviour: a source whose extra
 * byte is plainly significant, a source whose extra bytes are all padding and
 * need SEVERAL iterations to remove, and the same rejection through the other
 * instantiation.  Between them they pin the loop's bound at num.c:102 from
 * both sides -- it must run often enough to strip four bytes and stop exactly
 * at the destination's width.
 */
static int test_get_oversize(void)
{
    int ret = 1, test;

    {
        /*
         * One byte too wide, every bit set, declared unsigned: rule (a) fails
         * at once because 0xFF is not the positive pad byte, so the loop
         * breaks on its first iteration and the source is still too wide.
         * PROVNUM_E_TOOBIG, from num.c:108-111.
         */
        unsigned char src[sizeof(size_t) + 1];
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;
        int ok;

        ok = param_fill(src, sizeof src, (unsigned char)0xFFU);
        param_build_unsigned(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("U[SZ+1]=FF.. fixture", ok, 1); ret &= test;

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("U[SZ+1]=FF.. rc", got.rc, PROVNUM_E_TOOBIG);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("U[SZ+1]=FF.. untouched", got.value,
                            param_sentinel_size_t());
        ret &= test;
        TEST_ASSERT_INT_EQ("U[SZ+1]=FF.. param", got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * FOUR bytes too wide, and every one of them padding: the loop has to
         * iterate four times and then stop, because src.size is no longer
         * greater than dest.size.  A loop that stopped early would answer
         * PROVNUM_E_TOOBIG; one that ran once too often would copy a byte
         * short.  The value asserted is the largest size_t with its top bit
         * clear, which is what the significant bytes hold.
         */
        unsigned char src[sizeof(size_t) + 4];
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;
        int ok;

        ok = param_expect_pattern(src, sizeof src,
                                  param_max_signed_in(sizeof(size_t)),
                                  sizeof(size_t), (unsigned char)0x00U);
        param_build_unsigned(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("U[SZ+4]=00.. 7F FF.. fixture", ok, 1); ret &= test;

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("U[SZ+4]=00.. 7F FF.. rc", got.rc, 1); ret &= test;
        TEST_ASSERT_SIZE_EQ("U[SZ+4]=00.. 7F FF.. value", got.value,
                            SIZE_MAX / 2);
        ret &= test;
        TEST_ASSERT_INT_EQ("U[SZ+4]=00.. 7F FF.. param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * The same rejection at the int destination's width: a 0x01 above
         * sizeof(int) bytes of zeros is one byte too wide for an int however
         * small the number it denotes, because the strip rules work on bytes
         * and not on magnitude.
         */
        unsigned char src[sizeof(int) + 1];
        OSSL_PARAM param;
        int dest = param_sentinel_int();
        struct int_result got;
        int ok;

        ok = param_expect_pattern(src, sizeof src, (uintmax_t)0, sizeof(int),
                                  (unsigned char)0x01U);
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("I[IN+1]=01 00.. fixture", ok, 1); ret &= test;

        got = call_get_int(&dest, &param);
        TEST_ASSERT_INT_EQ("I[IN+1]=01 00.. rc", got.rc, PROVNUM_E_TOOBIG);
        ret &= test;
        TEST_ASSERT_INT_EQ("I[IN+1]=01 00.. untouched", got.value,
                           param_sentinel_int());
        ret &= test;
        TEST_ASSERT_INT_EQ("I[IN+1]=01 00.. param", got.param_unchanged, 1);
        ret &= test;
    }

    return ret;
}

/*
 * ===========================================================================
 * PROVNUM_E_UNSUPPORTED, and the proof of where it cannot happen
 * ===========================================================================
 * num.c:150 is the fallthrough taken when the simple-case condition at
 * num.c:121-124 does not hold.  Reaching it through the public API is
 * narrower than it looks, and the three proofs below are why this group
 * asserts what it does.
 *
 * PROOF 1 -- provnum_get_int() can NEVER return PROVNUM_E_UNSUPPORTED.  The
 * condition's last clause is
 *
 *     (dest.data_type == OSSL_PARAM_INTEGER || src.sign == POSITIVE)
 *
 * and for provnum_get_int() the destination descriptor built at num.c:158-160
 * takes its data_type from the macro's DT parameter, which num.c:186
 * instantiates as OSSL_PARAM_INTEGER.  The first disjunct is therefore
 * ALWAYS true and the clause can never fail.  A test cannot assert an
 * unreachable return, so this group asserts the COMPLEMENTARY fact instead:
 * the very input that yields PROVNUM_E_UNSUPPORTED from provnum_get_size_t()
 * yields SUCCESS from provnum_get_int().  That is what makes the exclusion
 * evidence rather than assumption -- and it fails if the instantiation at
 * num.c:186 is ever changed.
 *
 * PROOF 2 -- provnum_get_size_t() is the only reachable site.  num.c:185
 * instantiates it with OSSL_PARAM_UNSIGNED_INTEGER, so the first disjunct is
 * always false and the clause turns entirely on src.sign.  A source declared
 * OSSL_PARAM_INTEGER whose most significant bit is set makes paramsign()
 * answer NEGATIVE at num.c:32-33, and the fallthrough is taken.
 *
 * PROOF 3 -- the condition's other three clauses are UNSATISFIABLE through
 * the public API, so no test can cover them and none is attempted.  All four
 * numdesc initialisers -- num.c:158-160 and num.c:161-164 for the getters,
 * num.c:172-175 and num.c:176-178 for the setters -- set `endian` from the
 * same nativeendian() call, `limbsize` to 1 and `limbnailbits` to 0, for the
 * source and the destination alike.  dest.endian == src.endian,
 * dest.limbsize == 1 and dest.limbnailbits == 0 therefore hold on every call
 * that can be made, and only editing num.c could falsify one.  They are
 * named here so the gap is a documented consequence of the code's shape and
 * not an oversight in this file.
 *
 * PROOF 4 -- the second half of the strip-loop's floor clause is likewise
 * UNSATISFIABLE from a getter, and it is named here for the same reason.
 * num.c:101 reads
 *
 *     size_t end = dest.data == NULL || dest.size == 0 ? 1 : dest.size;
 *
 * and the `dest.size == 0` disjunct can only change the result when
 * dest.data is non-null AND dest.size is zero.  The getter's destination
 * descriptor at num.c:158-160 takes its size from sizeof(T), which is never
 * zero, so no call to provnum_get_size_t() or provnum_get_int() can satisfy
 * that combination; when the destination pointer is null the first disjunct
 * has already decided the value.  Deleting the disjunct therefore leaves
 * every getter answer and every getter destination byte unchanged --
 * confirmed here by an 88-million-input differential sweep across both
 * generated functions -- which makes it a semantically equivalent edit with
 * respect to THIS file rather than a coverage gap.  It is the setter's
 * descriptor at num.c:172-175 that takes its size from param->data_size and
 * can present zero capacity, so the disjunct is load-bearing there and its
 * reproducer belongs in the setter tests, not here.  Chasing it from this
 * file would mean asserting an input the getters cannot construct.
 */
static int test_get_unsupported_and_complement(void)
{
    int ret = 1, test;

    {
        /*
         * THE MINIMAL COMPLEMENTARY PAIR, and the evidence for PROOF 1: ONE
         * fixture -- a single 0xFF byte declared OSSL_PARAM_INTEGER -- offered
         * to both generated functions.  The unsigned destination refuses it
         * with PROVNUM_E_UNSUPPORTED; the signed destination accepts it and
         * delivers -1.  Nothing differs but the destination type, so the pair
         * shows the fallthrough is specific to the unsigned destination rather
         * than a general catch-all, which no single-function test could.
         */
        unsigned char src[1];
        OSSL_PARAM param;
        size_t as_size_t = param_sentinel_size_t();
        int as_int = param_sentinel_int();
        struct size_t_result unsigned_dest;
        struct int_result signed_dest;
        int ok;

        ok = param_fill(src, sizeof src, (unsigned char)0xFFU);
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("pair: I[1]=FF fixture", ok, 1); ret &= test;

        unsigned_dest = call_get_size_t(&as_size_t, &param);
        TEST_ASSERT_INT_EQ("pair: I[1]=FF->size_t rc", unsigned_dest.rc,
                           PROVNUM_E_UNSUPPORTED);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("pair: I[1]=FF->size_t untouched",
                            unsigned_dest.value, param_sentinel_size_t());
        ret &= test;
        TEST_ASSERT_INT_EQ("pair: I[1]=FF->size_t param",
                           unsigned_dest.param_unchanged, 1);
        ret &= test;

        signed_dest = call_get_int(&as_int, &param);
        TEST_ASSERT_INT_EQ("pair: I[1]=FF->int rc", signed_dest.rc, 1);
        ret &= test;
        TEST_ASSERT_INT_EQ("pair: I[1]=FF->int value", signed_dest.value, -1);
        ret &= test;
        TEST_ASSERT_INT_EQ("pair: I[1]=FF->int param",
                           signed_dest.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * A negative source exactly as wide as the unsigned destination: no
         * stripping is possible and nothing is too big, so the only thing
         * standing in the way is the sign, and PROVNUM_E_UNSUPPORTED is the
         * answer.  Compare the exact-width POSITIVE source in
         * test_get_edge_cases(), which differs in one bit and succeeds.
         */
        unsigned char src[sizeof(size_t)];
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;
        int ok;

        ok = param_fill(src, sizeof src, (unsigned char)0xFFU);
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("I[SZ]=FF..->size_t fixture", ok, 1); ret &= test;

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("I[SZ]=FF..->size_t rc", got.rc,
                           PROVNUM_E_UNSUPPORTED);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("I[SZ]=FF..->size_t untouched", got.value,
                            param_sentinel_size_t());
        ret &= test;
        TEST_ASSERT_INT_EQ("I[SZ]=FF..->size_t param", got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * A negative source one byte too wide, all bits set: this one DOES
         * strip -- 0xFF is the negative pad byte and the byte below it has its
         * high bit set, so both rules hold -- and after stripping it is no
         * longer too big.  The sign then decides, and the answer is
         * PROVNUM_E_UNSUPPORTED rather than PROVNUM_E_TOOBIG.  Paired with the
         * FF 00.. fixture in test_get_precedence(), which does not strip and
         * therefore answers PROVNUM_E_TOOBIG, this pins which of the two codes
         * belongs to which shape of input.
         */
        unsigned char src[sizeof(size_t) + 1];
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;
        int ok;

        ok = param_fill(src, sizeof src, (unsigned char)0xFFU);
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("I[SZ+1]=FF..->size_t fixture", ok, 1); ret &= test;

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("I[SZ+1]=FF..->size_t rc", got.rc,
                           PROVNUM_E_UNSUPPORTED);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("I[SZ+1]=FF..->size_t untouched", got.value,
                            param_sentinel_size_t());
        ret &= test;
        TEST_ASSERT_INT_EQ("I[SZ+1]=FF..->size_t param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    return ret;
}

/*
 * ===========================================================================
 * GUARD PRECEDENCE -- inputs that satisfy two guards at once
 * ===========================================================================
 * This is the group that makes the suite resistant to a refactoring mutation.
 * Every fixture below satisfies TWO of provnum_copy()'s guards
 * simultaneously, so its answer is decided by nothing but the order in which
 * the guards are evaluated.  Swapping any two of them changes no line's
 * reachability -- coverage stays exactly where it was, every other test in
 * this file still passes -- and yet the API starts answering differently.
 * Only assertions of this shape can see that.
 *
 * Each case names the two guards it puts in competition and the num.c lines
 * that establish which one wins.
 */
static int test_get_precedence(void)
{
    int ret = 1, test;

    {
        /*
         * WRONG TYPE (num.c:63) versus NULL DATA (num.c:75).  A source that is
         * both an OCTET_STRING and has no buffer.  The type check comes first,
         * so PROVNUM_E_WRONG_TYPE wins -- also the more useful answer, since a
         * caller who passed the wrong kind of parameter has a different bug
         * from one whose buffer went missing.
         */
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;

        param_build_null_data(&param, OSSL_PARAM_OCTET_STRING,
                              sizeof(size_t));

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("prec: wrong type vs null data", got.rc,
                           PROVNUM_E_WRONG_TYPE);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("prec: wrong type vs null data untouched",
                            got.value, param_sentinel_size_t());
        ret &= test;
        TEST_ASSERT_INT_EQ("prec: wrong type vs null data param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * WRONG TYPE (num.c:63) versus NULL DESTINATION (num.c:115).  A real
         * buffer of the wrong type, and nowhere to put the result.  The type
         * check is first of all the guards, so it wins here too.
         */
        unsigned char src[sizeof(int)];
        OSSL_PARAM param;
        struct size_t_result got;
        int ok;

        ok = param_fill(src, sizeof src, (unsigned char)0x01U);
        param_build(&param, OSSL_PARAM_OCTET_STRING, src, sizeof src);
        TEST_ASSERT_INT_EQ("prec: wrong type vs null dest fixture", ok, 1);
        ret &= test;

        got = call_get_size_t(NULL, &param);
        TEST_ASSERT_INT_EQ("prec: wrong type vs null dest", got.rc,
                           PROVNUM_E_WRONG_TYPE);
        ret &= test;
        TEST_ASSERT_INT_EQ("prec: wrong type vs null dest param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * EMPTY SOURCE (num.c:69) versus NULL DESTINATION (num.c:115), and the
         * most counter-intuitive answer in the whole contract: SUCCESS.  The
         * empty-source shortcut returns before the destination is ever looked
         * at, and it is careful to skip its memset when there is no
         * destination (num.c:70), so converting an empty number into nowhere
         * succeeds.  Compare the one-byte source with a null destination in
         * test_get_null_and_empty(), which is PROVNUM_E_NULL: the destination
         * check has not gone away, this input simply never reaches it.
         */
        unsigned char src[sizeof(int)];
        OSSL_PARAM param;
        struct size_t_result got;
        int ok;

        ok = param_fill(src, sizeof src, (unsigned char)0xFFU);
        ok = param_build_empty(&param, OSSL_PARAM_INTEGER, src) && ok;
        TEST_ASSERT_INT_EQ("prec: empty vs null dest fixture", ok, 1);
        ret &= test;

        got = call_get_size_t(NULL, &param);
        TEST_ASSERT_INT_EQ("prec: empty vs null dest", got.rc, 1); ret &= test;
        TEST_ASSERT_INT_EQ("prec: empty vs null dest param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * EMPTY SOURCE (num.c:69) versus NULL DATA (num.c:75).  Both hold at
         * once -- no buffer AND a declared size of zero -- and the shortcut is
         * evaluated first, so the answer is success with a zeroed destination
         * rather than PROVNUM_E_NULL.  A reader might well expect the null
         * pointer to dominate; it does not, and this is the only assertion
         * that says so.
         */
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;

        param_build_null_data(&param, OSSL_PARAM_INTEGER, (size_t)0);

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("prec: empty vs null data", got.rc, 1); ret &= test;
        TEST_ASSERT_SIZE_EQ("prec: empty vs null data value", got.value,
                            (size_t)0);
        ret &= test;
        TEST_ASSERT_INT_EQ("prec: empty vs null data param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * OVERSIZE (num.c:108) versus NULL DESTINATION (num.c:115).  The
         * oversize test is evaluated first, so PROVNUM_E_TOOBIG wins.
         *
         * The fixture has to be built with care, and the reason is worth
         * recording.  A null destination lowers the strip loop's floor from
         * dest.size to 1 (num.c:101), so a source whose extra bytes are
         * padding would be stripped all the way down to one byte, pass the
         * oversize test and come back PROVNUM_E_NULL -- which is exactly what
         * the one-byte case in test_get_null_and_empty() shows.  This source
         * therefore has to be genuinely non-strippable: a 0x01 on top fails
         * rule (a) immediately, the loop breaks at full width, and the source
         * is still wider than the destination when num.c:108 tests it.
         */
        unsigned char src[sizeof(size_t) + 1];
        OSSL_PARAM param;
        struct size_t_result got;
        int ok;

        ok = param_expect_pattern(src, sizeof src, (uintmax_t)0,
                                  sizeof(size_t), (unsigned char)0x01U);
        param_build_unsigned(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("prec: oversize vs null dest fixture", ok, 1);
        ret &= test;

        got = call_get_size_t(NULL, &param);
        TEST_ASSERT_INT_EQ("prec: oversize vs null dest", got.rc,
                           PROVNUM_E_TOOBIG);
        ret &= test;
        TEST_ASSERT_INT_EQ("prec: oversize vs null dest param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * OVERSIZE (num.c:108) versus the UNSUPPORTED FALLTHROUGH (num.c:150).
         * A negative signed source, too wide for the unsigned destination:
         * both PROVNUM_E_TOOBIG and PROVNUM_E_UNSUPPORTED are candidate
         * answers and the oversize test, being earlier, wins.
         *
         * CONSTRUCTING THIS CORRECTLY IS SUBTLE, and getting it wrong turns
         * the case into a duplicate of one already asserted elsewhere.  An
         * all-0xFF negative source of the same width STRIPS -- both padding
         * rules hold at every step -- so it stops being oversized and answers
         * PROVNUM_E_UNSUPPORTED instead; that is the third case in
         * test_get_unsupported_and_complement().  What is needed here is a
         * negative source the strip loop refuses to touch: MSB-first
         *
         *     FF 00 00 .. 00
         *
         * where the top byte equals the negative pad byte so rule (a) holds,
         * while the byte below it is 0x00, whose high bit does NOT match the
         * pad byte's, so rule (b) fails and the loop breaks on its first
         * iteration.  src.size is then still greater than dest.size at
         * num.c:108 and the oversize answer is the one that can be observed.
         */
        unsigned char src[sizeof(size_t) + 1];
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;
        int ok;

        ok = param_expect_pattern(src, sizeof src, (uintmax_t)0,
                                  sizeof(size_t), (unsigned char)0xFFU);
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("prec: oversize vs unsupported fixture", ok, 1);
        ret &= test;

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("prec: oversize vs unsupported", got.rc,
                           PROVNUM_E_TOOBIG);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("prec: oversize vs unsupported untouched",
                            got.value, param_sentinel_size_t());
        ret &= test;
        TEST_ASSERT_INT_EQ("prec: oversize vs unsupported param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    return ret;
}

/*
 * ===========================================================================
 * The parameter survives, member by member
 * ===========================================================================
 * Every case above already asserts param_identical(), which compares the
 * OSSL_PARAM's whole representation and so proves that not one of its five
 * members moved.  This group restates that invariant one member at a time for
 * three representative calls -- a success, an error that reads the buffer, and
 * an error that does not -- for two reasons a memcmp cannot serve.
 *
 * A failure here NAMES THE MEMBER that moved, where param_identical() can only
 * say the representation differs.  And it makes one member's expectation
 * explicit and greppable instead of implied: A GETTER MUST NOT WRITE
 * return_size.  Only the provnum_set_ half of implement_provnum() assigns it,
 * at num.c:181, and it does so on every path including its error returns.  The
 * obvious refactor -- folding the two halves of the macro together -- would
 * give the getters that assignment, and the contract broken would be a
 * caller's buffer sizing rather than anything a compiler could flag.
 *
 * This group also asserts the invariant no other group can: THE SOURCE BYTES
 * ARE NOT MODIFIED.  param_identical() compares the descriptor, not the buffer
 * it points at, so a conversion that wrote through `data` -- normalising the
 * padding it decided to strip, say, or byte-swapping in place -- would leave
 * every other assertion in this file passing while quietly corrupting the
 * caller's number.  The buffer is copied aside with memcpy() before the call
 * and compared byte for byte afterwards.
 */
static int test_get_error_invariants(void)
{
    int ret = 1, test;

    {
        /* A successful conversion: the parameter is input only. */
        unsigned char src[1];
        unsigned char before[sizeof src];
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;
        int ok;

        ok = param_put_host_order(src, sizeof src, (uintmax_t)5);
        param_build_unsigned(&param, src, sizeof src);
        memcpy(before, src, sizeof src);
        TEST_ASSERT_INT_EQ("inv success: fixture", ok, 1); ret &= test;

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("inv success: rc", got.rc, 1); ret &= test;
        TEST_ASSERT_SIZE_EQ("inv success: value", got.value, (size_t)5);
        ret &= test;
        TEST_ASSERT_MEM_EQ("inv success: source bytes", src, before,
                           sizeof src);
        ret &= test;
        TEST_ASSERT_PTR_NULL("inv success: key", param.key); ret &= test;
        TEST_ASSERT_UINT_EQ("inv success: data_type", param.data_type,
                            OSSL_PARAM_UNSIGNED_INTEGER);
        ret &= test;
        TEST_ASSERT_PTR_EQ("inv success: data", param.data, src); ret &= test;
        TEST_ASSERT_SIZE_EQ("inv success: data_size", param.data_size,
                            sizeof src);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("inv success: return_size not written",
                            param.return_size, (size_t)0);
        ret &= test;
    }

    {
        /*
         * An error that reads the source: the strip loop walks the buffer,
         * finds the source too wide and gives up.  Neither the parameter nor
         * the destination may show it.
         */
        unsigned char src[sizeof(size_t) + 1];
        unsigned char before[sizeof src];
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;
        int ok;

        ok = param_expect_pattern(src, sizeof src, (uintmax_t)0,
                                  sizeof(size_t), (unsigned char)0x01U);
        param_build_unsigned(&param, src, sizeof src);
        memcpy(before, src, sizeof src);
        TEST_ASSERT_INT_EQ("inv toobig: fixture", ok, 1); ret &= test;

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("inv toobig: rc", got.rc, PROVNUM_E_TOOBIG);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("inv toobig: destination untouched", got.value,
                            param_sentinel_size_t());
        ret &= test;
        TEST_ASSERT_MEM_EQ("inv toobig: source bytes", src, before,
                           sizeof src);
        ret &= test;
        TEST_ASSERT_PTR_NULL("inv toobig: key", param.key); ret &= test;
        TEST_ASSERT_UINT_EQ("inv toobig: data_type", param.data_type,
                            OSSL_PARAM_UNSIGNED_INTEGER);
        ret &= test;
        TEST_ASSERT_PTR_EQ("inv toobig: data", param.data, src); ret &= test;
        TEST_ASSERT_SIZE_EQ("inv toobig: data_size", param.data_size,
                            sizeof src);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("inv toobig: return_size not written",
                            param.return_size, (size_t)0);
        ret &= test;
    }

    {
        /*
         * An error that reads nothing: a null buffer with a signed type, which
         * is refused before any byte is touched.  `data` must still be null
         * afterwards -- a helper that "helpfully" repointed it at a scratch
         * buffer would be caught here -- and the declared size must be intact
         * so the caller can still see what it asked for.
         */
        OSSL_PARAM param;
        int dest = param_sentinel_int();
        struct int_result got;

        param_build_null_data(&param, OSSL_PARAM_INTEGER, sizeof(int));

        got = call_get_int(&dest, &param);
        TEST_ASSERT_INT_EQ("inv null: rc", got.rc, PROVNUM_E_NULL);
        ret &= test;
        TEST_ASSERT_INT_EQ("inv null: destination untouched", got.value,
                           param_sentinel_int());
        ret &= test;
        TEST_ASSERT_PTR_NULL("inv null: key", param.key); ret &= test;
        TEST_ASSERT_UINT_EQ("inv null: data_type", param.data_type,
                            OSSL_PARAM_INTEGER);
        ret &= test;
        TEST_ASSERT_PTR_NULL("inv null: data still null", param.data);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("inv null: data_size", param.data_size,
                            sizeof(int));
        ret &= test;
        TEST_ASSERT_SIZE_EQ("inv null: return_size not written",
                            param.return_size, (size_t)0);
        ret &= test;
    }

    return ret;
}

/*
 * Ten groups, each returning its own accumulated verdict in the project's
 * idiom, and two independent gates on the way out.  `ret` is the accumulation
 * itself.  TEST_REPORT() derives a second verdict from testutil.h's counters,
 * which is what makes an empty run a failure: a program that asserted nothing
 * -- because a group was dropped, or because a rebuild left main() calling
 * none of them -- cannot exit zero merely by reaching the end of main().
 * Both must be green, and the process status is the maintainer's "return
 * !ret;".
 */
int main(void)
{
    int ret = 1;

    ret &= test_get_size_t_happy();
    ret &= test_get_int_happy();
    ret &= test_get_boundaries();
    ret &= test_get_edge_cases();
    ret &= test_get_wrong_types();
    ret &= test_get_null_and_empty();
    ret &= test_get_oversize();
    ret &= test_get_unsupported_and_complement();
    ret &= test_get_precedence();
    ret &= test_get_error_invariants();

    if (TEST_REPORT("test_num_get") != 0)
        ret = 0;

    return !ret;
}
