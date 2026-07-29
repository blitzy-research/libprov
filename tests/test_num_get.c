/* CC0 license applied, see LICENSE */

/*
 * Contract, boundary and error-precedence tests for provnum_get_size_t() and
 * provnum_get_int(), the two conversions implement_provnum() generates at
 * num.c:170 and num.c:171.  Every case asserts a SPECIFIC value -- an exact
 * return code, an exact destination value, or an exact byte-level side effect.
 *
 * SUCCESS IS EXACTLY 1, AND ONLY num.c SAYS SO.  num.c:56 initialises
 * `struct resultdesc result = { dest.size, 1, };`, while include/prov/num.h
 * defines the four failure codes and never states the success value, so a
 * caller testing "> 0" and a caller testing "== 1" would both compile.  Every
 * success below is asserted as the literal 1 -- never >= 0, != 0 or > 0, which
 * would accept a whole class of mutation.
 *
 * THE GUARD CHAIN, IN THE ORDER provnum_copy() EVALUATES IT:
 *
 *     wrong-type rejection        num.c:58-62
 *     empty-source shortcut       num.c:64-68    returns SUCCESS
 *     null-data rejection         num.c:70-73
 *     padding-strip loop          num.c:92-96
 *     oversize rejection          num.c:98-101
 *     null-destination rejection  num.c:105-108
 *     simple-case copy            num.c:110-132
 *     unsupported fallthrough     num.c:135
 *
 * Several of those guards are mutually satisfiable, so an input can satisfy
 * two at once and the answer is then decided by nothing but evaluation order.
 * test_get_precedence() exists for exactly those inputs: reordering the guard
 * block changes no line's reachability, so coverage cannot see it, yet it
 * silently changes what the API answers.
 *
 * *** USE OSSL_PARAM_INTEGER FOR EVERY NULL-DATA AND ZERO-SIZE FIXTURE ***
 *
 * Do not "tidy" the fixtures in test_get_null_and_empty() to
 * OSSL_PARAM_UNSIGNED_INTEGER.  paramsign() is called from the argument list
 * at num.c:148, so it runs BEFORE provnum_copy() validates anything, and at
 * num.c:25-26 it returns POSITIVE immediately for OSSL_PARAM_UNSIGNED_INTEGER
 * without ever reaching the source dereference at num.c:27.  An
 * unsigned-typed null-data fixture is therefore STRUCTURALLY INCAPABLE of
 * detecting a missing null check, however correct its expected return code
 * looks.  Both spellings are kept below, the signed one first and labelled,
 * because only one of them can see such a bug.
 *
 * CALL, STORE, THEN ASSERT.  C does not specify the order in which
 * function-call arguments are evaluated, so reading a destination inside the
 * same expression that calls the function writing it is a bug.
 * call_get_size_t() and call_get_int() make that structural: each performs the
 * call first, then captures the destination, the parameter's return_size and
 * whether the parameter's representation survived.  Nothing in this file
 * asserts anything but an already-captured value.
 *
 * Success cases assert the return code AND the exact destination value.  Error
 * cases assert the return code AND that the destination still holds the
 * sentinel it was seeded with, since "the output was not modified" is a real
 * part of the contract.  Every case asserts that the const OSSL_PARAM is
 * byte-identical across the call, which checks underneath the type system,
 * where a cast could have discarded the qualifier.
 *
 * Boundary values are DERIVED from sizeof(T) and CHAR_BIT through
 * param_util.h, never transcribed, and four assertions tie the derivations to
 * SIZE_MAX, SIZE_MAX / 2, INT_MAX and INT_MIN so a derivation bug cannot make
 * a case vacuous.  Byte layout comes from the same header, which reproduces
 * num.c's nativeendian() rather than assuming an order, so every expectation
 * holds on either endianness.  Boundaries come in PAIRS -- the largest value
 * that fits and the smallest that does not -- so an off-by-one in either
 * direction fails.
 *
 * MEMORY SAFETY HAS A DETERMINISTIC OBSERVABLE HERE TOO, in
 * test_get_guarded_boundaries().  Some plausible single-token defects in num.c
 * change no return code and no destination value for any input: their whole
 * effect is an access one byte outside an object, which an ordinary build
 * answers with whatever byte happens to be adjacent.  MEASURED: with the
 * zero-size half of paramsign()'s guard removed, every other case in this file
 * still passed.  That group therefore places fixtures flush against a
 * PROT_NONE page, so the same access becomes a fault on every run under the
 * mandated flagless command; param_util.h's protected-boundary oracle explains
 * the mechanism and why it cannot manufacture a failure.  It is compiled in
 * only where LIBPROV_TEST_GUARD_PAGES is defined -- tests/CMakeLists.txt
 * defines it for this target only where its guard-page capability probe proved
 * the whole mapping, process and resource-limit set the oracle needs -- so on a
 * host missing any of them this target is still registered and every other case
 * in the file is unaffected.
 *
 * Exactly one behaviour is deliberately NOT asserted, marked "CLASS C" in
 * test_get_edge_cases().  It is not a gap and must not be "completed" by
 * asserting the value the code currently emits.
 *
 * The getters dereference their `param` argument unconditionally at
 * num.c:147-148, so a null OSSL_PARAM * is undefined behaviour rather than a
 * documented error, and there is no fixture for it: undefined behaviour is not
 * a result a test may legitimately assert.
 *
 * OSSL_PARAM is a plain public struct, so every fixture is built by hand over
 * test-owned automatic storage through param_util.h.  No OSSL_PARAM_get_,
 * OSSL_PARAM_set_ or OSSL_PARAM_construct_ function is ever called -- those are
 * the libcrypto helpers libprov's provnum_ family replaces -- and
 * <openssl/params.h> is genuinely absent from this translation unit, prov/num.h
 * reaching only <openssl/core.h>.  Nothing here reads the environment, and no
 * case depends on another or on the order they run in, so this program is safe
 * under `ctest -j N`.  Where the protected-boundary oracle is compiled in the
 * program also maps pages and forks children: each child is waited for before
 * the next case starts, each case's fixture is seeded inside its own child, and
 * the one file any of it opens is /dev/null, in the single child whose fault is
 * expected, so that an expected diagnostic stays out of the log.
 */

/*
 * THE FEATURE-TEST LEVEL, AND IT HAS TO BE SET HERE.  A feature-test macro
 * decides which declarations the C library's headers make visible, so it is
 * only effective before the FIRST #include -- which is why this block sits
 * above them rather than beside the code that needs it.  _DEFAULT_SOURCE and
 * not a _POSIX_C_SOURCE level, because param_util.h's protected-boundary
 * oracle needs MAP_ANONYMOUS, which is a Linux and BSD extension rather than a
 * POSIX flag; tests/test_err_death.c sets _POSIX_C_SOURCE for its own harness
 * because everything that one uses IS POSIX.  MEASURED on this host: glibc
 * reveals all of it under a bare -std=c99 anyway, so this buys portability
 * rather than fixing anything here, and param_util.h fails the compile with a
 * diagnostic naming the cause if a C library does gate them.
 */
#ifdef LIBPROV_TEST_GUARD_PAGES
# if !defined(_DEFAULT_SOURCE)
#  define _DEFAULT_SOURCE 1
# endif
#endif

#include "testutil.h"
#include "param_util.h"
#include "prov/num.h"

#include <limits.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
 * EVERY FIXTURE GETS ITS OWN BUFFER, SIZED EXACTLY TO THE CASE, with the width
 * written as a constant expression over sizeof(size_t) or sizeof(int) rather
 * than as a number.  An access one byte outside an exactly-sized automatic
 * object lands outside a DISTINCT object, which is what lets the opt-in
 * -fsanitize=address configuration see it, while the same access inside one
 * larger shared buffer would be invisible -- and out-of-bounds access on these
 * very inputs is what num.c's memory-safety repairs removed.  Widening one of
 * these buffers, padding it, or hoisting several into a shared array would
 * quietly weaken that.
 *
 * It is not, however, the only mechanism, because it depends on a build flag
 * the mandated command does not pass: test_get_guarded_boundaries() places the
 * same shapes against a PROT_NONE page so the same accesses fault in an
 * ORDINARY build.  The two are complements -- exact sizing covers every case in
 * the file under the sanitizer, the guarded group covers the shapes that need
 * no flag at all.
 *
 * A per-case block also keeps each case independent, so the order they run in
 * is irrelevant.
 */

/*
 * Everything one provnum_get_size_t() call reveals, captured in the order the
 * call makes it available and asserted only afterwards.  `param_unchanged`
 * carries param_identical()'s verdict against a snapshot taken before the
 * call, and `return_size` is captured because the getters must NOT write it:
 * only the provnum_set_ half of implement_provnum() assigns return_size, at
 * num.c:166.
 */
struct size_t_result {
    int rc;
    size_t value;
    size_t return_size;
    int param_unchanged;
};

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
 * exercises the null-destination guard at num.c:105-108 and the empty-source
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
         * num.c:116-123 runs.  A padding offset of dest.size - src.size rather
         * than src.size would put the significant byte at dest[0] and start
         * the padding at dest[SZ - 1], leaving the seeded sentinel in between,
         * so a wrong offset is a wrong VALUE here and not merely an
         * out-of-bounds write.
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
         * this is the second D3 regression guard.  The contract is 65535; a
         * wrong padding offset leaves seeded sentinel bytes in the result.
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
         * num.c:92-96 runs zero times.
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
         * num.c:85-88 documents are satisfied and the strip loop at
         * num.c:92-96 discards exactly one byte.  What is left is a size_t
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
         * provnum_set_ half of implement_provnum() assigns it, at num.c:166;
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
        /*
         * The descriptor-identity assertion every other case makes, made here
         * too.  call_get_size_t() computes param_unchanged for every fixture,
         * so leaving it unasserted in one case would quietly narrow the
         * "the const OSSL_PARAM survived the call byte for byte" claim this
         * file's label guide states without qualification.  It is not a
         * duplicate of the return_size assertion above: return_size is one
         * member, while param_identical() compares the whole representation --
         * all five members and the padding between them.
         */
        TEST_ASSERT_INT_EQ("U[1]=05 return_size param", got.param_unchanged,
                           1);
        ret &= test;
    }

    return ret;
}

static int test_get_int_happy(void)
{
    int ret = 1, test;

    /*
     * The derived int edges, tied to <limits.h> exactly as the size_t ones
     * are above.  The second assertion also states this file's one
     * representational premise: that the bit pattern one past the largest
     * positive value denotes INT_MIN, which is two's complement.  num.c
     * presupposes it too -- num.c:85-86 says the padding byte its rules
     * compare, num.c:7's sign_t, "just so happens to have the 2's complement
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
         * reaches its dereference at num.c:27, finds the high bit set and
         * answers NEGATIVE, so the padding at num.c:121 fills the remaining
         * bytes with 0xFF and -1 comes out sign extended.
         *
         * THE PRIMARY D3 REGRESSION GUARD.  A padding offset of dest.size -
         * src.size lands the significant byte at dest[0] and starts the sign
         * padding at dest[IN - 1], leaving the bytes between them holding
         * whatever the destination held before -- so a single wrong offset
         * turns an ordinary one-byte conversion into a wrong number.
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
         * at the wrong offset and if it is written with the wrong fill byte.
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
         * every step, so the strip loop at num.c:92-96 runs until src.size
         * reaches dest.size exactly -- five iterations here -- and the copy
         * then needs no padding at all.
         *
         * This case is a FULL-STRIP assertion and deliberately not labelled a
         * D3 guard: because it strips to exactly sizeof(int), src.size ==
         * dest.size and the padding branch at num.c:116-123 never runs, so the
         * padding offset cannot affect it.  The narrow-source cases above are
         * what catch a wrong offset.
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
         * num.c:111-114: paramsign() short-circuits to POSITIVE at
         * num.c:25-26, so the padding is written with 0x00 rather than 0xFF
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
 * Width and signedness boundaries, asserted in PAIRS.
 *
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
         * the oversize test at num.c:98 must not fire on equality, which is
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
         * below it.  The first padding rule at num.c:93 fails at once, since
         * 0x01 is not the positive pad byte, so the loop breaks at full width
         * and num.c:98-101 answers PROVNUM_E_TOOBIG.
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
         * bit is exactly what the second padding rule at num.c:94-95
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
         * answers POSITIVE at num.c:27-29 and the destination is zero padded.
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
         * num.c:27 distinguishes the two halves of this pair, which makes it
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
         * is POSITIVE, so the second disjunct of num.c:114 holds and the
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
         * bit set the source is NEGATIVE, neither disjunct of num.c:114
         * holds, and control reaches the fallthrough at num.c:135.  This is
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
 * The padding-strip rules, and the one behaviour this file will not assert.
 *
 * num.c:85-88 documents both rules the strip loop applies to a source wider
 * than its destination:
 *
 *   (a) the most significant byte must equal the sign pad byte, which for
 *       num.c's sign_t at num.c:7 is 0xFF when negative and 0x00 when
 *       positive -- the two's complement padding values;
 *   (b) the high bit of the NEXT byte down must match the high bit of that
 *       same pad byte.
 *
 * A NAMING NOTE, because that citation does not read cleanly on its own.
 * num.c:85-88 states both rules in terms of a "srcsigned", and no identifier
 * of that name exists anywhere in the file.  What the loop actually compares
 * is src.sign, the struct numdesc member declared at num.c:39: rule (a) is
 * the test at num.c:93 and rule (b) the test at num.c:94-95.  The stale name
 * is recorded here rather than corrected there because num.c's diff is
 * deliberately confined to the three sanctioned memory-safety repairs -- the
 * same reason include/prov/num.h's silence on the success value is recorded
 * in this file's header instead of being fixed in the header itself.
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
         * num.c:85-88 specifies; no separate assertion is made for it, since
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
     * CLASS C -- A DELIBERATE NON-ASSERTION.  THIS IS NOT A GAP.
     *
     * The behaviour: provnum_get_int() given an OSSL_PARAM_UNSIGNED_INTEGER
     * source exactly sizeof(int) bytes wide with every bit set.  paramsign()
     * short-circuits to POSITIVE at num.c:25-26, the simple-case condition at
     * num.c:111-114 is satisfied, src.size == dest.size so the bytes are
     * copied verbatim, and the signed destination ends up holding a NEGATIVE
     * number even though the source was declared unsigned.
     *
     * Two readings of the contract are defensible and include/prov/num.h
     * settles neither:
     *
     *   (a) an unsigned value larger than INT_MAX does not fit a signed
     *       destination and should be refused as PROVNUM_E_TOOBIG, on the same
     *       principle by which a source one byte wider is refused;
     *
     *   (b) the source's byte width matches the destination's exactly, so
     *       nothing is lost or padded and the copy is legitimate; how the
     *       caller interprets a full-width bit pattern is the caller's
     *       business.
     *
     * NO ASSERTION IS MADE about this input, in either direction.  Pinning
     * whatever the code emits would enshrine one reading as the contract on no
     * authority, and asserting the other would fail against code that is not
     * known to be wrong.  Do NOT "complete" this by adding an assertion; if
     * the intended behaviour is ever settled, assert it and delete this
     * comment.  The related setter-side ambiguity is documented by
     * param_util.h at param_expect_zero_padded().
     */

    return ret;
}

/*
 * The type whitelist -- every data type that is not an integer is refused.
 *
 * num.c:58-62 admits OSSL_PARAM_INTEGER and OSSL_PARAM_UNSIGNED_INTEGER and
 * rejects everything else.  <openssl/core.h> defines exactly five other data
 * types, and all five are exercised below, individually, so a failure names
 * the type that slipped through.  Testing one type would leave the check
 * indistinguishable from a comparison against that single value.
 */
static int test_get_wrong_types(void)
{
    int ret = 1, test;
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
         * function: implement_provnum() at num.c:139-168 produces both from
         * one body, and num.c:171 instantiates this one with
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
 * Absent inputs: a null source buffer, an empty source, a null destination.
 *
 * *** THE FIXTURES BELOW MUST STAY OSSL_PARAM_INTEGER.  READ THIS FIRST. ***
 *
 * provnum_get_size_t() and provnum_get_int() both compute paramsign(param) in
 * the argument list at num.c:148, so paramsign() runs BEFORE provnum_copy()
 * has validated anything at all.  Inside it, num.c:25-26 returns POSITIVE the
 * moment the data type is OSSL_PARAM_UNSIGNED_INTEGER, and only a source of
 * any other type reaches the dereference at num.c:27 -- indexed with data_size
 * - 1, which for a size of zero wraps and reads before the buffer.
 *
 * The consequence is the reason for this warning: a null-data or zero-size
 * fixture typed OSSL_PARAM_UNSIGNED_INTEGER never drives execution past that
 * short circuit, so it CANNOT detect a missing guard, no matter how right its
 * expected return code looks.  The signed cases therefore come first, are
 * labelled, and are the ones that matter; an unsigned-typed null-data case is
 * kept as a companion, because PROVNUM_E_NULL is genuinely its documented
 * answer too, but it is not a substitute.  Retyping the signed cases to
 * unsigned would leave every assertion in this file passing and reopen the
 * hole.
 *
 * One thing these cases deliberately do NOT pin: the guard answers POSITIVE,
 * and nothing observable depends on that choice.  src.sign is read at exactly
 * four places -- the two strip rules at num.c:93 and num.c:94-95, the sign
 * clause at num.c:114 and the pad fill at num.c:121 -- and every input that
 * reaches the guard leaves provnum_copy() before any of them, a zero data_size
 * by the empty-source shortcut at num.c:64-68 and a null data pointer with a
 * non-zero size by the rejection at num.c:70-73.  The returned value is dead
 * on every path that can produce it, so no assertion could distinguish
 * POSITIVE from NEGATIVE and none is written; this is an equivalence, not a
 * gap.
 */
static int test_get_null_and_empty(void)
{
    int ret = 1, test;

    {
        /*
         * A null source with a signed type, into the signed destination: the
         * fixture that reaches paramsign()'s dereference.  The documented
         * answer is PROVNUM_E_NULL, from num.c:70-73.
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
         * shortcut at num.c:64-68 returns SUCCESS rather than an error, and it
         * zeroes the WHOLE destination on the way out at num.c:66 -- so an
         * empty number converts to 0 and the sentinel is gone.  A refactor
         * that turned an empty source into an error, or that stopped clearing
         * the destination, would break here.
         *
         * This is also the zero-size half of the pre-validation dereference:
         * with the guard at num.c:19-20 removed, paramsign() computes
         * data_size - 1, wraps, and reads the byte BEFORE this buffer.  The
         * buffer is a separate automatic object sized exactly to the fixture
         * precisely so that the opt-in sanitizer configuration can see that
         * read; test_get_guarded_boundaries() puts the same shape against a
         * PROT_NONE page, which catches it with no build flag at all.  MEASURED:
         * without that group, reintroducing the defect left this case -- and
         * every other case in the file -- passing.
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
         * big, so control reaches num.c:105-108 and PROVNUM_E_NULL comes back.
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
     * Null DESTINATION with a source made ENTIRELY of pad bytes.  These look
     * redundant beside the two cases above; they are not, and the reason is
     * not visible from the return codes alone.
     *
     * A null destination clamps the padding-strip loop's floor to one byte
     * (num.c:91).  When every source byte equals the sign pad byte both strip
     * rules hold at every position, so the loop walks the source all the way
     * down and stops at a single byte -- src.size > end is false once src.size
     * reaches 1 (num.c:92).  The oversize test at num.c:98 then sees the
     * stripped width, so even a source wider than the destination is not too
     * big, and the answer is PROVNUM_E_NULL from num.c:105-108.  The sign pad
     * byte is the type's two's-complement fill (num.c:7), so "all pad bytes"
     * means all 0x00 for a positive source and all 0xff for a negative one.
     *
     * These are the only inputs that pin the strip loop's FLOOR.  Relaxing the
     * bound at num.c:92 from > to >= lets the loop run one iteration too many
     * at src.size == 1, where rule (a) holds -- the byte equals the sign pad
     * -- so the || does not short-circuit and rule (b) indexes srcmsb +
     * srcmsb2lsb, one byte BEFORE the start of the source.  That relaxation
     * changes no return code and no destination value for any provnum_get_*
     * input, so it is observable only as an out-of-bounds read: hence every
     * buffer below is sized EXACTLY and none is shared.  Widening one, padding
     * it, or hoisting it into a shared array would hide the defect these cases
     * exist to expose, and the fixtures must stay OSSL_PARAM_INTEGER except
     * where an unsigned type is named explicitly.  Exact sizing makes that read
     * visible to the opt-in -fsanitize=address configuration;
     * test_get_guarded_boundaries() runs the same shape against a PROT_NONE
     * page, which makes it fault under the mandated flagless command too.
     */
    {
        /*
         * One byte, 0x00, signed.  paramsign() reads the byte at num.c:27,
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
         * One byte, 0xff, signed: paramsign() answers NEGATIVE (num.c:27),
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
         * paramsign() short-circuits to POSITIVE at num.c:25-26 without
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
         * the sign clause at num.c:114.  It does not get that far, because
         * the null-destination guard at num.c:105-108 comes first.  So this
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
         * the oversize test at num.c:98 never fires.  PROVNUM_E_TOOBIG
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
 * Sources wider than the destination -- when the extra bytes are padding and
 * when they are not.
 *
 * The boundary pairs above take the width edge one byte at a time.  This
 * group covers the rest of the strip loop's behaviour: a source whose extra
 * byte is plainly significant, a source whose extra bytes are all padding and
 * need SEVERAL iterations to remove, and the same rejection through the other
 * instantiation.  Between them they pin the loop's bound at num.c:92 from
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
         * PROVNUM_E_TOOBIG, from num.c:98-101.
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
 * PROVNUM_E_UNSUPPORTED, and the proof of where it cannot happen.  num.c:135
 * is the fallthrough taken when the simple-case condition at num.c:111-114
 * does not hold, and reaching it through the public API is narrower than it
 * looks.
 *
 * PROOF 1 -- provnum_get_int() can NEVER return PROVNUM_E_UNSUPPORTED.  The
 * condition's last clause is
 *
 *     (dest.data_type == OSSL_PARAM_INTEGER || src.sign == POSITIVE)
 *
 * and for provnum_get_int() the destination descriptor built at num.c:143-145
 * takes its data_type from the macro's DT parameter, which num.c:171
 * instantiates as OSSL_PARAM_INTEGER, so the first disjunct is ALWAYS true.  A
 * test cannot assert an unreachable return, so this group asserts the
 * COMPLEMENTARY fact: the very input that yields PROVNUM_E_UNSUPPORTED from
 * provnum_get_size_t() yields SUCCESS from provnum_get_int().  That makes the
 * exclusion evidence rather than assumption, and it fails if the instantiation
 * at num.c:171 is ever changed.
 *
 * PROOF 2 -- provnum_get_size_t() is the only reachable site.  num.c:170
 * instantiates it with OSSL_PARAM_UNSIGNED_INTEGER, so the first disjunct is
 * always false and the clause turns entirely on src.sign.  A source declared
 * OSSL_PARAM_INTEGER whose most significant bit is set makes paramsign()
 * answer NEGATIVE at num.c:27-28, and the fallthrough is taken.
 *
 * PROOF 3 -- the condition's other three clauses are UNSATISFIABLE through the
 * public API, so no test can cover them and none is attempted.  All four
 * numdesc initialisers -- num.c:143-145 and num.c:146-149 for the getters,
 * num.c:157-160 and num.c:161-163 for the setters -- set `endian` from the
 * same nativeendian() call, `limbsize` to 1 and `limbnailbits` to 0 for source
 * and destination alike, so dest.endian == src.endian, dest.limbsize == 1 and
 * dest.limbnailbits == 0 hold on every call that can be made.  Only editing
 * num.c could falsify one; they are named so the gap is a documented
 * consequence of the code's shape rather than an oversight here.
 *
 * PROOF 4 -- the second half of the strip-loop's floor clause is likewise
 * UNSATISFIABLE from a getter.  num.c:91 reads
 *
 *     size_t end = dest.data == NULL || dest.size == 0 ? 1 : dest.size;
 *
 * and the `dest.size == 0` disjunct can only change the result when dest.data
 * is non-null AND dest.size is zero.  The getter's destination descriptor at
 * num.c:143-145 takes its size from sizeof(T), which is never zero, and when
 * the destination pointer is null the first disjunct has already decided the
 * value.  Deleting the disjunct therefore leaves every getter answer and
 * destination byte unchanged, which makes it a semantically equivalent edit
 * with respect to THIS file rather than a coverage gap.  It is the setter's
 * descriptor at num.c:157-160 that takes its size from param->data_size and
 * can present zero capacity, so the disjunct is load-bearing there and its
 * reproducer belongs in the setter tests.
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
 * GUARD PRECEDENCE -- inputs that satisfy two guards at once.
 *
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
 *
 * THE FULL GUARD CHAIN, in evaluation order, so a reader can see at a glance
 * which pairs are covered and which are impossible to construct:
 *
 *     1  wrong type            num.c:58
 *     2  empty source          num.c:64
 *     3  null source data      num.c:70
 *     4  padding-strip loop    num.c:92-96   (not a guard; feeds 5)
 *     5  oversize              num.c:98
 *     6  null destination      num.c:105
 *     7  unsupported           num.c:135       (fallthrough)
 *
 * MANY CASES CARRY A CONTROL, and it is what separates a precedence assertion
 * from an ordinary error test.  A case is only about ORDER if the losing guard
 * would really have fired; otherwise it silently degenerates into a duplicate
 * of some single-guard case elsewhere in this file, and a reordering mutation
 * walks straight past it.  So the fixture is reused with exactly one field
 * changed -- the one that disarms the winner -- and the loser's own answer is
 * asserted.  Two assertions, one fixture, and the competition is demonstrated
 * rather than claimed in a comment.
 */
static int test_get_precedence(void)
{
    int ret = 1, test;

    {
        /*
         * WRONG TYPE (num.c:58) versus NULL DATA (num.c:70).  A source that is
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
         * WRONG TYPE (num.c:58) versus NULL DESTINATION (num.c:105).  A real
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
         * WRONG TYPE (num.c:58) versus EMPTY SOURCE (num.c:64) -- the two
         * ADJACENT guards, and so the pair a reordering is most likely to
         * disturb.  A source that is simultaneously the wrong kind of
         * parameter and declares no bytes: an OCTET_STRING with a real,
         * non-null buffer and data_size == 0.  The type check is first, so
         * PROVNUM_E_WRONG_TYPE wins and the destination is left alone.
         *
         * THE BUFFER MUST BE REAL, and that is the whole point of the case.
         * Passing data == NULL as well would put THREE guards in competition
         * and make the case a weaker restatement of "wrong type vs null data"
         * above; a genuine buffer with a zero size isolates exactly two.
         *
         * Getting this wrong is not hypothetical.  Hoisting the empty-source
         * shortcut above the type check leaves every other assertion in this
         * file passing -- no line changes reachability, so coverage is
         * identical -- while provnum_get_size_t() starts answering SUCCESS to
         * a caller who handed it an octet string, and zeroing that caller's
         * destination on the way out.  This case is the only thing that sees
         * it, which is why the control below proves the losing guard really
         * was armed rather than merely asserting that it was.
         */
        unsigned char src[sizeof(size_t) + 1];
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;
        int ok;

        ok = param_fill(src, sizeof src, (unsigned char)0xEEU);
        ok = param_build_empty(&param, OSSL_PARAM_OCTET_STRING, src) && ok;
        TEST_ASSERT_INT_EQ("prec: wrong type vs empty fixture", ok, 1);
        ret &= test;

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("prec: wrong type vs empty", got.rc,
                           PROVNUM_E_WRONG_TYPE);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("prec: wrong type vs empty untouched", got.value,
                            param_sentinel_size_t());
        ret &= test;
        TEST_ASSERT_INT_EQ("prec: wrong type vs empty param",
                           got.param_unchanged, 1);
        ret &= test;

        /*
         * The control, and what makes the case above a PRECEDENCE assertion
         * instead of one more wrong-type test.  Change the single field that
         * disables the winning guard -- the data type -- and leave everything
         * else exactly as it was: the empty-source shortcut now fires, returns
         * success and zeroes the destination.  So the shortcut was reachable
         * for this descriptor all along and lost only because the type check
         * runs first.
         */
        dest = param_sentinel_size_t();
        ok = param_build_empty(&param, OSSL_PARAM_INTEGER, src);
        TEST_ASSERT_INT_EQ("prec: wrong type vs empty control fixture", ok, 1);
        ret &= test;

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("prec: wrong type vs empty control rc", got.rc, 1);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("prec: wrong type vs empty control zeroed",
                            got.value, (size_t)0);
        ret &= test;
        TEST_ASSERT_INT_EQ("prec: wrong type vs empty control param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * The same competition at the OTHER instantiation of
         * implement_provnum().  Worth repeating here, where most mirrors are
         * not, because the losing guard's behaviour is destination-width
         * dependent: the empty-source shortcut memsets dest.size bytes
         * (num.c:65-66), so a reordering writes sizeof(int) bytes here and
         * sizeof(size_t) bytes above.  Asserting both widths is what stops the
         * fix for one instantiation from silently leaving the other wrong.
         */
        unsigned char src[sizeof(int) + 1];
        OSSL_PARAM param;
        int dest = param_sentinel_int();
        struct int_result got;
        int ok;

        ok = param_fill(src, sizeof src, (unsigned char)0xEEU);
        ok = param_build_empty(&param, OSSL_PARAM_UTF8_STRING, src) && ok;
        TEST_ASSERT_INT_EQ("prec: wrong type vs empty ->int fixture", ok, 1);
        ret &= test;

        got = call_get_int(&dest, &param);
        TEST_ASSERT_INT_EQ("prec: wrong type vs empty ->int", got.rc,
                           PROVNUM_E_WRONG_TYPE);
        ret &= test;
        TEST_ASSERT_INT_EQ("prec: wrong type vs empty ->int untouched",
                           got.value, param_sentinel_int());
        ret &= test;
        TEST_ASSERT_INT_EQ("prec: wrong type vs empty ->int param",
                           got.param_unchanged, 1);
        ret &= test;

        dest = param_sentinel_int();
        ok = param_build_empty(&param, OSSL_PARAM_INTEGER, src);
        TEST_ASSERT_INT_EQ("prec: wrong type vs empty ->int control fixture",
                           ok, 1);
        ret &= test;

        got = call_get_int(&dest, &param);
        TEST_ASSERT_INT_EQ("prec: wrong type vs empty ->int control rc",
                           got.rc, 1);
        ret &= test;
        TEST_ASSERT_INT_EQ("prec: wrong type vs empty ->int control zeroed",
                           got.value, 0);
        ret &= test;
        TEST_ASSERT_INT_EQ("prec: wrong type vs empty ->int control param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * WRONG TYPE (num.c:58) versus OVERSIZE (num.c:98).  The type check
         * is the first guard of all and the oversize test is the fifth, with
         * the padding-strip loop in between, so PROVNUM_E_WRONG_TYPE wins over
         * the widest possible span of the guard chain.
         *
         * The source must be NON-STRIPPABLE or the competition evaporates: a
         * source whose extra bytes are padding would be reduced to the
         * destination's width by the loop at num.c:92-96 and never reach
         * num.c:98 as oversized at all.  MSB-first
         *
         *     01 00 00 .. 00
         *
         * fails rule (a) on the first iteration -- 0x01 is not the positive
         * pad byte -- so the loop breaks immediately at full width.
         */
        unsigned char src[sizeof(size_t) + 1];
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;
        int ok;

        ok = param_expect_pattern(src, sizeof src, (uintmax_t)0,
                                  sizeof(size_t), (unsigned char)0x01U);
        param_build(&param, OSSL_PARAM_OCTET_STRING, src, sizeof src);
        TEST_ASSERT_INT_EQ("prec: wrong type vs oversize fixture", ok, 1);
        ret &= test;

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("prec: wrong type vs oversize", got.rc,
                           PROVNUM_E_WRONG_TYPE);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("prec: wrong type vs oversize untouched",
                            got.value, param_sentinel_size_t());
        ret &= test;
        TEST_ASSERT_INT_EQ("prec: wrong type vs oversize param",
                           got.param_unchanged, 1);
        ret &= test;

        /*
         * The control: the identical buffer, identical size, integer type.
         * PROVNUM_E_TOOBIG -- so this descriptor really is oversized and
         * really does resist stripping, and the case above is a precedence
         * assertion rather than a restatement of the wrong-type group.
         */
        dest = param_sentinel_size_t();
        param_build_unsigned(&param, src, sizeof src);

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("prec: wrong type vs oversize control rc", got.rc,
                           PROVNUM_E_TOOBIG);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("prec: wrong type vs oversize control untouched",
                            got.value, param_sentinel_size_t());
        ret &= test;
        TEST_ASSERT_INT_EQ("prec: wrong type vs oversize control param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * The same competition at provnum_get_int()'s width.  Mirrored because
         * the losing guard is the one guard whose outcome depends on the
         * destination: num.c:98 compares against dest.size, so "oversized"
         * means five bytes here and nine bytes above, and only a fixture built
         * from sizeof(int) can put the int instantiation's oversize test into
         * competition at all.
         */
        unsigned char src[sizeof(int) + 1];
        OSSL_PARAM param;
        int dest = param_sentinel_int();
        struct int_result got;
        int ok;

        ok = param_expect_pattern(src, sizeof src, (uintmax_t)0, sizeof(int),
                                  (unsigned char)0x01U);
        param_build(&param, OSSL_PARAM_REAL, src, sizeof src);
        TEST_ASSERT_INT_EQ("prec: wrong type vs oversize ->int fixture", ok,
                           1);
        ret &= test;

        got = call_get_int(&dest, &param);
        TEST_ASSERT_INT_EQ("prec: wrong type vs oversize ->int", got.rc,
                           PROVNUM_E_WRONG_TYPE);
        ret &= test;
        TEST_ASSERT_INT_EQ("prec: wrong type vs oversize ->int untouched",
                           got.value, param_sentinel_int());
        ret &= test;
        TEST_ASSERT_INT_EQ("prec: wrong type vs oversize ->int param",
                           got.param_unchanged, 1);
        ret &= test;

        dest = param_sentinel_int();
        param_build_integer(&param, src, sizeof src);

        got = call_get_int(&dest, &param);
        TEST_ASSERT_INT_EQ("prec: wrong type vs oversize ->int control rc",
                           got.rc, PROVNUM_E_TOOBIG);
        ret &= test;
        TEST_ASSERT_INT_EQ("prec: wrong type vs oversize ->int control"
                           " untouched", got.value, param_sentinel_int());
        ret &= test;
        TEST_ASSERT_INT_EQ("prec: wrong type vs oversize ->int control param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * EMPTY SOURCE (num.c:64) versus NULL DESTINATION (num.c:105), and the
         * most counter-intuitive answer in the whole contract: SUCCESS.  The
         * empty-source shortcut returns before the destination is ever looked
         * at, and it is careful to skip its memset when there is no
         * destination (num.c:65), so converting an empty number into nowhere
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
         * EMPTY SOURCE (num.c:64) versus NULL DATA (num.c:70).  Both hold at
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
         * NULL DATA (num.c:70) versus OVERSIZE (num.c:98).  A source that
         * declares more bytes than the destination can hold and has no buffer
         * to read them from.  The null-data guard is third and the oversize
         * test fifth, so PROVNUM_E_NULL wins -- and it has to, because the
         * guard the ordering protects is not a preference but a dereference:
         * the padding-strip loop between them indexes src.data on its first
         * iteration (num.c:93-94), so a reordering does not answer -2, it
         * reads through a null pointer.
         *
         * THE TYPE MUST BE OSSL_PARAM_INTEGER, NEVER THE UNSIGNED TYPE.
         * paramsign() returns POSITIVE for an unsigned source before it looks
         * at anything (num.c:27), so an unsigned fixture never drives
         * execution into the branch that indexes the buffer and would be blind
         * to the whole null-dereference class.  With the signed type this case
         * also exercises the pre-validation guard at the head of paramsign()
         * (num.c:19-20), which is the only reason the call returns a code at
         * all rather than faulting before provnum_copy() is even entered.
         */
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;

        param_build_null_data(&param, OSSL_PARAM_INTEGER, sizeof(size_t) + 1);

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("prec: null data vs oversize", got.rc,
                           PROVNUM_E_NULL);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("prec: null data vs oversize untouched", got.value,
                            param_sentinel_size_t());
        ret &= test;
        TEST_ASSERT_INT_EQ("prec: null data vs oversize param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * The control for the case above, and it needs its own block because
         * the field that has to change is the data pointer.  Same declared
         * width, same integer type, but a real non-strippable buffer behind
         * it: PROVNUM_E_TOOBIG.  So the oversize test was genuinely reachable
         * for a source of this width and lost only to the earlier null-data
         * guard.
         */
        unsigned char src[sizeof(size_t) + 1];
        OSSL_PARAM param;
        size_t dest = param_sentinel_size_t();
        struct size_t_result got;
        int ok;

        ok = param_expect_pattern(src, sizeof src, (uintmax_t)0,
                                  sizeof(size_t), (unsigned char)0x01U);
        param_build_integer(&param, src, sizeof src);
        TEST_ASSERT_INT_EQ("prec: null data vs oversize control fixture", ok,
                           1);
        ret &= test;

        got = call_get_size_t(&dest, &param);
        TEST_ASSERT_INT_EQ("prec: null data vs oversize control rc", got.rc,
                           PROVNUM_E_TOOBIG);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("prec: null data vs oversize control untouched",
                            got.value, param_sentinel_size_t());
        ret &= test;
        TEST_ASSERT_INT_EQ("prec: null data vs oversize control param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * The same competition at provnum_get_int()'s width, for the reason
         * the wrong-type-versus-oversize mirror gives: "oversized" is defined
         * against dest.size, so five declared bytes is what puts the int
         * instantiation's oversize test in competition, and nine is what puts
         * the size_t one there.  Both instantiations must answer
         * PROVNUM_E_NULL.
         */
        OSSL_PARAM param;
        int dest = param_sentinel_int();
        struct int_result got;

        param_build_null_data(&param, OSSL_PARAM_INTEGER, sizeof(int) + 1);

        got = call_get_int(&dest, &param);
        TEST_ASSERT_INT_EQ("prec: null data vs oversize ->int", got.rc,
                           PROVNUM_E_NULL);
        ret &= test;
        TEST_ASSERT_INT_EQ("prec: null data vs oversize ->int untouched",
                           got.value, param_sentinel_int());
        ret &= test;
        TEST_ASSERT_INT_EQ("prec: null data vs oversize ->int param",
                           got.param_unchanged, 1);
        ret &= test;
    }

    {
        /*
         * OVERSIZE (num.c:98) versus NULL DESTINATION (num.c:105).  The
         * oversize test is evaluated first, so PROVNUM_E_TOOBIG wins.
         *
         * The fixture has to be built with care, and the reason is worth
         * recording.  A null destination lowers the strip loop's floor from
         * dest.size to 1 (num.c:91), so a source whose extra bytes are
         * padding would be stripped all the way down to one byte, pass the
         * oversize test and come back PROVNUM_E_NULL -- which is exactly what
         * the one-byte case in test_get_null_and_empty() shows.  This source
         * therefore has to be genuinely non-strippable: a 0x01 on top fails
         * rule (a) immediately, the loop breaks at full width, and the source
         * is still wider than the destination when num.c:98 tests it.
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
         * OVERSIZE (num.c:98) versus the UNSUPPORTED FALLTHROUGH (num.c:135).
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
         * num.c:98 and the oversize answer is the one that can be observed.
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
 * The parameter survives, member by member.  Every case above already asserts
 * param_identical(), which compares the whole representation; restating it one
 * member at a time NAMES THE MEMBER that moved, and makes one expectation
 * explicit and greppable: A GETTER MUST NOT WRITE return_size.  Only the
 * provnum_set_ half of implement_provnum() assigns it, at num.c:166, so
 * folding the two halves of the macro together would give the getters that
 * assignment and break a caller's buffer sizing with nothing a compiler could
 * flag.
 *
 * This group also asserts the invariant no other group can: THE SOURCE BYTES
 * ARE NOT MODIFIED.  param_identical() compares the descriptor, not the buffer
 * it points at, so a conversion that wrote through `data` would leave every
 * other assertion in this file passing while corrupting the caller's number.
 * The buffer is copied aside before the call and compared byte for byte after.
 */
static int test_get_error_invariants(void)
{
    int ret = 1, test;

    {
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
        /*
         * And the whole representation, once the members have been named.  The
         * two are not redundant: the member assertions say WHICH field moved,
         * while this one also covers the padding between data_type and data,
         * which no member assertion can reach.  Naming both is what makes a
         * failure diagnosable without narrowing what is checked.
         */
        TEST_ASSERT_INT_EQ("inv success: param representation",
                           got.param_unchanged, 1);
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
        TEST_ASSERT_INT_EQ("inv toobig: param representation",
                           got.param_unchanged, 1);
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
        TEST_ASSERT_INT_EQ("inv null: param representation",
                           got.param_unchanged, 1);
        ret &= test;
    }

    return ret;
}

#ifdef LIBPROV_TEST_GUARD_PAGES
/*
 * ===========================================================================
 * THE SAME SHAPES, WITH A HARDWARE BOUNDS CHECK
 * ===========================================================================
 * Three of num.c's guards exist only to keep an index inside its buffer, and
 * removing any of them changes NO return code and NO destination value for any
 * input a getter accepts.  Every other group in this file would keep passing:
 *
 *   - dropping "|| param->data_size == 0" from paramsign()'s guard
 *     (num.c:19-20) makes it compute data_size - 1, wrap, and read the byte
 *     before the source.  MEASURED: with that defect reintroduced, every
 *     target of the suite as it then stood -- the eight that predate this
 *     group -- stayed green; with this group in place it is caught here by
 *     name, as a SIGSEGV against the protected page.
 *   - relaxing the padding-strip loop's bound at num.c:92 from > to >= lets
 *     one extra iteration evaluate rule (b) at srcmsb + srcmsb2lsb, one step
 *     beyond the most significant end of the source.
 *   - restoring num.c:119's padding offset to dest.size - src.size writes past
 *     the end of a destination narrower than twice the source.
 *
 * So each fixture below is placed FLUSH AGAINST A PROT_NONE PAGE on the side
 * the over-run would go, which turns that access into a fault on every run with
 * no build flag: param_util.h's protected-boundary oracle owns the mechanism and
 * explains why it cannot manufacture a failure.  The fixture runs in a forked
 * child so a fault is reported as a named assertion failure rather than killing
 * this program, and the parent asserts BOTH that the child completed normally
 * AND that it observed exactly the documented result -- these are the same
 * contracts the unguarded groups assert, re-asserted where a stray byte is
 * fatal, not a weaker substitute for them.
 *
 * WHICH SIDE IS "THE OVER-RUN SIDE" DEPENDS ON BYTE ORDER, and
 * param_guard_at_msb_edge() is what keeps that decision in one place: a source
 * goes against `low` on a little-endian host and against `high` on a big-endian
 * one, because num.c's srcmsb arithmetic steps downward in the first case and
 * upward in the second.  Hard-coding either would make these cases vacuous on
 * the other kind of host.
 */

# include <stdio.h>

/*
 * Compose "guard <case>: <property>", so one failing line names both.  The
 * suite's established idiom -- tests/test_err_handle.c, tests/test_err_guards.c
 * and tests/test_err_alloc.c each have one of these.  Given a nonzero capacity
 * snprintf() truncates rather than overruns, and its result is not consulted
 * because a truncated label is still a usable one: the assertion prints its own
 * file and line, which locates the case exactly.
 */
# define GUARD_LABEL_MAX 96

static const char *guard_label(char *buffer, size_t capacity,
                               const char *casename, const char *property)
{
    if (buffer == NULL || capacity == 0)
        return "guard: <no label buffer>";

    snprintf(buffer, capacity, "guard %s: %s", casename, property);
    return buffer;
}

/*
 * How a guarded child ended, asserted as three separate properties because they
 * fail for three different reasons.  `error` means the HARNESS broke -- fork()
 * or waitpid() itself failed -- and says nothing about num.c.  `signo` names the
 * signal that killed the child, which is the whole diagnosis when a guard page
 * was touched.  `completed` is the verdict every case below is stated in terms
 * of.
 *
 * `completed` deliberately means "exited normally with status 0" rather than
 * "was not signalled": under the opt-in -fsanitize=address configuration a fault
 * becomes a report and a non-zero exit status instead of a signal, and the
 * predicate has to mean the same thing in both builds.  `signo` is asserted only
 * here, for cases that must complete, and never for the self-test, for the same
 * reason.
 */
static int guard_verdict_completed(const char *casename,
                                   const struct param_guard_verdict *verdict)
{
    char label[GUARD_LABEL_MAX];
    int ret = 1, test;

    TEST_ASSERT_INT_EQ(guard_label(label, sizeof label, casename, "harness"),
                       verdict->error, 0);
    ret &= test;
    TEST_ASSERT_INT_EQ(guard_label(label, sizeof label, casename,
                                   "killed by signal"),
                       verdict->signo, 0);
    ret &= test;
    TEST_ASSERT_INT_EQ(guard_label(label, sizeof label, casename,
                                   "completed normally"),
                       verdict->completed, 1);
    ret &= test;

    return ret;
}

/*
 * ONE BODY PER SHAPE.  A body runs in the forked child, so it must not assert
 * and must not print -- the parent owns both -- and it may touch nothing outside
 * the writable page it is handed.  Each seeds its own fixture INSIDE the child
 * rather than relying on the parent to have done it: the mapping is MAP_PRIVATE,
 * so a child's writes are invisible to the parent and to every later child,
 * which is exactly what keeps these cases independent of one another and of the
 * order they run in.
 *
 * A body that cannot build its fixture records PARAM_GUARD_RC_UNBUILT, which is
 * none of the five documented return codes, so the parent's exact-code assertion
 * fails naming the cause instead of the case quietly degrading into a different,
 * passing one.
 *
 * THAT CHECK COMES FIRST, AND IT INCLUDES THE RECORD'S CAPACITY.  Every body
 * that hands bytes back copies a NATIVE width -- 1, sizeof(int) or
 * sizeof(size_t) here -- into a record whose `bytes` array is sized by an
 * expression in param_util.h, so "it fits" is a property of that expression
 * rather than a guarantee of the language.  param_guard_record_fits() is
 * therefore consulted BEFORE the fixture is written and before any copy, not
 * after: a body that found out afterwards would have found out by overrunning a
 * shared mapping.  On every ABI this suite compiles for the answer is yes; the
 * point of asking is that a fixture which ever outgrew the record would be
 * refused instead of writing past it.
 */

/*
 * AN EMPTY SOURCE AT THE OVER-RUN EDGE: a real buffer address, a declared size
 * of zero, and OSSL_PARAM_INTEGER so paramsign() does not short-circuit at
 * num.c:25-26.  A width of zero is the right request of
 * param_guard_at_msb_edge(): an empty source still has an address, and that
 * address is the one whose over-run byte must be protected.  Without num.c's
 * zero-size guard, paramsign() reads it; with the guard, the empty-source
 * shortcut at num.c:64-68 returns success and zeroes the whole destination.
 */
static void guard_body_empty_source(struct param_guard_record *record,
                                    const struct param_guard *guard)
{
    unsigned char *src = param_guard_at_msb_edge(guard, 0);
    OSSL_PARAM param;
    OSSL_PARAM snapshot;
    size_t dest = param_sentinel_size_t();

    if (src == NULL || !param_build_empty(&param, OSSL_PARAM_INTEGER, src)) {
        record->rc = PARAM_GUARD_RC_UNBUILT;
        return;
    }

    param_snapshot(&snapshot, &param);
    record->rc = provnum_get_size_t(&dest, &param);
    record->uvalue = dest;
    record->return_size = param.return_size;
    record->param_unchanged = param_identical(&param, &snapshot);
}

/*
 * A NULL SOURCE BUFFER with a non-zero declared size, again signed so it reaches
 * past paramsign()'s short circuit.  No guard page is involved -- the address
 * the other half of the same missing guard would read is near zero, which the
 * hardware already refuses -- but the fork harness is what turns that refusal
 * into a named failure of this case rather than a dead test binary, so it
 * belongs here beside its twin.  The documented answer is PROVNUM_E_NULL from
 * num.c:70-73, with the destination untouched.
 */
static void guard_body_null_data(struct param_guard_record *record,
                                 const struct param_guard *guard)
{
    OSSL_PARAM param;
    OSSL_PARAM snapshot;
    size_t dest = param_sentinel_size_t();

    (void)guard;

    param_build_null_data(&param, OSSL_PARAM_INTEGER, sizeof(size_t));
    param_snapshot(&snapshot, &param);
    record->rc = provnum_get_size_t(&dest, &param);
    record->uvalue = dest;
    record->return_size = param.return_size;
    record->param_unchanged = param_identical(&param, &snapshot);
}

/*
 * THE PADDING-STRIP LOOP'S FLOOR.  A null destination clamps the floor to one
 * byte (num.c:91), and a one-byte source made entirely of the sign pad satisfies
 * rule (a) at that floor, so the loop's bound at num.c:92 is the only thing
 * stopping it: with > the loop does not run, with >= it runs once and rule (b)
 * indexes one step beyond the most significant byte.  The documented answer is
 * PROVNUM_E_NULL either way, which is precisely why no ordinary assertion can
 * tell them apart.  Both pad bytes are exercised -- 0x00 for a positive source
 * and 0xff for a negative one, num.c:7's two sign_t values -- because the rule
 * compares against whichever one paramsign() chose.
 */
static void guard_strip_floor(struct param_guard_record *record,
                              const struct param_guard *guard,
                              unsigned char pad)
{
    unsigned char *src = param_guard_at_msb_edge(guard, 1);
    OSSL_PARAM param;
    OSSL_PARAM snapshot;

    if (src == NULL || !param_guard_record_fits((size_t)1)) {
        record->rc = PARAM_GUARD_RC_UNBUILT;
        return;
    }

    src[0] = pad;
    param_build_integer(&param, src, (size_t)1);
    param_snapshot(&snapshot, &param);
    record->rc = provnum_get_size_t(NULL, &param);
    record->return_size = param.return_size;
    record->param_unchanged = param_identical(&param, &snapshot);
    record->nbytes = 1;
    record->bytes[0] = src[0];
}

static void guard_body_strip_floor_positive(struct param_guard_record *record,
                                            const struct param_guard *guard)
{
    guard_strip_floor(record, guard, (unsigned char)0x00U);
}

static void guard_body_strip_floor_negative(struct param_guard_record *record,
                                            const struct param_guard *guard)
{
    guard_strip_floor(record, guard, (unsigned char)0xFFU);
}

/*
 * NOTHING IS READ PAST THE END OF THE SOURCE.  A full-width source neither
 * enters the strip loop -- src.size > end is false when the two are equal -- nor
 * needs padding, so the only reads are paramsign()'s at the most significant
 * byte and the copy's at num.c:128-130.  Placed flush against `high`, this pins
 * both offsets: mis-deriving srcstart at num.c:126 as srcmsb on a little-endian
 * host, or copying one byte too many, reads into the protected page.  The value
 * is the largest that fits with the sign bit clear, so the source is positive
 * and provnum_get_size_t()'s unsigned destination accepts it (num.c:114).
 */
static void guard_body_source_high_edge(struct param_guard_record *record,
                                        const struct param_guard *guard)
{
    const size_t width = sizeof(size_t);
    unsigned char *src = param_guard_at_high(guard, width);
    OSSL_PARAM param;
    OSSL_PARAM snapshot;
    size_t dest = param_sentinel_size_t();

    /*
     * The capacity question precedes the fixture deliberately: || short
     * circuits, so a record too small to carry `width` bytes refuses the case
     * without the source ever being written, let alone copied back.
     */
    if (src == NULL
        || !param_guard_record_fits(width)
        || !param_put_host_order(src, width, param_max_signed_in(width))) {
        record->rc = PARAM_GUARD_RC_UNBUILT;
        return;
    }

    param_build_integer(&param, src, width);
    param_snapshot(&snapshot, &param);
    record->rc = provnum_get_size_t(&dest, &param);
    record->uvalue = dest;
    record->return_size = param.return_size;
    record->param_unchanged = param_identical(&param, &snapshot);
    record->nbytes = width;
    memcpy(record->bytes, src, width);
}

/*
 * A NATIVE DESTINATION AGAINST AN EDGE.  A one-byte source into an int leaves
 * sizeof(int) - 1 bytes to pad, which is the shape num.c:119's offset decides:
 * src.size puts the padding at [1, 4) and the old dest.size - src.size puts it
 * at [3, 6), two bytes past the end.  Against `high` that is a fault; against
 * `low` the same case bounds the other side, pinning that a correct conversion
 * writes nothing below the destination either.
 *
 * The destination is read back with memcpy() rather than through an int lvalue
 * over the mapping: the mapping has no declared type, the library filled it
 * through unsigned char lvalues, and copying its bytes into a real int object is
 * well defined whatever effective type those stores gave it.  The alignment of
 * the placement is asserted by the caller before either case runs.
 */
static void guard_dest_int(struct param_guard_record *record,
                           unsigned char *dest, unsigned char srcbyte)
{
    unsigned char src[1];
    OSSL_PARAM param;
    OSSL_PARAM snapshot;
    int value = 0;

    if (dest == NULL
        || !param_guard_record_fits(sizeof(int))
        || !param_fill_sentinel(dest, sizeof(int))) {
        record->rc = PARAM_GUARD_RC_UNBUILT;
        return;
    }

    src[0] = srcbyte;
    param_build_integer(&param, src, sizeof src);
    param_snapshot(&snapshot, &param);
    record->rc = provnum_get_int((int *)(void *)dest, &param);

    memcpy(&value, dest, sizeof value);
    record->ivalue = value;
    record->return_size = param.return_size;
    record->param_unchanged = param_identical(&param, &snapshot);
    record->nbytes = sizeof(int);
    memcpy(record->bytes, dest, sizeof(int));
}

static void guard_body_dest_high_edge(struct param_guard_record *record,
                                      const struct param_guard *guard)
{
    guard_dest_int(record, param_guard_at_high(guard, sizeof(int)),
                   (unsigned char)0xFFU);
}

static void guard_body_dest_low_edge(struct param_guard_record *record,
                                     const struct param_guard *guard)
{
    guard_dest_int(record, param_guard_at_low(guard, sizeof(int)),
                   (unsigned char)0x05U);
}

static int test_get_guarded_boundaries(void)
{
    struct param_guard guard;
    struct param_guard_record *record;
    struct param_guard_verdict verdict;
    int ret = 1, test;

    /*
     * CAPACITY FIRST, AND BLOCKING.  The bodies below consult
     * param_guard_record_fits() before they copy, which keeps the CHILD inside
     * the shared record; these two assertions keep the PARENT inside it as well,
     * because the byte comparisons further down read sizeof(size_t) and
     * sizeof(int) bytes out of `record->bytes` to compare them.  Both are native
     * widths, so "they fit" is a property of the expression param_util.h derives
     * PARAM_GUARD_BYTES from rather than a guarantee of the language.
     *
     * It returns rather than continuing, for the same reason the bodies refuse
     * rather than truncate: a group that carried on would perform the very
     * out-of-bounds read it just reported.  It returns BEFORE the mapping and
     * the record are opened, so nothing is owed to cleanup, and the assertions
     * make the run fail loudly instead of quietly losing the group.  On every
     * ABI this suite compiles for both hold.
     */
    TEST_ASSERT_INT_EQ("guard setup: size_t fixture fits the record",
                       param_guard_record_fits(sizeof(size_t)), 1);
    ret &= test;
    TEST_ASSERT_INT_EQ("guard setup: int fixture fits the record",
                       param_guard_record_fits(sizeof(int)), 1);
    ret &= test;
    if (!param_guard_record_fits(sizeof(size_t))
        || !param_guard_record_fits(sizeof(int)))
        return 0;

    /*
     * The mapping and the shared record are asserted, not probed: a registered
     * target must not turn into a vacuous pass because mmap() refused.  Both are
     * released before every return below, including the early ones.
     */
    TEST_ASSERT_INT_EQ("guard setup: mapping established",
                       param_guard_open(&guard), 1);
    ret &= test;
    if (guard.low == NULL)
        return 0;

    record = param_guard_record_open();
    TEST_ASSERT_PTR_NOT_NULL("guard setup: shared record", record);
    ret &= test;
    if (record == NULL) {
        param_guard_close(&guard);
        return 0;
    }

    /*
     * THE SELF-TEST, AND IT RUNS FIRST.  It reads the byte immediately below the
     * writable page, which the protection must make fatal.  A run in which THAT
     * completes is a run in which the guard pages were not armed, and every
     * "completed normally" verdict below would be vacuous -- so it is asserted
     * as completed == 0, and nothing more: which signal, or whether a sanitizer
     * converted the fault into an exit status instead, is no part of the claim.
     */
    verdict = param_guard_run(param_guard_body_self_test, record, &guard);
    TEST_ASSERT_INT_EQ("guard selftest: harness", verdict.error, 0);
    ret &= test;
    TEST_ASSERT_INT_EQ("guard selftest: protection armed", verdict.completed, 0);
    ret &= test;

    {
        verdict = param_guard_run(guard_body_empty_source, record, &guard);
        ret &= guard_verdict_completed("empty source", &verdict);
        TEST_ASSERT_INT_EQ("guard empty source: rc", record->rc, 1);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("guard empty source: value", record->uvalue,
                            (size_t)0);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("guard empty source: return_size not written",
                            record->return_size, (size_t)0);
        ret &= test;
        TEST_ASSERT_INT_EQ("guard empty source: param", record->param_unchanged,
                           1);
        ret &= test;
    }

    {
        verdict = param_guard_run(guard_body_null_data, record, &guard);
        ret &= guard_verdict_completed("null data", &verdict);
        TEST_ASSERT_INT_EQ("guard null data: rc", record->rc, PROVNUM_E_NULL);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("guard null data: destination untouched",
                            record->uvalue, param_sentinel_size_t());
        ret &= test;
        TEST_ASSERT_SIZE_EQ("guard null data: return_size not written",
                            record->return_size, (size_t)0);
        ret &= test;
        TEST_ASSERT_INT_EQ("guard null data: param", record->param_unchanged, 1);
        ret &= test;
    }

    {
        verdict = param_guard_run(guard_body_strip_floor_positive, record,
                                  &guard);
        ret &= guard_verdict_completed("strip floor 0x00", &verdict);
        TEST_ASSERT_INT_EQ("guard strip floor 0x00: rc", record->rc,
                           PROVNUM_E_NULL);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("guard strip floor 0x00: bytes recorded",
                            record->nbytes, (size_t)1);
        ret &= test;
        TEST_ASSERT_UINT_EQ("guard strip floor 0x00: source byte",
                            record->bytes[0], 0x00U);
        ret &= test;
        TEST_ASSERT_INT_EQ("guard strip floor 0x00: param",
                           record->param_unchanged, 1);
        ret &= test;
    }

    {
        verdict = param_guard_run(guard_body_strip_floor_negative, record,
                                  &guard);
        ret &= guard_verdict_completed("strip floor 0xff", &verdict);
        TEST_ASSERT_INT_EQ("guard strip floor 0xff: rc", record->rc,
                           PROVNUM_E_NULL);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("guard strip floor 0xff: bytes recorded",
                            record->nbytes, (size_t)1);
        ret &= test;
        TEST_ASSERT_UINT_EQ("guard strip floor 0xff: source byte",
                            record->bytes[0], 0xFFU);
        ret &= test;
        TEST_ASSERT_INT_EQ("guard strip floor 0xff: param",
                           record->param_unchanged, 1);
        ret &= test;
    }

    {
        unsigned char expected[sizeof(size_t)];
        int ok;

        ok = param_put_host_order(expected, sizeof expected,
                                  param_max_signed_in(sizeof(size_t)));
        TEST_ASSERT_INT_EQ("guard source high edge: expectation", ok, 1);
        ret &= test;

        verdict = param_guard_run(guard_body_source_high_edge, record, &guard);
        ret &= guard_verdict_completed("source high edge", &verdict);
        TEST_ASSERT_INT_EQ("guard source high edge: rc", record->rc, 1);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("guard source high edge: value", record->uvalue,
                            (size_t)param_max_signed_in(sizeof(size_t)));
        ret &= test;
        TEST_ASSERT_SIZE_EQ("guard source high edge: bytes recorded",
                            record->nbytes, sizeof expected);
        ret &= test;
        TEST_ASSERT_MEM_EQ("guard source high edge: source bytes",
                           record->bytes, expected, sizeof expected);
        ret &= test;
        TEST_ASSERT_INT_EQ("guard source high edge: param",
                           record->param_unchanged, 1);
        ret &= test;
    }

    TEST_ASSERT_INT_EQ("guard native destination: alignment expressible",
                       param_guard_align_ok(sizeof(int)), 1);
    ret &= test;

    {
        unsigned char expected[sizeof(int)];
        int ok;

        ok = param_put_host_order(expected, sizeof expected,
                                  param_max_unsigned_in(sizeof(int)));
        TEST_ASSERT_INT_EQ("guard dest high edge: expectation", ok, 1);
        ret &= test;

        verdict = param_guard_run(guard_body_dest_high_edge, record, &guard);
        ret &= guard_verdict_completed("dest high edge", &verdict);
        TEST_ASSERT_INT_EQ("guard dest high edge: rc", record->rc, 1);
        ret &= test;
        TEST_ASSERT_INT_EQ("guard dest high edge: value", record->ivalue, -1);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("guard dest high edge: bytes recorded",
                            record->nbytes, sizeof expected);
        ret &= test;
        TEST_ASSERT_MEM_EQ("guard dest high edge: destination bytes",
                           record->bytes, expected, sizeof expected);
        ret &= test;
        TEST_ASSERT_INT_EQ("guard dest high edge: param",
                           record->param_unchanged, 1);
        ret &= test;
    }

    {
        unsigned char expected[sizeof(int)];
        int ok;

        ok = param_expect_zero_padded(expected, sizeof expected, (uintmax_t)5,
                                      (size_t)1);
        TEST_ASSERT_INT_EQ("guard dest low edge: expectation", ok, 1);
        ret &= test;

        verdict = param_guard_run(guard_body_dest_low_edge, record, &guard);
        ret &= guard_verdict_completed("dest low edge", &verdict);
        TEST_ASSERT_INT_EQ("guard dest low edge: rc", record->rc, 1);
        ret &= test;
        TEST_ASSERT_INT_EQ("guard dest low edge: value", record->ivalue, 5);
        ret &= test;
        TEST_ASSERT_SIZE_EQ("guard dest low edge: bytes recorded",
                            record->nbytes, sizeof expected);
        ret &= test;
        TEST_ASSERT_MEM_EQ("guard dest low edge: destination bytes",
                           record->bytes, expected, sizeof expected);
        ret &= test;
        TEST_ASSERT_INT_EQ("guard dest low edge: param",
                           record->param_unchanged, 1);
        ret &= test;
    }

    param_guard_record_close(record);
    param_guard_close(&guard);

    return ret;
}
#endif                          /* LIBPROV_TEST_GUARD_PAGES */

/*
 * Ten groups, each returning its own accumulated verdict in the project's
 * idiom, plus an eleventh wherever the protected-boundary oracle is compiled
 * in, and two independent gates on the way out.  `ret` is the accumulation
 * itself.  TEST_REPORT() derives a second verdict from testutil.h's counters,
 * which is what makes an empty run a failure: a program that asserted nothing
 * -- because a group was dropped, or because a rebuild left main() calling
 * none of them -- cannot exit zero merely by reaching the end of main().
 * Both must be green, and the process status is the maintainer's "return
 * !ret;".
 *
 * The eleventh group is called under the same #ifdef that defines it rather
 * than being stubbed out to a group that returns 1 on hosts without mmap() and
 * fork(): a group that asserts nothing has no business reporting success, and
 * the other ten are unaffected either way.
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
#ifdef LIBPROV_TEST_GUARD_PAGES
    ret &= test_get_guarded_boundaries();
#endif

    if (TEST_REPORT("test_num_get") != 0)
        ret = 0;

    return !ret;
}
