/* CC0 license applied, see LICENSE */

/*
 * tests/test_num_set.c -- an executable specification of the contract
 * provnum_set_size_t() and provnum_set_int() offer their callers: the exact
 * return code for every reachable outcome, the exact bytes left in the
 * destination, and the side effect on OSSL_PARAM.return_size that no header
 * documents.
 *
 * NO USER-SPECIFIED RULES EXIST for this project -- the rules facility reports
 * "No user rules provided" -- so this file is held to enterprise-standard best
 * practice and nothing below claims the authority of a project rule.  What
 * does bind it are the requirements of the task, and the paragraphs that
 * follow record the ones that shaped the code, so a later reader can tell a
 * deliberate decision from an accident.
 *
 * WHAT THE SETTERS ARE.  num.c:169-183 is the provnum_set_##T half of the
 * implement_provnum(T, DT) macro, instantiated twice: for size_t with
 * OSSL_PARAM_UNSIGNED_INTEGER at num.c:185, and for int with
 * OSSL_PARAM_INTEGER at num.c:186.  Each builds a destination descriptor from
 * the caller's OSSL_PARAM (num.c:172-175), builds a source descriptor whose
 * data_type is the macro's DT and whose sign is HARDCODED POSITIVE
 * (num.c:176-178), hands both to provnum_copy() (num.c:59-152), assigns the
 * result's size to param->return_size (num.c:181) and returns the result's
 * code.  Every claim in this file follows from those lines.
 *
 * SUCCESS IS EXACTLY 1, and include/prov/num.h never says so: only num.c:61's
 * "struct resultdesc result = { dest.size, 1, };" fixes it.  Every success
 * below is asserted as == 1 literally -- never >= 0, != 0 or > 0.  A suite
 * that accepted "any non-negative value" would miss a whole class of
 * mutation, and a caller written against > 0 and one written against == 1
 * would both compile today.
 *
 * return_size IS WRITTEN ON EVERY PATH, INCLUDING EVERY FAILURE.  num.c:181
 * assigns it unconditionally, after provnum_copy() has returned, and
 * result.size was initialised to dest.size at num.c:61 and is overwritten by
 * no error path.  So param->return_size == param->data_size holds whether the
 * call succeeded or returned -2 or -4, and check_set_side_effects() asserts it
 * after every single call this file makes.  The side effect is undocumented
 * but load bearing: OpenSSL callers read return_size to size their buffers,
 * so dropping the assignment on the error paths would be a silent ABI break
 * rather than a cosmetic lapse.
 *
 * ONLY TWO ERROR CODES ARE REACHABLE THROUGH THE SETTERS: -2
 * (PROVNUM_E_TOOBIG, num.c:108-111) and -4 (PROVNUM_E_NULL, num.c:115-118).
 * The other two are unreachable BY CONSTRUCTION;
 * test_set_unreachable_docs() carries the proofs together with the
 * complementary facts that make them evidence rather than assumption.
 *
 * CALL, STORE, THEN ASSERT.  C leaves the order in which function-call
 * arguments are evaluated unspecified, so reading param.return_size or the
 * destination inside the same expression that makes the call is a bug and not
 * a matter of taste; a probe that did exactly that reported val=0 and rs=0 for
 * cases that had in fact succeeded.  run_set_case() is the single place in
 * this file that invokes a setter, and it stores the return code, then reads
 * the side effects, then asserts.
 *
 * NOTHING IS ASSERTED AS A LITERAL BYTE STRING.  nativeendian() (num.c:9-14)
 * steers both provnum_copy()'s padding-strip loop and its copy, so every
 * expectation here is laid out by param_util.h's host-order helpers -- the
 * same code that lays out the fixtures, so the two cannot disagree -- and
 * every boundary value is derived from sizeof and CHAR_BIT rather than
 * transcribed.  A hard-coded little-endian byte string, or a literal 127,
 * would assert this ABI instead of the contract.
 *
 * BOUNDARIES COME IN PAIRS: the largest value that fits next to the smallest
 * that does not, so an off-by-one in either direction fails.
 *
 * NO SMOKE TESTS.  Every case asserts a specific value -- the exact return
 * code, the exact destination content, the exact return_size and, on every
 * error path, that the destination still holds the sentinel it was seeded
 * with.  The one case whose byte pattern is deliberately NOT asserted still
 * asserts that the destination CHANGED, so not even it can pass by merely not
 * crashing.  The process exit status comes from testutil.h's assertion
 * counters, so falling off the end of main() cannot manufacture a pass
 * either.
 *
 * NO LIBCRYPTO.  <openssl/params.h> is never included and no
 * OSSL_PARAM_get_, OSSL_PARAM_set_ or OSSL_PARAM_construct_ function is
 * called: those are the libcrypto helpers the provnum_ family exists to
 * replace, so calling them would measure upstream OpenSSL and add the
 * dependency the task forbids.  OSSL_PARAM is a plain public struct from
 * <openssl/core.h> and is built here by hand.
 *
 * THREE BEHAVIORS ARE GENUINELY AMBIGUOUS and are documented rather than
 * asserted, each under a "Class C" heading: the zero padding a negative int
 * receives in an over-wide destination (test_set_int_happy()),
 * provnum_set_int(-1) into a two-byte destination (test_set_errors()), and
 * the destination's declared data_type having no influence on the outcome
 * (test_set_unreachable_docs()).  They are deliberate non-assertions and NOT
 * gaps: the normative OpenSSL prose that might settle them was not
 * retrievable, so pinning whatever the code emits today would enshrine an
 * accident as a contract.  Do not "complete" them by asserting the emitted
 * value.
 *
 * TWO MEMORY-SAFETY REPAIRS ALREADY MADE TO num.c ARE GUARDED HERE, each on
 * both instantiations of the macro, and every guard is written so that it
 * fails in an ORDINARY build rather than only under a sanitizer: every
 * destination buffer in this file is WIDER than the capacity its OSSL_PARAM
 * declares, and the bytes past that capacity are asserted to still hold the
 * sentinel.  The padding-offset repair at num.c:134 is guarded by the
 * over-wide destination cases in test_set_int_happy() and
 * test_set_size_t_bytes(); the zero-capacity clamp at num.c:101 is guarded by
 * the zero-capacity cases in test_set_errors().
 *
 * ACCUMULATOR IDIOM.  Each function keeps its own "int ret = 1;" and folds in
 * each verdict with "ret &= test;", the project's own pattern.  That local
 * deliberately shadows the file-scope accumulator testutil.h defines for the
 * same purpose -- that header documents and supports the spelling -- because
 * the file-scope one is refreshed from the counters by every assertion and so
 * cannot accumulate.  The shadowing is invisible at -Wall -Wextra, which is
 * the warning level this file is clean at.
 */

/*
 * testutil.h first: it pulls in nothing but the C standard library, so it can
 * precede any project or OpenSSL header without perturbing it.  param_util.h
 * already includes "prov/num.h" for the OSSL_PARAM type; it is included again
 * below in its own right, because this file calls the functions and uses the
 * PROVNUM_E_ codes that header declares, and repeating it is harmless -- it
 * has no include guard but is idempotent by construction, holding only a
 * guarded system include, function declarations and identical object-like
 * macros.
 */
#include "testutil.h"
#include "param_util.h"
#include "prov/num.h"

#include <limits.h>             /* INT_MIN, INT_MAX, CHAR_BIT */
#include <stdint.h>             /* SIZE_MAX, uintmax_t */
#include <stddef.h>             /* size_t */
#include <string.h>             /* memcmp, for "the destination changed" */

/*
 * Every destination buffer in this file is this wide, whatever capacity the
 * OSSL_PARAM over it declares, and the bytes beyond that capacity are
 * asserted to still hold the sentinel.  That is what turns an out-of-bounds
 * write -- the shape of the padding-offset defect num.c:134 was repaired for
 * -- into an ordinary assertion failure rather than something only a
 * sanitizer notices.  The widest capacity any case declares is the larger of
 * 3 * sizeof(int) and sizeof(size_t) + sizeof(int), so this expression is
 * strictly greater than both and every case has margin to inspect.
 */
#define SET_CASE_MAX_BYTES (sizeof(size_t) + 3 * sizeof(int))

/*
 * One provnum_set_ case, in the form run_set_case() executes.  Filling this
 * in with a C99 designated initialiser leaves every member a test does not
 * mention zeroed, which is the right default for all of them.
 */
struct set_case {
    /*
     * Names the case in every assertion it makes.  testutil.h's workers take
     * the label as a const char *, so this travels as far as a literal would,
     * and a failing line pairs it with the source line of the assertion --
     * which identifies the property, since each one sits on its own line.
     */
    const char *what;

    int use_int;                /* set_int(), else set_size_t() */
    unsigned int data_type;     /* the DESTINATION's declared type */
    size_t capacity;            /* the destination's declared data_size */
    int null_data;              /* build the parameter with no data buffer */
    size_t uvalue;              /* the value, when use_int is 0 */
    int ivalue;                 /* the value, when use_int is 1 */
    int expected_rc;            /* 1, PROVNUM_E_TOOBIG or PROVNUM_E_NULL */

    /*
     * The destination's expected content on success, `capacity` bytes laid
     * out by param_util.h.  NULL means the byte pattern is deliberately not
     * asserted, which is only ever a Class C case; the destination is then
     * still required to have CHANGED, so the case remains an assertion.
     * Ignored when expected_rc is not 1, because every setter error path
     * returns before writing anything and the sentinel is asserted instead.
     */
    const unsigned char *expected;
};

/*
 * Whether a return code is one the setters can actually produce.  The two it
 * excludes are the named exclusions proved in test_set_unreachable_docs():
 * PROVNUM_E_WRONG_TYPE, whose guard (num.c:63-64) tests a source data_type
 * num.c:176-178 hardcodes to an accepted one, and PROVNUM_E_UNSUPPORTED
 * (num.c:150), whose fallthrough needs a source sign the same lines hardcode
 * to POSITIVE.
 */
static int rc_is_reachable(int rc)
{
    return rc != PROVNUM_E_WRONG_TYPE && rc != PROVNUM_E_UNSUPPORTED;
}

/*
 * Every side effect a provnum_set_ call is required and permitted to have,
 * asserted in one place so that no case can forget one.  `before` is a
 * param_snapshot() taken immediately before the call.
 *
 * The last assertion is the strongest available form of "return_size is the
 * only member a setter writes": the snapshot's own return_size is replaced by
 * the observed one and the two representations are then compared BYTE FOR
 * BYTE, so the padding bytes OSSL_PARAM carries on a typical 64-bit target
 * are covered as well as the five members.  That comparison is sound because
 * param_build() clears the padding and param_snapshot() copies it.
 */
static int check_set_side_effects(const char *what, const OSSL_PARAM *param,
                                  const OSSL_PARAM *before)
{
    OSSL_PARAM expected_repr;
    int ret = 1;

    /* num.c:61 seeds result.size with dest.size, num.c:181 assigns it. */
    TEST_ASSERT_SIZE_EQ(what, param->return_size, param->data_size);
    ret &= test;

    TEST_ASSERT_PTR_EQ(what, param->key, before->key);
    ret &= test;
    TEST_ASSERT_UINT_EQ(what, param->data_type, before->data_type);
    ret &= test;
    TEST_ASSERT_PTR_EQ(what, param->data, before->data);
    ret &= test;
    TEST_ASSERT_SIZE_EQ(what, param->data_size, before->data_size);
    ret &= test;

    param_snapshot(&expected_repr, before);
    expected_repr.return_size = param->return_size;
    TEST_ASSERT_INT_EQ(what, param_identical(param, &expected_repr), 1);
    ret &= test;

    return ret;
}

/*
 * Run one case end to end.  The destination buffer lives here rather than in
 * the caller so that no case can size it wrongly, and it is deliberately
 * wider than any capacity a case declares: on success the bytes past the
 * capacity are asserted to still hold the sentinel, which catches a write
 * past the declared end of the destination without a sanitizer.
 */
static int run_set_case(const struct set_case *c)
{
    unsigned char buffer[SET_CASE_MAX_BYTES];
    unsigned char sentinel[SET_CASE_MAX_BYTES];
    OSSL_PARAM param;
    OSSL_PARAM before;
    int ret = 1;
    int rc;

    /*
     * STRICTLY narrower than the buffer, not merely no wider: the trailing
     * bytes are what the over-write check inspects, so a case that asked for
     * the whole buffer would leave nothing to compare and testutil.h would
     * rightly count a zero-byte comparison as a missing assertion.  Asserted
     * rather than assumed, because a case is data and data can be edited.
     */
    TEST_ASSERT_INT_EQ(c->what, c->capacity < sizeof buffer, 1);
    ret &= test;
    if (c->capacity >= sizeof buffer)
        return 0;

    /* Seed the destination, and a reference to compare it against. */
    param_fill_sentinel(buffer, sizeof buffer);
    param_fill_sentinel(sentinel, sizeof sentinel);

    if (c->null_data) {
        param_build_null_data(&param, c->data_type, c->capacity);
    } else if (c->capacity == 0) {
        /*
         * param_build_empty() returns a verdict that MUST be asserted: it
         * refuses a null buffer, and a refusal would leave the OSSL_PARAM
         * untouched, quietly turning a zero-capacity fixture into something
         * else with a documented answer of its own.
         */
        TEST_ASSERT_INT_EQ(c->what,
                           param_build_empty(&param, c->data_type, buffer), 1);
        ret &= test;
        if (!test)
            return 0;           /* param was left unbuilt; nothing to run */
    } else {
        param_build(&param, c->data_type, buffer, c->capacity);
    }

    param_snapshot(&before, &param);

    /*
     * CALL, STORE, THEN ASSERT.  Nothing about the outcome is read until the
     * call has returned and its result is in a variable of its own.
     */
    if (c->use_int)
        rc = provnum_set_int(&param, c->ivalue);
    else
        rc = provnum_set_size_t(&param, c->uvalue);

    TEST_ASSERT_INT_EQ(c->what, rc, c->expected_rc);
    ret &= test;
    ret &= check_set_side_effects(c->what, &param, &before);

    if (c->expected_rc != 1) {
        /*
         * Both reachable error paths -- PROVNUM_E_TOOBIG at num.c:108-111 and
         * PROVNUM_E_NULL at num.c:115-118 -- return before provnum_copy()
         * writes anything, so the whole buffer must still be the sentinel.
         * That holds for a null-data fixture too, where this buffer was never
         * handed to the parameter at all.
         */
        TEST_ASSERT_MEM_EQ(c->what, buffer, sentinel, sizeof buffer);
        ret &= test;
        return ret;
    }

    /*
     * A successful setter always writes, and no case here converts a value
     * whose bytes are the sentinel, so "the destination differs from the
     * sentinel" is a genuine assertion.  It is what keeps a Class C case --
     * one that deliberately asserts no byte pattern -- from degenerating into
     * a check that the code merely ran.
     *
     * The capacity is necessarily non-zero at this point: a zero-capacity
     * destination strips its source down to one byte at num.c:102-106 and is
     * then refused by num.c:108-111, so it can only ever carry an expected
     * result of PROVNUM_E_TOOBIG and has already returned above.
     */
    TEST_ASSERT_INT_EQ(c->what, memcmp(buffer, sentinel, c->capacity) != 0, 1);
    ret &= test;

    if (c->expected != NULL) {
        TEST_ASSERT_MEM_EQ(c->what, buffer, c->expected, c->capacity);
        ret &= test;
    }

    /* The declared capacity is the whole permission the setter has. */
    TEST_ASSERT_MEM_EQ(c->what, buffer + c->capacity, sentinel + c->capacity,
                       sizeof buffer - c->capacity);
    ret &= test;

    return ret;
}

/*
 * The seven groups, in the order main() runs them.  Each returns 1 when every
 * assertion it made held, and each is independent: all state is automatic, so
 * the groups may be reordered, and separate test executables may run in
 * parallel, without interacting.
 */
static int test_set_int_happy(void);        /* widths, padding, Class C #2 */
static int test_set_int_extremes(void);     /* INT_MIN, INT_MAX, 1-byte pair */
static int test_set_size_t_capacity(void);  /* the effective SIGNED capacity */
static int test_set_size_t_bytes(void);     /* byte-level output, host order */
static int test_set_errors(void);           /* -4, -2, Class C #3 */
static int test_set_return_size_invariant(void);  /* the side effect, always */
static int test_set_unreachable_docs(void); /* -1 and -3, Class C #4 */

int main(void)
{
    int ret = 1;
    int status;

    ret &= test_set_int_happy();
    ret &= test_set_int_extremes();
    ret &= test_set_size_t_capacity();
    ret &= test_set_size_t_bytes();
    ret &= test_set_errors();
    ret &= test_set_return_size_invariant();
    ret &= test_set_unreachable_docs();

    /*
     * testutil.h's report is the authority on the exit status: it derives it
     * from the assertion counters, so a run that asserted nothing fails even
     * though every group above would have returned 1.  The accumulated `ret`
     * is honoured as well; the two can disagree only if a group dropped a
     * verdict, in which case failing is the right answer.
     */
    status = TEST_REPORT("test_num_set");

    return status != 0 || !ret ? 1 : 0;
}

/*
 * provnum_set_int() at the widths that matter: exactly as wide as the source,
 * wider, and narrower.  Every case asserts the return code, the whole
 * destination content and the side effects; the widths are expressed in terms
 * of sizeof(int) so they stay meaningful on any ABI.
 */
static int test_set_int_happy(void)
{
    int ret = 1;

    {
        /*
         * The base case: a destination exactly as wide as an int.  The
         * padding-strip loop at num.c:102-106 does not run, because src.size
         * is not greater than end, and no padding is written, because
         * num.c:126 finds src.size and dest.size equal.  What lands in the
         * destination is the int's own representation in host byte order.
         */
        unsigned char expected[SET_CASE_MAX_BYTES];
        struct set_case c = {
            .what = "set_int(5) -> int-wide INTEGER destination",
            .use_int = 1,
            .data_type = OSSL_PARAM_INTEGER,
            .capacity = sizeof(int),
            .ivalue = 5,
            .expected_rc = 1,
            .expected = expected
        };

        TEST_ASSERT_INT_EQ(c.what,
                           param_put_host_order(expected, c.capacity,
                                                (uintmax_t)5), 1);
        ret &= test;
        ret &= run_set_case(&c);
    }

    {
        /*
         * D3 REGRESSION GUARD.  A destination three int widths deep takes the
         * value in its least significant sizeof(int) bytes and zero padding
         * above, because num.c:134 starts the padding at src.size on a LITTLE
         * destination and num.c:136-137 fills it with src.sign, which
         * num.c:176-178 hardcodes to POSITIVE and num.c:7 defines as 0x00.
         *
         * The offset num.c:134 computes was "dest.size - src.size" before it
         * was repaired, which for this exact case is 8: the memset then wrote
         * dest[8 .. 15], four bytes past a twelve-byte destination.  This case
         * therefore fails in an ordinary build and not only under a
         * sanitizer, because run_set_case() asserts that the bytes beyond the
         * declared capacity still hold the sentinel.
         */
        unsigned char expected[SET_CASE_MAX_BYTES];
        struct set_case c = {
            .what = "set_int(5) -> 3 int widths, D3 padding-offset guard",
            .use_int = 1,
            .data_type = OSSL_PARAM_INTEGER,
            .capacity = sizeof(int) * 3,
            .ivalue = 5,
            .expected_rc = 1,
            .expected = expected
        };

        TEST_ASSERT_INT_EQ(c.what,
                           param_expect_zero_padded(expected, c.capacity,
                                                    (uintmax_t)5,
                                                    sizeof(int)), 1);
        ret &= test;
        ret &= run_set_case(&c);
    }

    {
        /*
         * The narrowest destination there is.  Here the strip loop DOES run:
         * every byte above the least significant one is 0x00, which equals
         * src.sign (rule 1, num.c:90-91 and :103), and the high bit of the
         * next byte down is clear (rule 2, num.c:92-93 and :104-105), so the
         * source is stripped from sizeof(int) bytes to one and the value
         * fits.
         */
        unsigned char expected[SET_CASE_MAX_BYTES];
        struct set_case c = {
            .what = "set_int(5) -> single-byte INTEGER destination",
            .use_int = 1,
            .data_type = OSSL_PARAM_INTEGER,
            .capacity = 1,
            .ivalue = 5,
            .expected_rc = 1,
            .expected = expected
        };

        TEST_ASSERT_INT_EQ(c.what,
                           param_put_host_order(expected, c.capacity,
                                                (uintmax_t)5), 1);
        ret &= test;
        ret &= run_set_case(&c);
    }

    {
        /*
         * One byte narrower than the source: the strip loop runs exactly once
         * and then stops on its own bound, num.c:102, rather than on either
         * padding rule.
         */
        unsigned char expected[SET_CASE_MAX_BYTES];
        struct set_case c = {
            .what = "set_int(5) -> one byte narrower than an int",
            .use_int = 1,
            .data_type = OSSL_PARAM_INTEGER,
            .capacity = sizeof(int) - 1,
            .ivalue = 5,
            .expected_rc = 1,
            .expected = expected
        };

        TEST_ASSERT_INT_EQ(c.what,
                           param_put_host_order(expected, c.capacity,
                                                (uintmax_t)5), 1);
        ret &= test;
        ret &= run_set_case(&c);
    }

    {
        /*
         * Zero is the one value whose every byte is padding.  The destination
         * is as wide as the source, so nothing is stripped and nothing is
         * padded; all sizeof(int) bytes are written as 0x00, which is still a
         * change from the sentinel and so still an assertion.
         */
        unsigned char expected[SET_CASE_MAX_BYTES];
        struct set_case c = {
            .what = "set_int(0) -> int-wide INTEGER destination",
            .use_int = 1,
            .data_type = OSSL_PARAM_INTEGER,
            .capacity = sizeof(int),
            .ivalue = 0,
            .expected_rc = 1,
            .expected = expected
        };

        TEST_ASSERT_INT_EQ(c.what,
                           param_put_host_order(expected, c.capacity,
                                                (uintmax_t)0), 1);
        ret &= test;
        ret &= run_set_case(&c);
    }

    {
        /*
         * -1 is every bit set.  The expected pattern is derived as "the
         * largest value sizeof(int) bytes can hold" rather than transcribed,
         * and it is the two's-complement representation num.c's own padding
         * rules assume (num.c:90-91 calls src.sign "the 2's complement padding
         * value").  Because the destination is exactly as wide as the source
         * no padding is involved, so this case says nothing about the
         * over-wide destination that Class C #2 below leaves open.
         */
        unsigned char expected[SET_CASE_MAX_BYTES];
        struct set_case c = {
            .what = "set_int(-1) -> int-wide INTEGER destination",
            .use_int = 1,
            .data_type = OSSL_PARAM_INTEGER,
            .capacity = sizeof(int),
            .ivalue = -1,
            .expected_rc = 1,
            .expected = expected
        };

        TEST_ASSERT_INT_EQ(c.what,
                           param_put_host_order(expected, c.capacity,
                                                param_max_unsigned_in(
                                                    sizeof(int))), 1);
        ret &= test;
        ret &= run_set_case(&c);
    }

    {
        /*
         * CLASS C #2 -- DELIBERATE NON-ASSERTION, NOT A GAP.  Do not
         * "complete" this by asserting the emitted byte pattern.
         *
         * A negative int written into a destination wider than sizeof(int) is
         * ZERO padded, not sign extended, so a provnum_get_int() read back
         * does not recover the original value.  The mechanism is exact: the
         * padding memset at num.c:136-137 writes src.sign, and num.c:176-178
         * hardcodes the source descriptor's sign to POSITIVE, which num.c:7
         * defines as 0x00.  The destination's own declared data_type has no
         * say, because it is consulted only at num.c:124 where the
         * disjunction is already satisfied by src.sign == POSITIVE.
         *
         * Two readings of the contract are defensible and include/prov/num.h
         * settles neither:
         *
         *   (a) The padding should be sign extension, so that the wider
         *       destination denotes the same number and a round trip through
         *       provnum_get_int() is lossless.
         *   (b) The destination's declared data_type is what should govern,
         *       and a writer handed a wider buffer is entitled to treat the
         *       value as a magnitude and zero fill above it.
         *
         * WHAT IS ASSERTED HERE, both mechanical and unambiguous: the return
         * code is exactly 1, and the return_size side effect and the
         * unchanged-parameter invariants hold, via check_set_side_effects().
         * The destination is also asserted to have CHANGED, so this case
         * cannot pass by merely running.
         *
         * WHAT IS NOT ASSERTED: that the resulting byte pattern is correct --
         * .expected is left NULL for exactly that reason -- and that a
         * provnum_get_int() round trip recovers -5.  Either assertion would
         * enshrine one reading as the contract.
         */
        struct set_case c = {
            .what = "set_int(-5) -> 3 int widths, Class C #2 zero padding",
            .use_int = 1,
            .data_type = OSSL_PARAM_INTEGER,
            .capacity = sizeof(int) * 3,
            .ivalue = -5,
            .expected_rc = 1,
            .expected = NULL
        };

        ret &= run_set_case(&c);
    }

    return ret;
}

/*
 * The edges of int, and the effective capacity of a single-byte destination.
 * Every value below is derived from <limits.h> and from param_util.h's
 * width helpers, so the cases stay correct wherever sizeof(int) and CHAR_BIT
 * land; nothing is transcribed.
 */
static int test_set_int_extremes(void)
{
    int ret = 1;

    {
        /*
         * INT_MIN into a destination exactly as wide as an int.  The expected
         * bit pattern is derived as INT_MAX + 1 computed in uintmax_t, which
         * is the two's-complement representation of INT_MIN -- the
         * representation num.c:90-91 already assumes when it calls src.sign
         * the 2's complement padding value.
         */
        unsigned char expected[SET_CASE_MAX_BYTES];
        struct set_case c = {
            .what = "set_int(INT_MIN) -> int-wide INTEGER destination",
            .use_int = 1,
            .data_type = OSSL_PARAM_INTEGER,
            .capacity = sizeof(int),
            .ivalue = INT_MIN,
            .expected_rc = 1,
            .expected = expected
        };

        TEST_ASSERT_INT_EQ(c.what,
                           param_put_host_order(expected, c.capacity,
                                                (uintmax_t)INT_MAX
                                                + (uintmax_t)1), 1);
        ret &= test;
        ret &= run_set_case(&c);
    }

    {
        /*
         * INT_MAX, the other edge: every value bit set and the sign bit
         * clear.  Taken together with the INT_MIN case above, the pair pins
         * both ends of the type at its natural width.
         */
        unsigned char expected[SET_CASE_MAX_BYTES];
        struct set_case c = {
            .what = "set_int(INT_MAX) -> int-wide INTEGER destination",
            .use_int = 1,
            .data_type = OSSL_PARAM_INTEGER,
            .capacity = sizeof(int),
            .ivalue = INT_MAX,
            .expected_rc = 1,
            .expected = expected
        };

        TEST_ASSERT_INT_EQ(c.what,
                           param_put_host_order(expected, c.capacity,
                                                (uintmax_t)INT_MAX), 1);
        ret &= test;
        ret &= run_set_case(&c);
    }

    /*
     * BOUNDARY PAIR: the largest int a single-byte destination accepts, next
     * to the smallest it refuses.  Both values are derived from
     * param_max_signed_in(1), which is CHAR_BIT arithmetic and not a literal
     * 127, so the pair still straddles the real boundary if a byte is not
     * eight bits wide.  An off-by-one at num.c:102 or num.c:108 breaks one
     * half or the other.
     */
    {
        /*
         * Strips cleanly: the bytes above the least significant one are
         * 0x00 == src.sign (rule 1, num.c:103), and the high bit of the
         * surviving byte is clear, which is what rule 2 (num.c:104-105)
         * requires of the byte below the one being dropped.
         */
        unsigned char expected[SET_CASE_MAX_BYTES];
        const uintmax_t fits = param_max_signed_in(1);
        struct set_case c = {
            .what = "set_int(largest that fits one byte) -> 1-byte INTEGER",
            .use_int = 1,
            .data_type = OSSL_PARAM_INTEGER,
            .capacity = 1,
            .ivalue = (int)fits,
            .expected_rc = 1,
            .expected = expected
        };

        TEST_ASSERT_INT_EQ(c.what,
                           param_put_host_order(expected, c.capacity, fits),
                           1);
        ret &= test;
        ret &= run_set_case(&c);
    }

    {
        /*
         * One more, and the same loop refuses to strip.  The byte above the
         * least significant one is still 0x00, satisfying rule 1, but the
         * high bit of the byte below it is now SET, so rule 2
         * (num.c:104-105) fails and the loop breaks at a source size of two.
         * Two is greater than the one-byte destination, so num.c:108-111
         * answers PROVNUM_E_TOOBIG and leaves the destination alone.
         *
         * For an int destination declared OSSL_PARAM_INTEGER this is
         * unambiguous: one signed byte cannot denote this value.  The
         * surprising case is the same boundary reached through
         * provnum_set_size_t(), where the source type is unsigned; that lives
         * in test_set_size_t_capacity().
         */
        const uintmax_t refused = param_max_signed_in(1) + (uintmax_t)1;
        struct set_case c = {
            .what = "set_int(smallest that does not fit one byte) -> 1 byte",
            .use_int = 1,
            .data_type = OSSL_PARAM_INTEGER,
            .capacity = 1,
            .ivalue = (int)refused,
            .expected_rc = PROVNUM_E_TOOBIG,
            .expected = NULL
        };

        /*
         * The derivation is safe for the int type: C requires INT_MAX to be
         * at least 32767, and one byte's worth of value bits cannot exceed
         * that on any implementation where CHAR_BIT is 8 or 16.
         */
        TEST_ASSERT_INT_EQ(c.what, refused <= (uintmax_t)INT_MAX, 1);
        ret &= test;
        ret &= run_set_case(&c);
    }

    {
        /*
         * The far end of the same band: even the largest value a byte could
         * hold if every bit were available is refused, because the strip loop
         * breaks on rule 2 the moment the surviving byte has its high bit
         * set.  This is what makes the boundary above an EFFECTIVE SIGNED
         * capacity rather than an accident of one value -- the whole range
         * from param_max_signed_in(1) + 1 upwards is rejected, not just its
         * first member.
         */
        const uintmax_t allbits = param_max_unsigned_in(1);
        struct set_case c = {
            .what = "set_int(all bits of one byte set) -> 1-byte INTEGER",
            .use_int = 1,
            .data_type = OSSL_PARAM_INTEGER,
            .capacity = 1,
            .ivalue = (int)allbits,
            .expected_rc = PROVNUM_E_TOOBIG,
            .expected = NULL
        };

        TEST_ASSERT_INT_EQ(c.what, allbits <= (uintmax_t)INT_MAX, 1);
        ret &= test;
        ret &= run_set_case(&c);
    }

    return ret;
}

/*
 * THE EFFECTIVE SIGNED CAPACITY OF provnum_set_size_t(), which is the most
 * surprising thing this file records and the one an unwary "fix" is most
 * likely to break.  A size_t is unsigned and its destination is declared
 * OSSL_PARAM_UNSIGNED_INTEGER, yet a one-byte destination accepts only the
 * values whose top bit is clear.
 *
 * The mechanism, exactly.  num.c:176-178 hardcodes the SOURCE descriptor's
 * sign to POSITIVE for the setter direction, which num.c:7 defines as 0x00.
 * The padding-strip loop at num.c:102-106 may therefore drop a leading byte
 * only while BOTH rules hold: rule 1 (num.c:90-91, tested at :103) needs the
 * byte being dropped to equal 0x00, and rule 2 (num.c:92-93, tested at
 * :104-105) needs the high bit of the next byte down to match the high bit of
 * 0x00, that is, to be clear.  A value with its top byte-bit set therefore
 * cannot be narrowed onto its own last byte, the loop stops one byte early,
 * and num.c:108-111 answers PROVNUM_E_TOOBIG.
 *
 * Each pair below is written adjacently -- largest that fits, then smallest
 * that does not -- and both members are derived from param_max_signed_in() so
 * they track CHAR_BIT rather than asserting this ABI.
 */
static int test_set_size_t_capacity(void)
{
    int ret = 1;

    /* PAIR at one byte. */
    {
        unsigned char expected[SET_CASE_MAX_BYTES];
        const uintmax_t fits = param_max_signed_in(1);
        struct set_case c = {
            .what = "set_size_t(top bit of one byte clear) -> 1 byte, fits",
            .data_type = OSSL_PARAM_UNSIGNED_INTEGER,
            .capacity = 1,
            .uvalue = (size_t)fits,
            .expected_rc = 1,
            .expected = expected
        };

        TEST_ASSERT_INT_EQ(c.what,
                           param_put_host_order(expected, c.capacity, fits),
                           1);
        ret &= test;
        ret &= run_set_case(&c);
    }

    {
        /*
         * The headline case: one more than the value above, into the same
         * destination, is REFUSED even though a single unsigned byte plainly
         * represents it.  Nothing about the destination's declared
         * OSSL_PARAM_UNSIGNED_INTEGER type changes that; only the source
         * sign hardcoded at num.c:176-178 governs the strip loop.
         */
        const uintmax_t refused = param_max_signed_in(1) + (uintmax_t)1;
        struct set_case c = {
            .what = "set_size_t(top bit of one byte set) -> 1 byte, refused",
            .data_type = OSSL_PARAM_UNSIGNED_INTEGER,
            .capacity = 1,
            .uvalue = (size_t)refused,
            .expected_rc = PROVNUM_E_TOOBIG,
            .expected = NULL
        };

        ret &= run_set_case(&c);
    }

    {
        /*
         * The rest of the band is refused too, so the boundary above is a
         * capacity and not a one-value quirk: the largest value a byte can
         * hold with every bit available still does not fit a one-byte
         * destination.
         */
        struct set_case c = {
            .what = "set_size_t(all bits of one byte set) -> 1 byte, refused",
            .data_type = OSSL_PARAM_UNSIGNED_INTEGER,
            .capacity = 1,
            .uvalue = (size_t)param_max_unsigned_in(1),
            .expected_rc = PROVNUM_E_TOOBIG,
            .expected = NULL
        };

        ret &= run_set_case(&c);
    }

    {
        /*
         * And a value that exceeds the destination's width outright, which
         * reaches the same PROVNUM_E_TOOBIG through a different route: here
         * the strip loop breaks on rule 1 (num.c:103) because the surviving
         * upper byte is not 0x00 at all, rather than on rule 2.  Both routes
         * must answer -2, and both must leave return_size at the declared
         * data_size.
         */
        struct set_case c = {
            .what = "set_size_t(one more than a byte holds) -> 1 byte",
            .data_type = OSSL_PARAM_UNSIGNED_INTEGER,
            .capacity = 1,
            .uvalue = (size_t)(param_max_unsigned_in(1) + (uintmax_t)1),
            .expected_rc = PROVNUM_E_TOOBIG,
            .expected = NULL
        };

        ret &= run_set_case(&c);
    }

    /*
     * PAIR at two bytes: the same mechanism one width up, which is what shows
     * the rule is a property of the strip loop and not of the single-byte
     * case.  A two-byte destination needs a size_t at least two bytes wide,
     * which C99 7.18.3 guarantees by requiring SIZE_MAX >= 65535.
     */
    {
        unsigned char expected[SET_CASE_MAX_BYTES];
        const uintmax_t fits = param_max_signed_in(2);
        struct set_case c = {
            .what = "set_size_t(top bit of two bytes clear) -> 2 bytes, fits",
            .data_type = OSSL_PARAM_UNSIGNED_INTEGER,
            .capacity = 2,
            .uvalue = (size_t)fits,
            .expected_rc = 1,
            .expected = expected
        };

        TEST_ASSERT_INT_EQ(c.what,
                           param_put_host_order(expected, c.capacity, fits),
                           1);
        ret &= test;
        ret &= run_set_case(&c);
    }

    {
        const uintmax_t refused = param_max_signed_in(2) + (uintmax_t)1;
        struct set_case c = {
            .what = "set_size_t(top bit of two bytes set) -> 2 bytes, refused",
            .data_type = OSSL_PARAM_UNSIGNED_INTEGER,
            .capacity = 2,
            .uvalue = (size_t)refused,
            .expected_rc = PROVNUM_E_TOOBIG,
            .expected = NULL
        };

        ret &= run_set_case(&c);
    }

    {
        /*
         * SIZE_MAX at the type's own width: every bit set, and accepted,
         * because a destination as wide as the source needs no stripping at
         * all -- the loop bound at num.c:102 is false on entry.  This is the
         * counterpart to the refusals above: the effective capacity is only
         * ever reduced when the destination is NARROWER than the source.
         */
        unsigned char expected[SET_CASE_MAX_BYTES];
        struct set_case c = {
            .what = "set_size_t(SIZE_MAX) -> size_t-wide UNSIGNED destination",
            .data_type = OSSL_PARAM_UNSIGNED_INTEGER,
            .capacity = sizeof(size_t),
            .uvalue = SIZE_MAX,
            .expected_rc = 1,
            .expected = expected
        };

        TEST_ASSERT_INT_EQ(c.what,
                           param_put_host_order(expected, c.capacity,
                                                (uintmax_t)SIZE_MAX), 1);
        ret &= test;
        ret &= run_set_case(&c);
    }

    {
        /*
         * SIZE_MAX / 2 is the same width with the top bit clear, so it is the
         * value that would survive a strip if one were attempted.  Asserting
         * it beside SIZE_MAX proves the full-width copy is not quietly
         * sensitive to the sign bit.
         */
        unsigned char expected[SET_CASE_MAX_BYTES];
        struct set_case c = {
            .what = "set_size_t(SIZE_MAX / 2) -> size_t-wide UNSIGNED",
            .data_type = OSSL_PARAM_UNSIGNED_INTEGER,
            .capacity = sizeof(size_t),
            .uvalue = SIZE_MAX / 2,
            .expected_rc = 1,
            .expected = expected
        };

        TEST_ASSERT_INT_EQ(c.what,
                           param_put_host_order(expected, c.capacity,
                                                (uintmax_t)(SIZE_MAX / 2)), 1);
        ret &= test;
        ret &= run_set_case(&c);
    }

    {
        /*
         * The bottom of the range: zero strips all the way down to a single
         * byte, because every byte of it satisfies both padding rules, so the
         * narrowest destination there is accepts it.
         */
        unsigned char expected[SET_CASE_MAX_BYTES];
        struct set_case c = {
            .what = "set_size_t(0) -> single-byte UNSIGNED destination",
            .data_type = OSSL_PARAM_UNSIGNED_INTEGER,
            .capacity = 1,
            .uvalue = 0,
            .expected_rc = 1,
            .expected = expected
        };

        TEST_ASSERT_INT_EQ(c.what,
                           param_put_host_order(expected, c.capacity,
                                                (uintmax_t)0), 1);
        ret &= test;
        ret &= run_set_case(&c);
    }

    return ret;
}

/*
 * Byte-level output for provnum_set_size_t(), where the question is not
 * whether a value fits but WHERE each of its bytes lands.  nativeendian()
 * (num.c:9-14) drives both the destination offset chosen at num.c:140 and the
 * source offset at num.c:141, so every expectation here is laid out by
 * param_util.h from a logical description -- a most-significant-byte-first
 * pattern, or a value plus a padding width -- and never as a literal byte
 * string that would only be right on one byte order.
 */
static int test_set_size_t_bytes(void)
{
    int ret = 1;

    {
        /*
         * Three DISTINCT bytes, so a byte-order mistake cannot hide behind a
         * symmetric pattern.  The value is built from CHAR_BIT so that
         * significance 2 holds 1, significance 1 holds 2 and significance 0
         * holds 3; the expectation is laid out from the same description given
         * most significant byte first, which param_put_msb_first() maps onto
         * the running host.  On a little-endian host that is the raw sequence
         * 03 02 01, and on a big-endian one 01 02 03 -- the test asserts the
         * description, not either sequence.
         */
        unsigned char expected[SET_CASE_MAX_BYTES];
        static const unsigned char msb_first[] = { 1, 2, 3 };
        const size_t width = sizeof msb_first;
        const uintmax_t value = ((uintmax_t)1 << (2 * CHAR_BIT))
                                | ((uintmax_t)2 << CHAR_BIT)
                                | (uintmax_t)3;
        struct set_case c = {
            .what = "set_size_t(three distinct bytes) -> 3-byte UNSIGNED",
            .data_type = OSSL_PARAM_UNSIGNED_INTEGER,
            .capacity = sizeof msb_first,
            .uvalue = (size_t)value,
            .expected_rc = 1,
            .expected = expected
        };

        /*
         * Three distinct bytes need a size_t at least three bytes wide.  C99
         * 7.18.3 guarantees only two, so the precondition is asserted rather
         * than assumed; every platform an OpenSSL 3 provider runs on has a
         * 32- or 64-bit size_t, and on a narrower one this case would need
         * widening rather than rewriting.
         */
        TEST_ASSERT_INT_EQ(c.what, sizeof(size_t) >= width, 1);
        ret &= test;
        TEST_ASSERT_INT_EQ(c.what,
                           param_put_msb_first(expected, c.capacity, msb_first,
                                               width), 1);
        ret &= test;
        ret &= run_set_case(&c);
    }

    {
        /*
         * D3 REGRESSION GUARD, on the OTHER instantiation of the macro.  The
         * padding offset at num.c:134 is shared code, but each instantiation
         * reaches it with a different sizeof(T), so the size_t half deserves
         * its own case: a destination a whole int wider than a size_t takes
         * the value in its least significant sizeof(size_t) bytes and zero
         * padding above.  Before num.c:134 was repaired the memset started at
         * dest.size - src.size and ran off the end; run_set_case() asserts the
         * bytes past the declared capacity, so this fails without a sanitizer.
         */
        unsigned char expected[SET_CASE_MAX_BYTES];
        struct set_case c = {
            .what = "set_size_t(5) -> destination wider than a size_t, D3",
            .data_type = OSSL_PARAM_UNSIGNED_INTEGER,
            .capacity = sizeof(size_t) + sizeof(int),
            .uvalue = 5,
            .expected_rc = 1,
            .expected = expected
        };

        TEST_ASSERT_INT_EQ(c.what,
                           param_expect_zero_padded(expected, c.capacity,
                                                    (uintmax_t)5,
                                                    sizeof(size_t)), 1);
        ret &= test;
        ret &= run_set_case(&c);
    }

    {
        /*
         * Zero at the source's own width: every byte written, every byte
         * 0x00.  Worth its own case because it is the only success whose
         * output contains no set bit at all, so a copy that silently wrote
         * nothing would still differ from the sentinel and only a full byte
         * comparison catches it.
         */
        unsigned char expected[SET_CASE_MAX_BYTES];
        struct set_case c = {
            .what = "set_size_t(0) -> size_t-wide UNSIGNED destination",
            .data_type = OSSL_PARAM_UNSIGNED_INTEGER,
            .capacity = sizeof(size_t),
            .uvalue = 0,
            .expected_rc = 1,
            .expected = expected
        };

        TEST_ASSERT_INT_EQ(c.what,
                           param_put_host_order(expected, c.capacity,
                                                (uintmax_t)0), 1);
        ret &= test;
        ret &= run_set_case(&c);
    }

    return ret;
}

/*
 * Both error codes the setters can reach, on both instantiations, with the
 * destination asserted untouched and return_size asserted anyway.
 *
 * PROVNUM_E_NULL (-4) comes from num.c:115-118, the destination check, which
 * sits AFTER the oversize check at num.c:108-111 -- an ordering that matters
 * and is pinned by the last case in this group.  PROVNUM_E_TOOBIG (-2) comes
 * from num.c:108-111 and is reached here two ways: a destination with no
 * capacity at all, and a destination narrower than the value needs.
 */
static int test_set_errors(void)
{
    int ret = 1;

    {
        /*
         * A parameter with a declared size but no buffer.  provnum_copy()
         * reaches num.c:115-118 and answers PROVNUM_E_NULL; num.c:181 still
         * assigns return_size, which is exactly the kind of error-path side
         * effect a suite that only checked return codes would miss.
         */
        struct set_case c = {
            .what = "set_int(5) -> INTEGER destination with no buffer",
            .use_int = 1,
            .data_type = OSSL_PARAM_INTEGER,
            .capacity = sizeof(int),
            .null_data = 1,
            .ivalue = 5,
            .expected_rc = PROVNUM_E_NULL,
            .expected = NULL
        };

        ret &= run_set_case(&c);
    }

    {
        /* The same contract through the size_t instantiation. */
        struct set_case c = {
            .what = "set_size_t(5) -> UNSIGNED destination with no buffer",
            .data_type = OSSL_PARAM_UNSIGNED_INTEGER,
            .capacity = sizeof(size_t),
            .null_data = 1,
            .uvalue = 5,
            .expected_rc = PROVNUM_E_NULL,
            .expected = NULL
        };

        ret &= run_set_case(&c);
    }

    {
        /*
         * D2 REGRESSION GUARD.  A real buffer with a declared size of ZERO.
         * The clamp at num.c:101 exists for exactly this shape: without the
         * "|| dest.size == 0" the loop bound `end` would be 0, the condition
         * at num.c:102 would stay true until the source size reached 0, and
         * srcmsb would step one position before the start of the source
         * buffer.  The documented answer is unchanged by the repair --
         * PROVNUM_E_TOOBIG with return_size 0, because a source of
         * sizeof(size_t) bytes cannot be narrowed below one and one is greater
         * than zero -- so this case asserts the contract and the clamp keeps
         * it from being reached through undefined behaviour.
         *
         * run_set_case() compares the WHOLE buffer against the sentinel here,
         * not the declared capacity: a comparison of zero bytes inspects
         * nothing and testutil.h treats it as a missing assertion.
         */
        struct set_case c = {
            .what = "set_size_t(0) -> zero-capacity UNSIGNED destination, D2",
            .data_type = OSSL_PARAM_UNSIGNED_INTEGER,
            .capacity = 0,
            .uvalue = 0,
            .expected_rc = PROVNUM_E_TOOBIG,
            .expected = NULL
        };

        ret &= run_set_case(&c);
    }

    {
        /*
         * The same zero-capacity shape on the int instantiation, so the clamp
         * is covered for both source widths.
         */
        struct set_case c = {
            .what = "set_int(0) -> zero-capacity INTEGER destination, D2",
            .use_int = 1,
            .data_type = OSSL_PARAM_INTEGER,
            .capacity = 0,
            .ivalue = 0,
            .expected_rc = PROVNUM_E_TOOBIG,
            .expected = NULL
        };

        ret &= run_set_case(&c);
    }

    {
        /*
         * SIZE_MAX into a destination one byte narrower than a size_t.  Not a
         * single byte of the source is 0x00, so the strip loop breaks
         * immediately on rule 1 (num.c:103) and the source keeps its full
         * width; sizeof(size_t) is greater than sizeof(size_t) - 1, so
         * num.c:108-111 answers PROVNUM_E_TOOBIG.  The width is derived, so
         * this is "one byte too narrow for the widest value" on any ABI.
         */
        struct set_case c = {
            .what = "set_size_t(SIZE_MAX) -> one byte too narrow",
            .data_type = OSSL_PARAM_UNSIGNED_INTEGER,
            .capacity = sizeof(size_t) - 1,
            .uvalue = SIZE_MAX,
            .expected_rc = PROVNUM_E_TOOBIG,
            .expected = NULL
        };

        ret &= run_set_case(&c);
    }

    {
        /*
         * INT_MAX into a destination one byte narrower than an int: the
         * mirror of the case above on the other instantiation.  Here the top
         * byte of the source is not 0x00 either -- it carries INT_MAX's
         * highest value bits -- so rule 1 stops the loop at once.
         */
        struct set_case c = {
            .what = "set_int(INT_MAX) -> one byte too narrow",
            .use_int = 1,
            .data_type = OSSL_PARAM_INTEGER,
            .capacity = sizeof(int) - 1,
            .ivalue = INT_MAX,
            .expected_rc = PROVNUM_E_TOOBIG,
            .expected = NULL
        };

        ret &= run_set_case(&c);
    }

    {
        /*
         * PRECEDENCE: oversize is decided BEFORE the destination pointer is
         * checked.  num.c:108-111 runs ahead of num.c:115-118, so a parameter
         * that is simultaneously too narrow AND has no buffer must answer
         * PROVNUM_E_TOOBIG, not PROVNUM_E_NULL.  A null destination clamps the
         * loop bound to 1 at num.c:101, so the source is stripped as far as it
         * can go and the comparison at num.c:108 is against the DECLARED
         * data_size -- one byte here, which SIZE_MAX cannot be narrowed into.
         *
         * This is the assertion that survives a reordering of the guard block:
         * moving either check changes no line's reachability, yet changes this
         * answer.
         */
        struct set_case c = {
            .what = "set_size_t(SIZE_MAX) -> no buffer AND too narrow",
            .data_type = OSSL_PARAM_UNSIGNED_INTEGER,
            .capacity = 1,
            .null_data = 1,
            .uvalue = SIZE_MAX,
            .expected_rc = PROVNUM_E_TOOBIG,
            .expected = NULL
        };

        ret &= run_set_case(&c);
    }

    /*
     * CLASS C #3 -- DELIBERATE NON-ASSERTION, NOT A GAP.  Do not "complete"
     * this by asserting the emitted value.  There is deliberately NO call
     * here: invoking the setter and then asserting nothing about the outcome
     * would be the "checks only that the code runs" test this suite is
     * forbidden to contain, while asserting the outcome is what the ambiguity
     * rule forbids.  The behaviour is recorded, not exercised.
     *
     * provnum_set_int(&param, -1) into a TWO-BYTE destination answers
     * PROVNUM_E_TOOBIG.  The mechanism is the same hardcoded sign as
     * everywhere else in this file: num.c:176-178 sets the source sign to
     * POSITIVE == 0x00 (num.c:7), so the 0xFF bytes of -1 fail rule 1 at
     * num.c:103 at the first iteration, the source keeps its full sizeof(int)
     * width, and num.c:108-111 refuses it.
     *
     *   (a) -1 is exactly representable in two bytes as 0xFFFF, and a
     *       conversion helper that knows the value is negative could narrow
     *       it, so this should succeed.
     *   (b) The padding-strip rules are stated in terms of the source's own
     *       sign byte (num.c:84-94), and with that sign fixed at POSITIVE the
     *       value legitimately requires its full source width, so refusing it
     *       is correct.
     *
     * include/prov/num.h settles neither reading -- it documents the four
     * error codes and says nothing about narrowing negative values -- and the
     * normative OpenSSL prose for the upstream OSSL_PARAM_set_ family was not
     * retrievable, so no assertion is made either way.  What IS asserted, in
     * test_set_int_extremes(), is the unambiguous half of the same mechanism:
     * a POSITIVE value whose top byte-bit is set is refused by a destination
     * that could hold it unsigned.
     */

    return ret;
}

/*
 * The return_size side effect, swept across every reachable path of both
 * instantiations at once.
 *
 * num.c:181 assigns param->return_size unconditionally from result.size, and
 * result.size was set to the DESTINATION's declared size at num.c:61 and is
 * written by no other line, so param->return_size == param->data_size is
 * expected to hold identically on success, on PROVNUM_E_TOOBIG and on
 * PROVNUM_E_NULL.  Asserting it once per case elsewhere in this file proves it
 * case by case; asserting it here over a table that deliberately mixes all
 * three outcomes and both source widths proves it is a property of the
 * function rather than of any one input, and makes the removal of num.c:181
 * fail loudly in a dozen places at once instead of one.
 *
 * check_set_side_effects() is shared with run_set_case(), so the invariant has
 * a single implementation and cannot drift between the two.
 */
static int test_set_return_size_invariant(void)
{
    struct rs_case {
        const char *what;
        int use_int;            /* set_int(), else set_size_t() */
        unsigned int data_type;
        size_t capacity;
        int null_data;
        size_t uvalue;
        int ivalue;
        int expected_rc;
    };
    /*
     * Not static const: the boundary values are computed from CHAR_BIT by
     * param_util.h at run time rather than transcribed, which C99 permits in
     * an initialiser for an object of automatic storage duration.
     */
    const struct rs_case cases[] = {
        { "rs: set_int success, exact width", 1, OSSL_PARAM_INTEGER,
          sizeof(int), 0, 0, 5, 1 },
        { "rs: set_int success, over-wide destination", 1, OSSL_PARAM_INTEGER,
          sizeof(int) * 3, 0, 0, 5, 1 },
        { "rs: set_int success, stripped onto one byte", 1, OSSL_PARAM_INTEGER,
          1, 0, 0, 5, 1 },
        { "rs: set_int refused, one byte too small", 1, OSSL_PARAM_INTEGER,
          1, 0, 0, (int)(param_max_signed_in(1) + (uintmax_t)1),
          PROVNUM_E_TOOBIG },
        { "rs: set_int refused, no destination buffer", 1, OSSL_PARAM_INTEGER,
          sizeof(int), 1, 0, 5, PROVNUM_E_NULL },
        { "rs: set_int refused, zero-capacity destination", 1,
          OSSL_PARAM_INTEGER, 0, 0, 0, 0, PROVNUM_E_TOOBIG },
        { "rs: set_int success into an UNSIGNED destination", 1,
          OSSL_PARAM_UNSIGNED_INTEGER, sizeof(int), 0, 0, 5, 1 },
        { "rs: set_size_t success, widest value at its own width", 0,
          OSSL_PARAM_UNSIGNED_INTEGER, sizeof(size_t), 0, SIZE_MAX, 0, 1 },
        { "rs: set_size_t success, within one byte's signed capacity", 0,
          OSSL_PARAM_UNSIGNED_INTEGER, 1, 0, (size_t)param_max_signed_in(1),
          0, 1 },
        { "rs: set_size_t refused, past one byte's signed capacity", 0,
          OSSL_PARAM_UNSIGNED_INTEGER, 1, 0,
          (size_t)(param_max_signed_in(1) + (uintmax_t)1), 0,
          PROVNUM_E_TOOBIG },
        { "rs: set_size_t refused, no destination buffer", 0,
          OSSL_PARAM_UNSIGNED_INTEGER, sizeof(size_t), 1, 5, 0,
          PROVNUM_E_NULL },
        { "rs: set_size_t refused, zero-capacity destination", 0,
          OSSL_PARAM_UNSIGNED_INTEGER, 0, 0, 0, 0, PROVNUM_E_TOOBIG },
        { "rs: set_size_t success, destination wider than a size_t", 0,
          OSSL_PARAM_UNSIGNED_INTEGER, sizeof(size_t) + sizeof(int), 0, 5, 0,
          1 }
    };
    const size_t count = sizeof cases / sizeof cases[0];
    unsigned char buffer[SET_CASE_MAX_BYTES];
    size_t index;
    int ret = 1;

    for (index = 0; index < count; index++) {
        const struct rs_case *c = &cases[index];
        OSSL_PARAM param;
        OSSL_PARAM before;
        int rc;

        param_fill_sentinel(buffer, sizeof buffer);

        if (c->null_data) {
            param_build_null_data(&param, c->data_type, c->capacity);
        } else if (c->capacity == 0) {
            /* The verdict must be asserted; see param_build_empty(). */
            TEST_ASSERT_INT_EQ(c->what,
                               param_build_empty(&param, c->data_type, buffer),
                               1);
            ret &= test;
            if (!test)
                continue;       /* param was left unbuilt; skip this row */
        } else {
            param_build(&param, c->data_type, buffer, c->capacity);
        }

        param_snapshot(&before, &param);

        /* Call, store, then assert -- never read an output in this call. */
        if (c->use_int)
            rc = provnum_set_int(&param, c->ivalue);
        else
            rc = provnum_set_size_t(&param, c->uvalue);

        TEST_ASSERT_INT_EQ(c->what, rc, c->expected_rc);
        ret &= test;
        ret &= check_set_side_effects(c->what, &param, &before);
    }

    /*
     * A table that silently emptied itself would assert nothing and, without
     * this, would still report success for the group.
     */
    TEST_ASSERT_SIZE_EQ("rs: every tabulated path was exercised", index,
                        count);
    ret &= test;

    return ret;
}

/*
 * One sweep of a destination data_type, asserting only what the unreachability
 * proofs in test_set_unreachable_docs() establish: whatever the destination
 * claims to be, the answer is never PROVNUM_E_WRONG_TYPE and never
 * PROVNUM_E_UNSUPPORTED.  The value is positive and comfortably fits, so
 * neither reachable error code can intrude either; the OUTCOME is nonetheless
 * left unasserted, because "the declared destination type ought to have been
 * validated" is one of the two readings Class C #4 keeps open.
 */
static int check_no_unreachable_code(const char *what, unsigned int data_type,
                                     int use_int)
{
    unsigned char buffer[SET_CASE_MAX_BYTES];
    unsigned char sentinel[SET_CASE_MAX_BYTES];
    OSSL_PARAM param;
    OSSL_PARAM before;
    const size_t capacity = sizeof(size_t);
    int ret = 1;
    int rc;

    param_fill_sentinel(buffer, sizeof buffer);
    param_fill_sentinel(sentinel, sizeof sentinel);
    param_build(&param, data_type, buffer, capacity);
    param_snapshot(&before, &param);

    if (use_int)
        rc = provnum_set_int(&param, 5);
    else
        rc = provnum_set_size_t(&param, 5);

    TEST_ASSERT_INT_EQ(what, rc_is_reachable(rc), 1);
    ret &= test;
    ret &= check_set_side_effects(what, &param, &before);

    /*
     * Whatever it decided, it may not have written past the capacity the
     * parameter declared.
     */
    TEST_ASSERT_MEM_EQ(what, buffer + capacity, sentinel + capacity,
                       sizeof buffer - capacity);
    ret &= test;

    return ret;
}

/*
 * THE NAMED EXCLUSIONS.  Two of the four codes include/prov/num.h defines are
 * unreachable through provnum_set_size_t() and provnum_set_int() BY
 * CONSTRUCTION.  They are not missing coverage, and no input can be
 * constructed to reach them; the proofs below say why, and the sweep at the
 * end asserts the complementary fact that makes them evidence rather than
 * assumption.
 *
 * PROVNUM_E_WRONG_TYPE (-1) IS UNREACHABLE.  The guard at num.c:63-64 tests
 * src.data_type, and num.c:176-178 hardcodes that member to the macro
 * parameter DT: OSSL_PARAM_UNSIGNED_INTEGER for the size_t instantiation
 * (num.c:185) and OSSL_PARAM_INTEGER for the int one (num.c:186).  Those are
 * precisely the two types the guard accepts, so it can never fire.  The
 * DESTINATION's data_type is not what that guard reads, which is why the sweep
 * below can walk every OSSL_PARAM data type without producing -1.
 *
 * PROVNUM_E_UNSUPPORTED (-3) IS UNREACHABLE.  The fallthrough at num.c:150 is
 * reached only when the simple-case condition at num.c:121-124 is false.  Its
 * last clause is "(dest.data_type == OSSL_PARAM_INTEGER || src.sign ==
 * POSITIVE)", and num.c:176-178 hardcodes src.sign to POSITIVE, so the second
 * disjunct is always true.  The other three clauses are always true as well:
 * num.c:172-175 and num.c:176-178 give destination and source the same
 * endianness from nativeendian(), a limbsize of 1 and a limbnailbits of 0.
 * The condition therefore cannot be false, so num.c:150 is dead for the
 * setters.
 *
 * THE EMPTY-SOURCE SHORTCUT AND THE NULL-SOURCE GUARD ARE UNREACHABLE TOO.
 * num.c:69-73 needs src.size == 0 and num.c:75-78 needs src.data == NULL, but
 * num.c:176-178 sets src.size to sizeof(T), which is never zero, and src.data
 * to &src, the address of the setter's own parameter, which is never null.
 * Both belong to the getter direction; tests/test_num_get.c is where they are
 * reachable.
 *
 * So exactly two error codes are reachable here, PROVNUM_E_TOOBIG and
 * PROVNUM_E_NULL, and every error case in this file asserts one of them.
 *
 * CLASS C #4 -- DELIBERATE NON-ASSERTION, NOT A GAP.  Do not "complete" this
 * by asserting the emitted value.  The outcome of a setter does not depend on
 * param->data_type at all: writing a negative value into an
 * OSSL_PARAM_UNSIGNED_INTEGER destination behaves exactly as it does into an
 * OSSL_PARAM_INTEGER one.  The mechanism is the same clause as the -3 proof
 * above: dest.data_type is read at num.c:124 and nowhere else in the copy, and
 * that read is already satisfied by src.sign == POSITIVE, so the declared type
 * cannot influence the answer.
 *
 *   (a) A negative value written into a destination the caller has declared
 *       UNSIGNED should be rejected, because the parameter's declared type is
 *       part of its contract with the core.
 *   (b) The setter's job is to serialise the native value it was handed, and
 *       the declared type is advisory metadata the caller owns.
 *
 * include/prov/num.h settles neither, so no case in this file asserts the
 * outcome of a NEGATIVE value into a non-signed destination.  The sweep below
 * uses a positive value for exactly that reason, and asserts only the two
 * exclusions.
 */
static int test_set_unreachable_docs(void)
{
    int ret = 1;

    /*
     * Every OSSL_PARAM data type <openssl/core.h> defines, as the
     * DESTINATION's declared type, through both instantiations.  The five
     * non-integer types are the interesting ones: if the wrong-type guard read
     * the destination instead of the source, or if the simple-case condition
     * could fail, these are the inputs that would show it.
     */
    ret &= check_no_unreachable_code("set_int -> INTEGER destination",
                                     OSSL_PARAM_INTEGER, 1);
    ret &= check_no_unreachable_code("set_size_t -> INTEGER destination",
                                     OSSL_PARAM_INTEGER, 0);
    ret &= check_no_unreachable_code("set_int -> UNSIGNED_INTEGER destination",
                                     OSSL_PARAM_UNSIGNED_INTEGER, 1);
    ret &= check_no_unreachable_code(
        "set_size_t -> UNSIGNED_INTEGER destination",
        OSSL_PARAM_UNSIGNED_INTEGER, 0);
    ret &= check_no_unreachable_code("set_int -> REAL destination",
                                     OSSL_PARAM_REAL, 1);
    ret &= check_no_unreachable_code("set_size_t -> REAL destination",
                                     OSSL_PARAM_REAL, 0);
    ret &= check_no_unreachable_code("set_int -> UTF8_STRING destination",
                                     OSSL_PARAM_UTF8_STRING, 1);
    ret &= check_no_unreachable_code("set_size_t -> UTF8_STRING destination",
                                     OSSL_PARAM_UTF8_STRING, 0);
    ret &= check_no_unreachable_code("set_int -> OCTET_STRING destination",
                                     OSSL_PARAM_OCTET_STRING, 1);
    ret &= check_no_unreachable_code("set_size_t -> OCTET_STRING destination",
                                     OSSL_PARAM_OCTET_STRING, 0);
    ret &= check_no_unreachable_code("set_int -> UTF8_PTR destination",
                                     OSSL_PARAM_UTF8_PTR, 1);
    ret &= check_no_unreachable_code("set_size_t -> UTF8_PTR destination",
                                     OSSL_PARAM_UTF8_PTR, 0);
    ret &= check_no_unreachable_code("set_int -> OCTET_PTR destination",
                                     OSSL_PARAM_OCTET_PTR, 1);
    ret &= check_no_unreachable_code("set_size_t -> OCTET_PTR destination",
                                     OSSL_PARAM_OCTET_PTR, 0);

    return ret;
}
