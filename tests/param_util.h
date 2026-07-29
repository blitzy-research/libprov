/* CC0 license applied, see LICENCE.md */

#ifndef LIBPROV_TESTS_PARAM_UTIL_H
#define LIBPROV_TESTS_PARAM_UTIL_H

/*
 * ===========================================================================
 * tests/param_util.h -- OSSL_PARAM fixtures for the numeric tests
 * ===========================================================================
 *
 * tests/test_num_get.c and tests/test_num_set.c drive num.c's four public
 * conversion functions.  Doing that properly needs three things, and this
 * header supplies exactly those three and nothing else:
 *
 *   1. OSSL_PARAM descriptors built BY HAND over test-owned storage, in every
 *      shape the contract can be asked about -- including the shapes a
 *      well-behaved caller would never produce, such as a null data pointer
 *      with a non-zero data_size, or a non-null buffer with a data_size of
 *      zero.  Those are error-path fixtures, not accidents.
 *   2. multi-byte magnitudes laid out in the HOST's byte order, so a fixture
 *      denotes the same number on a little-endian and on a big-endian
 *      machine.
 *   3. expected byte patterns for the setters, laid out by that same rule, so
 *      that a byte-for-byte assertion is a portable statement rather than an
 *      x86-64 assumption.
 *
 * No user-specified rules exist for this project -- the rules facility reports
 * "No user rules provided" -- so this header is held to ordinary
 * enterprise-standard C practice.  The constraints it does honour come from
 * the project's testing requirements and each one is spelled out below, next
 * to the code that implements it.
 *
 * ---------------------------------------------------------------------------
 * 1.  Division of labour: what lives here and what deliberately does not
 * ---------------------------------------------------------------------------
 *
 * The test suite's shared code is split three ways, and the split is worth
 * knowing before reaching for a helper:
 *
 *   tests/testutil.h    assertions.  It already owns byte-buffer comparison:
 *                       TEST_ASSERT_MEM_EQ() compares two buffers and, on
 *                       mismatch, prints an aligned hex dump of both plus a
 *                       caret row marking every differing offset.
 *   tests/mock_core.h   the err.c side of the suite -- the core handle, the
 *                       recording callbacks, the dispatch tables.  Nothing
 *                       here has anything to do with those.
 *   tests/param_util.h  this file: numeric FIXTURES and EXPECTATIONS.
 *
 * So this header CONSTRUCTS expected byte patterns and does not compare them.
 * Duplicating testutil.h's comparator would give the suite two hex-diff
 * printers to keep in step, and the second one would inevitably drift.  The
 * intended shape of a byte-level assertion is therefore:
 *
 *     unsigned char expected[12];
 *
 *     param_expect_zero_padded(expected, sizeof expected, 5U, sizeof(int));
 *     TEST_ASSERT_MEM_EQ("set_int 5 bytes", dest, expected, sizeof dest);
 *              construct here  ^^^^^^^^                compare there
 *
 * The single exception is param_identical() at the foot of this file, which
 * compares two OSSL_PARAM structs.  It lives here rather than in testutil.h
 * for the reason given at its definition: testutil.h is deliberately free of
 * OpenSSL types, and this is the only shared helper that needs one.
 *
 * Also absent, on purpose: assertion macros, a main(), any allocator or
 * process trickery, and any call to a provnum_ function.  This header builds
 * and describes data; the test programs do the calling and the asserting.
 *
 * ---------------------------------------------------------------------------
 * 2.  OSSL_PARAM is constructed directly.  libcrypto is never involved
 * ---------------------------------------------------------------------------
 *
 * The suite's mocking requirement reads, verbatim:
 *
 *     "Where OpenSSL types are needed, construct them directly or mock them
 *      (e.g., a hand-built dispatch table with stub callbacks); do not add a
 *      dependency on a running provider or on libcrypto functions."
 *
 * For OSSL_PARAM the first branch of that applies: it is a plain public
 * struct of five members, so every fixture here is a direct field assignment
 * over storage the caller owns.  Nothing is allocated and nothing is
 * constructed by libcrypto.
 *
 * <openssl/params.h> is NOT included here and must not be included by any
 * test.  It declares OSSL_PARAM_get_int(), OSSL_PARAM_set_size_t(),
 * OSSL_PARAM_construct_int() and their siblings as libcrypto functions -- and
 * those are precisely the functions libprov reimplements as the provnum_
 * family.  Calling them would both add the forbidden dependency and quietly
 * turn the suite into a test of upstream OpenSSL.  <openssl/core.h>, which
 * defines the struct and the OSSL_PARAM_* data-type constants, arrives
 * transitively through "prov/num.h" below and is all that is needed.
 *
 * The build reflects this: libprov links nothing, and a test executable that
 * uses this header links libc alone.
 *
 * ---------------------------------------------------------------------------
 * 3.  Include guards, and why the project's public headers have none
 * ---------------------------------------------------------------------------
 *
 * include/prov/num.h carries NO include guard, and is right not to need one:
 * it holds four declarations and four object-like macros, so including it
 * twice is harmless.  This header takes the opposite and ordinary position
 * and DOES guard, because it defines functions with internal linkage that a
 * second inclusion would redefine.  The guard above this comment is that
 * guard, and the two positions are consistent rather than contradictory: each
 * file guards exactly as much as its contents require.
 *
 * ---------------------------------------------------------------------------
 * 4.  Byte order is a first-class variable, never an assumption
 * ---------------------------------------------------------------------------
 *
 * num.c decides layout at run time.  nativeendian() (num.c:9-14) steers both
 * the padding-strip loop (num.c:86-91) and the copy (num.c:106-125), so a
 * fixture with hard-coded little-endian bytes would still compile on a
 * big-endian host and would then assert something false.  Every layout helper
 * below therefore asks param_host_endian() at run time, and every width is a
 * parameter derived by the caller from sizeof and CHAR_BIT -- never a
 * transcribed 4, 8, 32 or 64.
 *
 * One implementation of the layout rule serves both the fixture side and the
 * expectation side (param_put_host_order() delegates to
 * param_expect_pattern()), so a fixture and the expectation it is checked
 * against cannot disagree about byte order.
 *
 * ---------------------------------------------------------------------------
 * 5.  Two hazards these helpers exist to keep a test out of
 * ---------------------------------------------------------------------------
 *
 * CALL, STORE, THEN ASSERT.  C does not specify the order in which
 * function-call arguments are evaluated, so reading a destination inside the
 * same expression that calls the function filling it is a bug.  testutil.h
 * section 3 documents the real occurrence.  Nothing here can rescue a test
 * from that; it is repeated because both consumers of this header are exposed
 * to it.
 *
 * USE OSSL_PARAM_INTEGER, NOT OSSL_PARAM_UNSIGNED_INTEGER, FOR THE NULL-DATA
 * AND ZERO-SIZE FIXTURES.  This one is subtle enough to have already cost the
 * suite a blind spot; the full reasoning is at param_build_null_data().
 *
 * ---------------------------------------------------------------------------
 * 6.  A worked example
 * ---------------------------------------------------------------------------
 *
 *     #include "testutil.h"
 *     #include "param_util.h"
 *
 *     static const unsigned char pattern[] = {
 *         0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
 *     };
 *     unsigned char source[sizeof pattern];
 *     OSSL_PARAM param;
 *     size_t value = param_sentinel_size_t();
 *     int rc;
 *
 *     param_put_msb_first(source, sizeof source, pattern, sizeof pattern);
 *     param_build_unsigned(&param, source, sizeof source);
 *
 *     rc = provnum_get_size_t(&value, &param);
 *     TEST_ASSERT_INT_EQ("9-byte padded rc", rc, 1);
 *     TEST_ASSERT_SIZE_EQ("9-byte padded value", value, SIZE_MAX / 2U);
 */

#include <stddef.h>             /* size_t, NULL                              */
#include <string.h>             /* memset, memcpy, memcmp                    */
#include <limits.h>             /* CHAR_BIT, UCHAR_MAX                       */
#include <stdint.h>             /* uintmax_t, UINTMAX_MAX                    */

/*
 * "prov/num.h" is the library header under test.  It is included for its
 * OSSL_PARAM type, which it obtains from <openssl/core.h>; the PROVNUM_E_
 * codes it also defines belong to the test programs' assertions rather than
 * to this file, which never inspects a return code.
 */
#include "prov/num.h"

/*
 * ---------------------------------------------------------------------------
 * Unused-helper discipline
 * ---------------------------------------------------------------------------
 *
 * No consumer uses every helper below, and a static function that is defined
 * but never called draws -Wunused-function.  Marking each definition
 * maybe-unused silences that for the helpers a given translation unit happens
 * not to need, without silencing anything else and without resorting to
 * "static inline" as an oblique way of getting the same effect.
 *
 * The attribute is spelled through this macro rather than through OpenSSL's
 * internal ossl_unused so that nothing here depends on an OpenSSL internal;
 * on a compiler without the GNU attribute syntax the macro vanishes and the
 * only consequence is a diagnostic this header cannot suppress.
 * ---------------------------------------------------------------------------
 */
#if defined(__GNUC__)
# define PARAMUTIL_MAYBE_UNUSED __attribute__((unused))
#else
# define PARAMUTIL_MAYBE_UNUSED
#endif

/*
 * The byte a destination is seeded with before a call that must not touch it.
 * 0xAA is chosen because it is not 0x00, not 0xFF and not a plausible result
 * of any conversion under test, so "the destination still holds the sentinel"
 * and "the destination was left alone" mean the same thing.  Every byte of
 * the pattern is identical, which makes the seeded value of a multi-byte
 * object independent of byte order.
 */
#define PARAM_SENTINEL_BYTE ((unsigned char)0xAAU)

/*
 * ===========================================================================
 * Byte order
 * ===========================================================================
 *
 * The enumerators carry the same values as num.c's own endian_t (num.c:6):
 * BIG is +1 and LITTLE is -1, because in num.c that value doubles as the step
 * from the most significant byte towards the least significant one
 * (num.c:73).  Mirroring the encoding keeps the two files' arithmetic
 * comparable line for line.
 */
typedef enum {
    PARAM_ENDIAN_BIG = 1,
    PARAM_ENDIAN_LITTLE = -1
} param_endian_t;

/*
 * Which end of a multi-byte object holds its most significant byte.
 *
 * This deliberately reproduces num.c:9-14 -- the low-addressed byte of an int
 * holding 1 -- rather than consulting a compiler or system macro such as
 * __BYTE_ORDER__.  The point of the fixtures is to agree with the code under
 * test, and the only way to guarantee that is to ask the same question in the
 * same way: if some exotic host made the two answers differ, a fixture built
 * from a different oracle would misassert while looking correct.  A
 * consequence worth naming: like num.c, this classifies anything that is not
 * pure little-endian as big-endian.  num.c and this header then agree, which
 * is what matters here.
 */
static PARAMUTIL_MAYBE_UNUSED param_endian_t param_host_endian(void)
{
    const int probe = 1;

    return *(const unsigned char *)&probe == 1U
           ? PARAM_ENDIAN_LITTLE
           : PARAM_ENDIAN_BIG;
}

/*
 * The step, in raw byte offsets, from the most significant byte of an object
 * towards its least significant one: +1 on a big-endian host, -1 on a
 * little-endian one.  This is num.c:73's srcmsb2lsb, and it is exactly the
 * numeric value of the endianness, which is why the enumerators above are
 * spelled the way they are.
 */
static PARAMUTIL_MAYBE_UNUSED int param_msb_to_lsb_step(void)
{
    return (int)param_host_endian();
}

/*
 * The raw index, within a `width`-byte object, of the byte at the given
 * SIGNIFICANCE: significance 0 is the least significant byte, significance
 * width - 1 the most significant.
 *
 * This is the single layout primitive of the header -- every writer below is
 * a loop over it, and param_msb_index() and param_lsb_index() are named
 * special cases of it.  Expressing fixtures in terms of significance rather
 * than of raw offsets is what makes them portable: "set the high bit of the
 * next-to-most-significant byte", the condition the padding-strip loop of
 * num.c:86-91 turns on, is significance width - 2 on either host.
 *
 * An out-of-range significance is clamped to the most significant byte rather
 * than allowed to index past the object.  A fixture asking for it is a bug,
 * but a bug in a test must produce a wrong value a comparison can report, not
 * an out-of-bounds access that takes the harness with it.
 */
static PARAMUTIL_MAYBE_UNUSED size_t param_byte_index(size_t width,
                                                      size_t significance)
{
    if (width == 0)
        return 0;
    if (significance >= width)
        significance = width - 1;

    return param_host_endian() == PARAM_ENDIAN_BIG
           ? width - 1 - significance
           : significance;
}

/*
 * The raw index of the most significant byte of a `width`-byte object: 0 on a
 * big-endian host, width - 1 on a little-endian one.  num.c:72's srcmsb.
 *
 * A width of zero yields 0.  num.c reached the same expression with a size of
 * zero and computed data_size - 1, which wrapped and read before the buffer;
 * that was one of the defects the sanctioned repairs to num.c removed, and
 * this helper does not reintroduce the shape.
 */
static PARAMUTIL_MAYBE_UNUSED size_t param_msb_index(size_t width)
{
    return width == 0 ? 0 : param_byte_index(width, width - 1);
}

/*
 * The raw index of the least significant byte of a `width`-byte object:
 * width - 1 on a big-endian host, 0 on a little-endian one.  This is srclsb
 * of num.c:98, computed there as srcmsb + srcmsb2lsb * (size - 1).  The two
 * expressions agree at every width.
 */
static PARAMUTIL_MAYBE_UNUSED size_t param_lsb_index(size_t width)
{
    return param_byte_index(width, 0);
}

/*
 * ===========================================================================
 * Width arithmetic
 * ===========================================================================
 *
 * Boundary values must be DERIVED from a width and CHAR_BIT, never
 * transcribed: a suite that spells 127 and 32767 as literals is asserting an
 * ABI rather than a contract.  These two helpers are pure bit arithmetic and
 * make no claim about what num.c does with the values -- that claim belongs
 * in the test that uses them.  Used in a pair they generate the boundary that
 * matters, "the largest value that fits and the smallest that does not":
 *
 *     largest  = param_max_signed_in(1);        127 where CHAR_BIT is 8
 *     smallest = param_max_signed_in(1) + 1U;   128
 */

/*
 * The largest value representable in `width` bytes with every bit available:
 * 2^(width * CHAR_BIT) - 1.  Zero for a width of zero.  Saturates at
 * UINTMAX_MAX once `width` reaches sizeof(uintmax_t), which is exact at that
 * width and a clamp beyond it.
 */
static PARAMUTIL_MAYBE_UNUSED uintmax_t param_max_unsigned_in(size_t width)
{
    if (width == 0)
        return (uintmax_t)0;
    if (width >= sizeof(uintmax_t))
        return UINTMAX_MAX;

    return ((uintmax_t)1 << (width * CHAR_BIT)) - (uintmax_t)1;
}

/*
 * The largest value representable in `width` bytes with the most significant
 * bit left clear: 2^(width * CHAR_BIT - 1) - 1.  Zero for a width of zero.
 * Exact up to and including sizeof(uintmax_t) bytes, then clamped.
 *
 * This is the boundary that matters wherever a value is laid out in a buffer
 * whose most significant bit carries a sign, which is why it earns a helper
 * of its own next to the all-bits form above.
 */
static PARAMUTIL_MAYBE_UNUSED uintmax_t param_max_signed_in(size_t width)
{
    if (width == 0)
        return (uintmax_t)0;
    if (width >= sizeof(uintmax_t))
        return UINTMAX_MAX >> 1;

    return ((uintmax_t)1 << (width * CHAR_BIT - 1)) - (uintmax_t)1;
}

/*
 * Byte number `significance` of `value`, counting from the least significant.
 *
 * Internal: the public writers below are the interface.  The bound is not
 * defensive tidiness -- shifting a uintmax_t by its own width is undefined
 * behaviour, and a caller may legitimately ask for a buffer wider than
 * uintmax_t (a nine-byte OSSL_PARAM source is a real fixture).  Bytes above
 * the value's width read as zero, which is the zero extension an unsigned
 * value calls for.
 */
static PARAMUTIL_MAYBE_UNUSED unsigned char
paramutil_byte_of(uintmax_t value, size_t significance)
{
    if (significance >= sizeof(uintmax_t))
        return (unsigned char)0;

    return (unsigned char)((value >> (significance * CHAR_BIT))
                           & (uintmax_t)UCHAR_MAX);
}

/*
 * ===========================================================================
 * Laying bytes out
 * ===========================================================================
 *
 * Every writer in this section returns an int rather than void, and the
 * convention is uniform:
 *
 *     1   the request was well formed and has been carried out
 *     0   the request was self-contradictory and NOTHING was written
 *
 * A rejected request leaves the buffer exactly as it was, which is what makes
 * the convention useful rather than merely tidy: a test that seeds its buffer
 * with param_fill_sentinel() first sees an untouched sentinel, so a fixture
 * bug surfaces as a reported mismatch instead of as a half-built fixture that
 * quietly passes.  Asserting the return value is cheap and worth doing where
 * the width and the value are computed rather than literal:
 *
 *     TEST_ASSERT_INT_EQ("fixture built",
 *                        param_put_host_order(buf, sizeof buf, value), 1);
 *
 * Rejection has exactly two causes across the whole section: a null buffer
 * with a non-zero width, and a value region wider than the buffer holding it.
 * Both are test bugs.  A width of zero is not a bug -- a zero-capacity
 * destination is a real fixture -- so it succeeds vacuously, writing nothing.
 */

/*
 * Set every byte of a `width`-byte buffer to `byte`.
 *
 * Byte order does not enter into it, which is exactly why it is useful for
 * seeding: after this call every byte is known, so any byte that later differs
 * was written by the code under test.
 */
static PARAMUTIL_MAYBE_UNUSED int param_fill(void *buf, size_t width,
                                             unsigned char byte)
{
    if (width == 0)
        return 1;
    if (buf == NULL)
        return 0;

    memset(buf, (int)byte, width);
    return 1;
}

/*
 * Seed a buffer with PARAM_SENTINEL_BYTE.  Use it before every call that must
 * leave its destination untouched -- which is every error path of the four
 * conversion functions -- so that "unmodified" becomes an assertable fact
 * rather than an assumption:
 *
 *     unsigned char dest[4];
 *     unsigned char untouched[sizeof dest];
 *
 *     param_fill_sentinel(dest, sizeof dest);
 *     param_fill_sentinel(untouched, sizeof untouched);
 *     ... call something that must fail ...
 *     TEST_ASSERT_MEM_EQ("dest untouched", dest, untouched, sizeof dest);
 */
static PARAMUTIL_MAYBE_UNUSED int param_fill_sentinel(void *buf, size_t width)
{
    return param_fill(buf, width, PARAM_SENTINEL_BYTE);
}

/*
 * Lay out "the low `value_bytes` bytes hold `value`, the remaining
 * width - value_bytes more significant bytes hold `pad`", in host byte order.
 *
 * This is the general layout worker of the header: param_put_host_order()
 * below is the case where the value fills the whole buffer, and
 * param_expect_zero_padded() is the case where the pad is 0x00.  Keeping one
 * implementation is deliberate -- a fixture and the expectation it is checked
 * against are laid out by the same code, so they cannot disagree about byte
 * order even if that code were wrong.
 *
 * `value` is taken as a bit pattern, not as a number with a sign: only its low
 * `value_bytes` bytes are consulted, so a negative int may be handed over
 * either as (uintmax_t)(unsigned int)v or as (uintmax_t)v and both produce the
 * same bytes.  Bytes of the value region above sizeof(uintmax_t) read as zero.
 *
 * Worked, on a little-endian host with 8-bit bytes and a 4-byte int:
 *
 *     param_expect_pattern(e, 12, 5U, sizeof(int), 0x00)
 *         -> 05 00 00 00 | 00 00 00 00 00 00 00 00
 *     param_expect_pattern(e, 12, (uintmax_t)(unsigned int)-5,
 *                          sizeof(int), 0x00)
 *         -> FB FF FF FF | 00 00 00 00 00 00 00 00
 *     param_expect_pattern(e, 3, 0x010203U, 3, 0x00)
 *         -> 03 02 01
 *
 * On a big-endian host each of those buffers is the same sequence read the
 * other way round, and every one of the three is produced by this one call.
 */
static PARAMUTIL_MAYBE_UNUSED int param_expect_pattern(void *buf, size_t width,
                                                       uintmax_t value,
                                                       size_t value_bytes,
                                                       unsigned char pad)
{
    unsigned char *bytes = (unsigned char *)buf;
    size_t significance;

    if (value_bytes > width)
        return 0;
    if (width == 0)
        return 1;
    if (bytes == NULL)
        return 0;

    /* The more significant remainder first: it is the part `pad` describes. */
    for (significance = value_bytes; significance < width; significance++)
        bytes[param_byte_index(width, significance)] = pad;

    /* Then the value, least significant byte first. */
    for (significance = 0; significance < value_bytes; significance++)
        bytes[param_byte_index(width, significance)] =
            paramutil_byte_of(value, significance);

    return 1;
}

/*
 * Write `value` across the whole of a `width`-byte buffer in host byte order:
 * the least significant byte lands at index 0 on a little-endian host and at
 * index width - 1 on a big-endian one.  A buffer wider than the value is zero
 * extended, which is the right reading because `value` is unsigned.
 *
 * This is the workhorse for building OSSL_PARAM source buffers:
 *
 *     unsigned char source[sizeof(size_t)];
 *
 *     param_put_host_order(source, sizeof source, SIZE_MAX);
 *     param_build_unsigned(&param, source, sizeof source);
 */
static PARAMUTIL_MAYBE_UNUSED int param_put_host_order(void *buf, size_t width,
                                                       uintmax_t value)
{
    /*
     * value_bytes == width, so the pad region is empty and the pad byte is
     * never consulted; 0x00 is passed only because the parameter must be
     * given something.
     */
    return param_expect_pattern(buf, width, value, width, (unsigned char)0);
}

/*
 * The zero-padded case of param_expect_pattern(), which is the only case the
 * setters ever produce.
 *
 * That is not a convenience assumption but a property of the code: the source
 * descriptor the provnum_set_ half of implement_provnum builds hardwires its
 * sign to POSITIVE (num.c:155), and the padding memset at num.c:114 writes
 * that sign.  POSITIVE is 0x00 (num.c:7), so a destination wider than the
 * value is zero filled whatever the value's own sign -- including for a
 * negative int, where a reader might expect the pad to be 0xFF.  Whether that
 * SHOULD be sign extension is a genuinely open question about the contract,
 * and it is left open: this helper describes the bytes, and the argument over
 * what they ought to be belongs in tests/test_num_set.c, which is where the
 * ambiguity is recorded.
 */
static PARAMUTIL_MAYBE_UNUSED int param_expect_zero_padded(void *buf,
                                                           size_t width,
                                                           uintmax_t value,
                                                           size_t value_bytes)
{
    return param_expect_pattern(buf, width, value, value_bytes,
                                (unsigned char)0);
}

/*
 * Lay out a logical byte pattern given MOST SIGNIFICANT BYTE FIRST, whatever
 * the host's byte order.
 *
 * This is the mirror of param_put_host_order() and exists for the fixtures a
 * magnitude cannot express: a nine-byte OSSL_PARAM source is wider than any
 * integer type, and the padding-strip rules of num.c:86-91 turn on individual
 * bit patterns rather than on a value.  Written this way a fixture reads as
 * the number it denotes:
 *
 *     static const unsigned char nine[] = {
 *         0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
 *     };
 *     unsigned char source[sizeof nine];
 *
 *     param_put_msb_first(source, sizeof source, nine, sizeof nine);
 *
 * On a big-endian host `source` ends up a copy of `nine`; on a little-endian
 * one it ends up reversed, FF FF FF FF FF FF FF 7F 00.  Either way it denotes
 * the same number -- here SIZE_MAX / 2 where size_t is eight bytes, carried in
 * nine bytes with one byte of strippable padding on top.
 *
 * A pattern shorter than the buffer occupies the least significant end and the
 * more significant remainder is zeroed, so a narrow pattern means the number
 * it looks like rather than whatever was on the stack.  A pattern LONGER than
 * the buffer is rejected outright: silently dropping its leading bytes would
 * change the number the fixture denotes, which is the one thing a fixture
 * helper must never do quietly.
 */
static PARAMUTIL_MAYBE_UNUSED int
param_put_msb_first(void *buf, size_t width, const unsigned char *msb_first,
                    size_t count)
{
    unsigned char *bytes = (unsigned char *)buf;
    size_t significance;

    if (count > width)
        return 0;
    if (count != 0 && msb_first == NULL)
        return 0;
    if (width == 0)
        return 1;
    if (bytes == NULL)
        return 0;

    for (significance = count; significance < width; significance++)
        bytes[param_byte_index(width, significance)] = (unsigned char)0;

    /*
     * msb_first[0] is the most significant byte of the pattern, so pattern
     * element `pos` carries significance count - 1 - pos.
     */
    for (significance = 0; significance < count; significance++)
        bytes[param_byte_index(width, significance)] =
            msb_first[count - 1 - significance];

    return 1;
}

/*
 * ===========================================================================
 * Sentinel values for integer destinations
 * ===========================================================================
 *
 * The conversion getters write through a size_t * or an int *, not into a
 * buffer, so the destination-untouched invariant needs a recognisable VALUE
 * rather than a recognisable byte pattern.  These two return the value whose
 * every byte is PARAM_SENTINEL_BYTE, which is what makes the invariant a
 * one-line assertion:
 *
 *     size_t value = param_sentinel_size_t();
 *     int rc = provnum_get_size_t(&value, &param);
 *
 *     TEST_ASSERT_INT_EQ("oversize rc", rc, PROVNUM_E_TOOBIG);
 *     TEST_ASSERT_SIZE_EQ("dest untouched", value, param_sentinel_size_t());
 *
 * Both are pure: each builds the value in a local and returns it, so there is
 * no shared state and calling one twice in an expression is safe.  Because
 * every byte of the pattern is the same, the value does not depend on byte
 * order and the same call may be used on both sides of the comparison.
 */

/* The size_t whose every byte is PARAM_SENTINEL_BYTE. */
static PARAMUTIL_MAYBE_UNUSED size_t param_sentinel_size_t(void)
{
    size_t value;

    memset(&value, (int)PARAM_SENTINEL_BYTE, sizeof value);
    return value;
}

/*
 * The int whose every byte is PARAM_SENTINEL_BYTE.  It is negative wherever
 * int is two's complement, which is all the more distinguishable from a
 * successful conversion of any of the fixtures in this suite.
 */
static PARAMUTIL_MAYBE_UNUSED int param_sentinel_int(void)
{
    int value;

    memset(&value, (int)PARAM_SENTINEL_BYTE, sizeof value);
    return value;
}

/*
 * ===========================================================================
 * OSSL_PARAM construction
 * ===========================================================================
 *
 * OSSL_PARAM has five members and <openssl/core.h> fixes their order:
 *
 *     struct ossl_param_st {
 *         const char *key;         the name of the parameter
 *         unsigned int data_type;  what kind of content is in the buffer
 *         void *data;              the value being passed in or out
 *         size_t data_size;        data size
 *         size_t return_size;      returned content size
 *     };
 *
 * so the project's own idiom for a parameter is one brace initialiser:
 *
 *     OSSL_PARAM p = { NULL, OSSL_PARAM_INTEGER, buf, sizeof buf, 0 };
 *
 * The builders below produce precisely that, field for field, and are worth
 * having only for what a brace initialiser cannot do.  They are functions, not
 * macros, so the compiler checks that `data` really is a pointer and that
 * `data_size` really is an integer -- a brace initialiser with two arguments
 * transposed is well formed C and produces a fixture that means something
 * quite different.  And a name says which fixture is intended: an
 * OSSL_PARAM whose data pointer is null with a size of four is a deliberate
 * error-path fixture, not a typo, and param_build_null_data() says so where
 * a bare initialiser could not.
 *
 * Two fields are fixed by all of them:
 *
 *   key          NULL.  libprov never reads it -- num.c refers to data,
 *                data_type, data_size and return_size and to nothing else, as
 *                a search of the file confirms -- so a fixture that set a name
 *                would be asserting relevance the code does not have.
 *   return_size  0, so that a setter's write to it is visible as a change.
 *                Every provnum_set_ call assigns it, on success and on every
 *                error path alike (num.c:159), and seeding it to zero is what
 *                lets a test see the assignment rather than a leftover.
 *
 * Every combination of data_type, data and data_size is a legitimate fixture
 * here -- the awkward ones are the whole point -- so, unlike the writers
 * above, these have no self-contradictory input to report and return void.
 * The one impossible argument, a null OSSL_PARAM *, is treated as a no-op:
 * a test always passes the address of a local, so it cannot arise, and if a
 * later refactor made it arise it should not crash the harness.
 */

/*
 * The general builder: all five members, three of them from the caller.
 *
 * Use it directly for the data types no convenience covers -- the five
 * non-integer ones, OSSL_PARAM_REAL through OSSL_PARAM_OCTET_PTR, which are
 * what a wrong-type test needs -- and prefer the named forms below otherwise.
 *
 * The memset is the third reason these are functions.  OSSL_PARAM has padding
 * between data_type and data on a typical 64-bit target, and neither a brace
 * initialiser nor a sequence of member assignments is required to give those
 * bytes any particular value: after
 *
 *     OSSL_PARAM p = { NULL, OSSL_PARAM_INTEGER, buf, sizeof buf, 0 };
 *
 * the five members are fixed and the padding is unspecified.  Clearing the
 * object first makes the WHOLE representation of a fixture deterministic, not
 * merely the part with names.  That costs nothing, it removes a source of
 * run-to-run variation from the suite, and it means two parameters built here
 * from equal arguments really are equal all the way down -- which is what lets
 * param_identical() at the foot of this file be a byte comparison rather than
 * a member-by-member one.
 */
static PARAMUTIL_MAYBE_UNUSED void param_build(OSSL_PARAM *param,
                                               unsigned int data_type,
                                               void *data, size_t data_size)
{
    if (param == NULL)
        return;

    memset(param, 0, sizeof *param);

    param->key = NULL;
    param->data_type = data_type;
    param->data = data;
    param->data_size = data_size;
    param->return_size = 0;
}

/*
 * A signed-integer parameter over a caller-owned buffer.
 *
 * OSSL_PARAM_INTEGER is the type whose most significant byte carries a sign,
 * so it is the type that reaches num.c's sign detection, its sign-extension
 * padding rules and its negative-value paths.  It is also the type the
 * null-data and zero-size fixtures must use; see param_build_null_data().
 */
static PARAMUTIL_MAYBE_UNUSED void param_build_integer(OSSL_PARAM *param,
                                                       void *data,
                                                       size_t data_size)
{
    param_build(param, OSSL_PARAM_INTEGER, data, data_size);
}

/*
 * An unsigned-integer parameter over a caller-owned buffer.
 *
 * OSSL_PARAM_UNSIGNED_INTEGER short-circuits num.c's sign detection to
 * positive (num.c:21-22), which is what makes it the right type for magnitude
 * fixtures -- an all-bits-set buffer means SIZE_MAX here and -1 under
 * OSSL_PARAM_INTEGER -- and the wrong type for anything that needs to reach
 * the code past that short circuit.
 */
static PARAMUTIL_MAYBE_UNUSED void param_build_unsigned(OSSL_PARAM *param,
                                                        void *data,
                                                        size_t data_size)
{
    param_build(param, OSSL_PARAM_UNSIGNED_INTEGER, data, data_size);
}

/*
 * A parameter with NO data buffer but a non-zero declared size: the fixture
 * for the null-source contract, whose documented answer is PROVNUM_E_NULL.
 *
 * USE OSSL_PARAM_INTEGER HERE.  This is the single most important choice in
 * the numeric fixtures, and it is not a matter of taste.
 *
 * paramsign() (num.c:16-26) returns positive IMMEDIATELY for an unsigned data
 * type, before it would look at the buffer at all.  A null-data fixture typed
 * OSSL_PARAM_UNSIGNED_INTEGER therefore never drives execution through the
 * code that touches the source buffer, and is structurally incapable of
 * detecting anything about how a null buffer is handled there -- it exercises
 * the short circuit instead and passes for the wrong reason.  A fixture typed
 * OSSL_PARAM_INTEGER does reach that code, so the assertion means what it
 * appears to mean.
 *
 * This was measured, not reasoned about afterwards.  With the fixtures typed
 * unsigned, deleting num.c's guard against the pre-validation dereference
 * changed no test result at all.  Retyping the same fixtures signed made the
 * deletion fail immediately.  The unsigned spelling is not merely weaker; it
 * is blind.
 *
 *     param_build_null_data(&param, OSSL_PARAM_INTEGER, sizeof(size_t));
 *
 * The data_type stays a parameter because one fixture legitimately needs
 * another value: pairing a null buffer with a non-integer type such as
 * OSSL_PARAM_OCTET_STRING is how a test pins which of the two guards is
 * consulted first, and the answer there is PROVNUM_E_WRONG_TYPE.
 */
static PARAMUTIL_MAYBE_UNUSED void
param_build_null_data(OSSL_PARAM *param, unsigned int data_type,
                      size_t data_size)
{
    param_build(param, data_type, NULL, data_size);
}

/*
 * A parameter with a real buffer but a declared size of ZERO.
 *
 * The same signed-versus-unsigned reasoning as param_build_null_data() applies
 * in full, for the same reason: a zero size is the other input that once made
 * num.c index outside its source buffer, and paramsign()'s short circuit hides
 * it just as effectively.  Prefer OSSL_PARAM_INTEGER.
 *
 * The shape reads two ways depending on which side of a conversion it is on,
 * and both are real fixtures.  As a getter's SOURCE it is an empty number,
 * whose documented answer is success with a zeroed destination -- and that
 * shortcut is taken before the destination is checked, so it succeeds even
 * where the destination pointer is null.  As a setter's DESTINATION it is a
 * zero-capacity buffer, which nothing fits into, and the answer is
 * PROVNUM_E_TOOBIG with return_size left at zero.
 *
 * `data` is a parameter rather than fixed so that the buffer stays a real
 * address: what distinguishes this fixture from param_build_null_data() is
 * exactly that the pointer is valid, and passing NULL here would collapse the
 * two.
 */
static PARAMUTIL_MAYBE_UNUSED void param_build_empty(OSSL_PARAM *param,
                                                     unsigned int data_type,
                                                     void *data)
{
    param_build(param, data_type, data, 0);
}

/*
 * ===========================================================================
 * The did-not-touch-the-parameter invariant
 * ===========================================================================
 *
 * provnum_get_size_t() and provnum_get_int() take a const OSSL_PARAM *, so the
 * type system already forbids them writing to it.  These two helpers check the
 * claim at the level below the type system, where a cast could have discarded
 * the qualifier: the parameter's REPRESENTATION is the same afterwards, byte
 * for byte.  Verified against the real code, which leaves it identical.
 *
 *     OSSL_PARAM param, before;
 *
 *     param_build_unsigned(&param, source, sizeof source);
 *     param_snapshot(&before, &param);
 *     rc = provnum_get_size_t(&value, &param);
 *     TEST_ASSERT_INT_EQ("param untouched",
 *                        param_identical(&param, &before), 1);
 *
 * These belong here and not in testutil.h because testutil.h is deliberately
 * free of OpenSSL types -- it includes nothing but the C standard library, so
 * that it may be included ahead of anything without perturbing it -- and an
 * OSSL_PARAM comparator cannot be written under that constraint.  This is the
 * only comparison in this header for that reason; byte buffers are compared
 * with testutil.h's TEST_ASSERT_MEM_EQ(), as section 1 above explains.
 */

/*
 * Copy a parameter's representation aside for later comparison.
 *
 * memcpy, not `*snapshot = *param`, and the distinction is load-bearing rather
 * than stylistic.  OSSL_PARAM has padding on a typical 64-bit target -- an
 * unsigned int between two pointers leaves a hole -- and a struct assignment
 * is not required to copy padding bytes, so a snapshot taken by assignment
 * could differ from its original in bytes nobody ever wrote.  That would make
 * param_identical() report a spurious difference and turn a sound invariant
 * into an intermittent failure.  memcpy copies the object's bytes, all of
 * them, which is what a byte-for-byte comparison afterwards needs.
 */
static PARAMUTIL_MAYBE_UNUSED void param_snapshot(OSSL_PARAM *snapshot,
                                                  const OSSL_PARAM *param)
{
    if (snapshot == NULL || param == NULL)
        return;

    memcpy(snapshot, param, sizeof *snapshot);
}

/*
 * Whether two parameters have identical representations: 1 if they do, 0 if
 * they do not.
 *
 * Intended for a parameter against a param_snapshot() of itself, which is why
 * comparing padding is safe here -- the snapshot's padding was copied from the
 * original's, so any difference the comparison reports was written after the
 * snapshot was taken.  It is equally safe between two parameters that
 * param_build() produced, because that clears the padding.
 *
 * ONE COMBINATION IS NOT SAFE, and it is the tempting one: comparing a
 * param_build() result against a hand-written brace initialiser.  Those two
 * agree in all five members and may still differ in their padding, because a
 * brace initialiser leaves padding unspecified while param_build() zeroes it.
 * This is not hypothetical -- writing that comparison while validating this
 * header produced exactly that failure, with every member verified equal
 * one line earlier.  Compare the members when that is the claim:
 *
 *     TEST_ASSERT_UINT_EQ("data_type", param.data_type, braced.data_type);
 *     TEST_ASSERT_PTR_EQ("data", param.data, braced.data);
 *
 * or snapshot one of them and compare against the snapshot.
 *
 * A predicate rather than an assertion: it returns a verdict for
 * TEST_ASSERT() to record and print, keeping assertion output the concern of
 * the one file that owns it.  Two null pointers count as identical and one
 * null pointer never matches a parameter, so a fixture slip yields a verdict
 * instead of dereferencing nothing.
 */
static PARAMUTIL_MAYBE_UNUSED int param_identical(const OSSL_PARAM *param,
                                                  const OSSL_PARAM *snapshot)
{
    if (param == NULL || snapshot == NULL)
        return param == snapshot;

    return memcmp(param, snapshot, sizeof *param) == 0;
}

#endif                          /* LIBPROV_TESTS_PARAM_UTIL_H */

