/* CC0 license applied, see LICENSE */

#ifndef LIBPROV_TESTS_PARAM_UTIL_H
#define LIBPROV_TESTS_PARAM_UTIL_H

/*
 * OSSL_PARAM fixtures for the libprov numeric tests: descriptors built BY HAND
 * over test-owned storage.  OSSL_PARAM needs no constructor, being a plain
 * public struct whose five members <openssl/core.h> fixes.  Its OSSL_PARAM_get_*,
 * set_* and construct_* families are the libcrypto functions provnum_ replaces
 * and not one of them is ever called; <openssl/params.h> is neither included
 * here nor reached from here, prov/num.h pulling in only <openssl/core.h>, so
 * it is genuinely absent from both translation units that include this header.
 * (The five tests that include prov/err.h instead DO reach it transitively --
 * through <openssl/core_dispatch.h> and <openssl/indicator.h> -- which is why
 * the suite-wide rule is stated as "never called" rather than "never
 * included"; see tests/testutil.h.)
 *
 * Byte order is a variable, not an assumption: every helper takes a byte's
 * SIGNIFICANCE and computes the raw index for the running host, and a fixture
 * and its expectation are laid out by the same rule so the two cannot
 * disagree.  Widths derive from sizeof and CHAR_BIT.  Null-data and zero-size
 * fixtures are typed OSSL_PARAM_INTEGER; param_build_null_data() says why.
 *
 * ALIASING IS A GUARANTEE HERE: param_put_msb_first(buf, n, buf, n) and
 * param_snapshot(&p, &p) are reachable calls, so every helper answers the same
 * whether source and destination are one object, partly overlapping or wholly
 * disjoint.  Two rules deliver that and must be preserved -- memmove() rather
 * than memcpy() for any copy whose operands the caller chooses, memcpy() being
 * defined only for non-overlapping regions (C99 7.21.2.1); and a transform
 * that both reads and writes finishes with the source before it disturbs the
 * destination.
 */

#include <stddef.h>
#include <string.h>
#include <limits.h>
#include <stdint.h>

#include "prov/num.h"

/*
 * No consumer uses every helper below, so the ones a given translation unit
 * never calls are marked as legitimately unused.
 */
#if defined(__GNUC__)
# define PARAMUTIL_MAYBE_UNUSED __attribute__((unused))
#else
# define PARAMUTIL_MAYBE_UNUSED
#endif

/*
 * The byte a destination is seeded with before a call that must not touch it:
 * distinct from the zero and sign padding the conversions write, and uniform,
 * so a multi-byte object's seeded value ignores byte order.  This is the
 * sentinel for a BYTE BUFFER; a destination that is an integer object is
 * seeded with param_sentinel_size_t() or param_sentinel_int() instead.
 */
#define PARAM_SENTINEL_BYTE ((unsigned char)0xAAU)

/*
 * The same values as num.c's own endian_t, where the value doubles as
 * srcmsb2lsb, the step from the most significant byte towards the least.
 */
typedef enum {
    PARAM_ENDIAN_BIG = 1,
    PARAM_ENDIAN_LITTLE = -1
} param_endian_t;

/*
 * Which end of a multi-byte object holds its most significant byte.  It
 * reproduces num.c's nativeendian() rather than consulting __BYTE_ORDER__,
 * because a fixture must agree with the code under test; anything not purely
 * little-endian counts as big.
 */
static PARAMUTIL_MAYBE_UNUSED param_endian_t param_host_endian(void)
{
    const int probe = 1;

    return *(const unsigned char *)&probe == 1U
           ? PARAM_ENDIAN_LITTLE
           : PARAM_ENDIAN_BIG;
}

/*
 * num.c's srcmsb2lsb: the step, in raw byte offsets, from an object's most
 * significant byte towards its least, and exactly the numeric value of the
 * endianness -- hence the enumerators above.
 */
static PARAMUTIL_MAYBE_UNUSED int param_msb_to_lsb_step(void)
{
    return (int)param_host_endian();
}

/*
 * The raw index, within a `width`-byte object, of the byte at the given
 * SIGNIFICANCE, 0 being the least significant: the header's single layout
 * primitive, which every writer below loops over.  Significance is what makes
 * a fixture portable: "the high bit of the next-to-most-significant byte",
 * which provnum_copy()'s padding-strip loop turns on, sits at significance
 * (width - 2) on either host.  An out-of-range value is clamped, avoiding a
 * bad access.
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
 * num.c's srcmsb.  A width of zero yields 0; num.c reached this expression
 * with a size of zero, computed data_size - 1, wrapped and read before the
 * buffer.
 */
static PARAMUTIL_MAYBE_UNUSED size_t param_msb_index(size_t width)
{
    return width == 0 ? 0 : param_byte_index(width, width - 1);
}

/*
 * num.c's srclsb, computed there as srcmsb + srcmsb2lsb * (size - 1).
 */
static PARAMUTIL_MAYBE_UNUSED size_t param_lsb_index(size_t width)
{
    return param_byte_index(width, 0);
}

/*
 * Boundary values must be DERIVED from a width and CHAR_BIT, never
 * transcribed: a suite spelling 127 and 32767 as literals asserts an ABI
 * rather than a contract.  Used in a pair the two below generate the boundary
 * that matters, the largest value that fits and the smallest that does not.
 */

/*
 * The largest value representable in `width` bytes with every bit available.
 * Saturating at UINTMAX_MAX is exact at sizeof(uintmax_t) and a clamp beyond.
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
 * bit left clear -- the boundary that matters wherever that bit carries a
 * sign -- exact up to sizeof(uintmax_t) bytes, then clamped.
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
 * The bound is not defensive tidiness: shifting a uintmax_t by its own width
 * is undefined behaviour, and a buffer wider than uintmax_t is a real fixture
 * -- a nine-byte OSSL_PARAM source, whose upper bytes read as zero.
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
 * Every writer below returns 1 when the request was well formed and carried
 * out, 0 when it was self-contradictory and NOTHING was written -- so a
 * buffer seeded with param_fill_sentinel() still holds the sentinel and a
 * fixture bug surfaces as a reported mismatch.  Each documents the invalid
 * combinations it rejects; a width of zero is not one, a zero-capacity
 * destination being a fixture.
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
 * Seed a buffer with PARAM_SENTINEL_BYTE, before every call that must leave
 * its destination untouched -- every conversion error path -- so that
 * "unmodified" becomes an assertable fact.
 */
static PARAMUTIL_MAYBE_UNUSED int param_fill_sentinel(void *buf, size_t width)
{
    return param_fill(buf, width, PARAM_SENTINEL_BYTE);
}

/*
 * Lay out "the low `value_bytes` bytes hold `value`, the remaining more
 * significant bytes hold `pad`" in host byte order.  `value` is a bit pattern,
 * not a signed number.  Returns 0 having written nothing when value_bytes
 * exceeds width, or when the buffer is null and width is non-zero.
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

    for (significance = value_bytes; significance < width; significance++)
        bytes[param_byte_index(width, significance)] = pad;

    for (significance = 0; significance < value_bytes; significance++)
        bytes[param_byte_index(width, significance)] =
            paramutil_byte_of(value, significance);

    return 1;
}

/*
 * Write `value` across the whole of a `width`-byte buffer in host byte order,
 * a wider buffer being zero extended since `value` is unsigned.
 */
static PARAMUTIL_MAYBE_UNUSED int param_put_host_order(void *buf, size_t width,
                                                       uintmax_t value)
{
    return param_expect_pattern(buf, width, value, width, (unsigned char)0);
}

/*
 * The zero-padded case of param_expect_pattern(), and the only case the
 * setters produce -- a property of the code, not a convenience assumption:
 * the source descriptor the provnum_set_ half of implement_provnum builds
 * hardwires its sign to POSITIVE, provnum_copy()'s padding memset writes that
 * sign, and POSITIVE is 0x00 in num.c's sign_t.  A wider destination is
 * therefore zero filled even for a negative int, where a reader might expect
 * 0xFF.  Whether it SHOULD be sign extension is genuinely open;
 * tests/test_num_set.c records both readings in its Class C #2 block and
 * asserts neither.
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
 * the host's byte order: the mirror of param_put_host_order(), for fixtures a
 * magnitude cannot express, a nine-byte OSSL_PARAM source being wider than
 * any integer type.  A shorter pattern occupies the least significant end,
 * the remainder zeroed; a LONGER one is rejected, dropping leading bytes
 * being a change to the number denoted.
 *
 * `buf` and `msb_first` MAY OVERLAP, the same address included.  The
 * pattern is moved to where it belongs FIRST, so the source is read once
 * and never after a byte of it has been overwritten, and the padding is
 * zeroed LAST because it may well cover where the pattern was read from.
 * That order is not incidental: zeroing first and then placing the pattern
 * byte by byte -- the obvious shape, and the shape this function had --
 * turns param_put_msb_first(b, 3, b, 3) over { 1, 2, 3 } into 03 02 03 on
 * a little-endian host, b[0] having already been made 3 by the time it is
 * read as the most significant byte.  That call denotes 03 02 01, which is
 * what the code below writes.
 */
static PARAMUTIL_MAYBE_UNUSED int
param_put_msb_first(void *buf, size_t width, const unsigned char *msb_first,
                    size_t count)
{
    unsigned char *bytes = (unsigned char *)buf;
    const param_endian_t order = param_host_endian();
    unsigned char *pattern;
    unsigned char *padding;

    if (count > width)
        return 0;
    if (count != 0 && msb_first == NULL)
        return 0;
    if (width == 0)
        return 1;
    if (bytes == NULL)
        return 0;

    /*
     * Significances 0 .. count - 1 are contiguous under either byte order, so
     * the pattern occupies one run of `count` bytes and the more significant
     * remainder one run of width - count bytes.  Each base address below is
     * the layout primitive evaluated at the low-addressed end of its own run,
     * spelled out here so the arithmetic stays checkable against
     * param_byte_index() instead of standing on its own:
     *
     *     BIG     pattern  param_byte_index(width, count - 1) = width - count
     *             padding  param_byte_index(width, width - 1) = 0
     *     LITTLE  pattern  param_byte_index(width, 0)         = 0
     *             padding  param_byte_index(width, count)     = count
     */
    if (order == PARAM_ENDIAN_BIG) {
        pattern = bytes + (width - count);
        padding = bytes;
    } else {
        pattern = bytes;
        padding = bytes + count;
    }

    /*
     * The move goes first, so that an overlapping `msb_first` is read before
     * any of it can be disturbed.  memmove() rather than memcpy() because the
     * caller chooses both operands and may pass one twice.  Guarded on a
     * non-zero count: a null pattern with a count of zero is accepted above,
     * and a null pointer is not a valid memmove() argument at any length.
     */
    if (count != 0)
        memmove(pattern, msb_first, count);

    /*
     * On a big-endian host most-significant-first IS the host's own order, so
     * the run is already as it should be.  On a little-endian one the two run
     * in opposite directions, and the moved run is turned round where it lies
     * -- which needs no second look at `msb_first`, the whole point of having
     * moved it.  One byte is its own reverse and none is trivially so;
     * count - 1 is formed only inside the guard, where it cannot wrap.
     */
    if (count > 1 && order == PARAM_ENDIAN_LITTLE) {
        size_t low;
        size_t high;

        for (low = 0, high = count - 1; low < high; low++, high--) {
            unsigned char swapped = pattern[low];

            pattern[low] = pattern[high];
            pattern[high] = swapped;
        }
    }

    /*
     * The padding goes last.  It cannot reach the pattern's run, the two being
     * disjoint by construction, but it may well cover where `msb_first` was --
     * which is precisely why it may not run any earlier.
     */
    if (width > count)
        memset(padding, 0, width - count);

    return 1;
}

/*
 * The getters write through a size_t * or an int *, not into a buffer, so the
 * destination-untouched invariant needs a recognisable VALUE rather than a
 * byte pattern.  Both below are pure and compute their value by ARITHMETIC,
 * never by writing bytes into an integer object and reading it back: C99
 * 6.2.6.2 lets an integer type carry padding bits, and for a SIGNED type
 * leaves it implementation-defined whether a given combination of sign and
 * value bits is a value at all or a TRAP REPRESENTATION.  Filling a BYTE
 * buffer with PARAM_SENTINEL_BYTE -- param_fill_sentinel() above -- stays as
 * it was, unsigned char having neither padding bits nor trap representations.
 *
 * Both values are ones no fixture in this suite can produce, so "still holds
 * the sentinel" and "was left alone" mean the same thing.  Keep it that way:
 * do not add a case whose expected result is either sentinel.
 */

/*
 * PARAM_SENTINEL_BYTE repeated across every byte of a size_t, 0xAAAA...AA,
 * built by shifting: size_t is unsigned, so each step is reduction modulo the
 * type's range rather than overflow.  The size_t cases here convert to 0, 5,
 * 0x010203, SIZE_MAX and SIZE_MAX / 2, none of which is this pattern at any
 * width.
 */
static PARAMUTIL_MAYBE_UNUSED size_t param_sentinel_size_t(void)
{
    size_t value = 0;
    size_t pos;

    for (pos = 0; pos < sizeof value; pos++) {
        value <<= CHAR_BIT;
        value |= (size_t)PARAM_SENTINEL_BYTE;
    }

    return value;
}

/*
 * -INT_MAX: an ordinary value of type int on every conforming
 * implementation, because INT_MAX is representable and INT_MIN is never
 * greater than -INT_MAX whatever the sign representation.  It is always
 * negative, always at the far edge of the range, and the result of no fixture
 * in this suite.  INT_MIN would be equally portable and is deliberately NOT
 * used: the suite converts a natural-width source to exactly INT_MIN as one
 * of its boundary cases, so seeding with INT_MIN there would let a dropped
 * write pass for a successful conversion.
 */
static PARAMUTIL_MAYBE_UNUSED int param_sentinel_int(void)
{
    return -INT_MAX;
}

/*
 * <openssl/core.h> fixes OSSL_PARAM's five members and their order -- key,
 * data_type, data, data_size, return_size -- so the project's own idiom is
 * one brace initialiser.  The builders below produce exactly that, and earn
 * their place through what an initialiser cannot do: the compiler checks that
 * `data` is a pointer and `data_size` an integer, where an initialiser with
 * those transposed is well formed C meaning something else.  All fix key to
 * NULL, libprov reading only the other four, and return_size to 0, so a
 * setter's assignment to it -- made on success and on every error path alike
 * -- shows as a change, not a leftover.  Every combination of the other three
 * is a fixture, so nearly all of these return void, treating a null
 * OSSL_PARAM * as a no-op.  param_build_empty() is the exception and
 * returns a VERDICT that its caller must assert; the reasoning is at its
 * definition.
 */

/*
 * The general builder: all five members, three from the caller.  Use it
 * directly for the data types no convenience covers -- OSSL_PARAM_REAL
 * through OSSL_PARAM_OCTET_PTR, which a wrong-type test needs.  The memset
 * matters: OSSL_PARAM has padding between data_type and data on a typical
 * 64-bit target that neither an initialiser nor member assignments need set,
 * and clearing it makes a fixture's WHOLE representation deterministic, which
 * is what lets param_identical() be a byte comparison.
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
 * A signed-integer parameter over a caller-owned buffer.  OSSL_PARAM_INTEGER
 * is the type whose most significant byte carries a sign, so it reaches
 * num.c's sign detection, padding rules and negative-value paths, and it is
 * the type the null-data and zero-size fixtures must use.
 */
static PARAMUTIL_MAYBE_UNUSED void param_build_integer(OSSL_PARAM *param,
                                                       void *data,
                                                       size_t data_size)
{
    param_build(param, OSSL_PARAM_INTEGER, data, data_size);
}

/*
 * An unsigned-integer parameter over a caller-owned buffer.
 * OSSL_PARAM_UNSIGNED_INTEGER takes paramsign()'s unsigned short-circuit
 * straight to positive: right for magnitude fixtures -- an all-bits-set
 * buffer means SIZE_MAX here and -1 under OSSL_PARAM_INTEGER -- wrong for
 * anything that must reach past that short circuit.
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
 * USE OSSL_PARAM_INTEGER HERE.  paramsign() returns positive IMMEDIATELY for
 * an unsigned data type, so a null-data fixture typed
 * OSSL_PARAM_UNSIGNED_INTEGER exercises the short circuit and can detect
 * nothing beyond it; typed OSSL_PARAM_INTEGER it does reach that code.
 * data_type stays a parameter because pairing a null buffer with a
 * non-integer type pins which guard runs first: for OSSL_PARAM_OCTET_STRING
 * the answer is PROVNUM_E_WRONG_TYPE.
 */
static PARAMUTIL_MAYBE_UNUSED void
param_build_null_data(OSSL_PARAM *param, unsigned int data_type,
                      size_t data_size)
{
    param_build(param, data_type, NULL, data_size);
}

/*
 * A parameter with a real buffer but a declared size of ZERO.  Both readings
 * of that shape are real fixtures: as a getter's SOURCE it is an empty number,
 * answered with success and a zeroed destination by a shortcut taken before
 * the destination is checked, so it succeeds even with a null destination
 * pointer; as a setter's DESTINATION it is a zero-capacity buffer, answered
 * with PROVNUM_E_TOOBIG and return_size left at zero.
 *
 * Returns 1 when the fixture was built and 0 when it was refused, and the
 * result MUST be asserted, because a refusal leaves the OSSL_PARAM untouched
 * and nothing else can reveal it.  A NULL buffer is what it refuses: accepting
 * one would yield { NULL, type, NULL, 0, 0 }, a null-data fixture wearing this
 * function's name, which still passes -- that shape has a documented answer of
 * its own -- while no longer exercising the zero-capacity path, so the clamp
 * that path depends on could be reverted unnoticed.
 *
 * param_build_null_data() gets no mirror-image check on purpose: a declared
 * size of zero is legitimate there, because provnum_copy() consults its
 * empty-source shortcut BEFORE its null-data guard, so that shape has to stay
 * constructible in order to pin which of the two wins -- success, not
 * PROVNUM_E_NULL.
 */
static PARAMUTIL_MAYBE_UNUSED int param_build_empty(OSSL_PARAM *param,
                                                    unsigned int data_type,
                                                    void *data)
{
    if (param == NULL || data == NULL)
        return 0;

    param_build(param, data_type, data, 0);
    return 1;
}

/*
 * provnum_get_size_t() and provnum_get_int() take a const OSSL_PARAM *, so
 * the type system already forbids them writing to it.  The two below check
 * the claim beneath it, where a cast could have discarded the qualifier: the
 * parameter's REPRESENTATION is the same afterwards, byte for byte.
 */

/*
 * Copy a parameter's representation aside for later comparison.  A BYTE
 * copy, not `*snapshot = *param`: OSSL_PARAM has padding on a typical
 * 64-bit target, a struct assignment need not copy padding bytes, and a
 * snapshot differing from its original in bytes nobody wrote would turn a
 * sound invariant into an intermittent failure.  memmove() for that copy,
 * not memcpy(): both arguments are the caller's to choose, so
 * param_snapshot(&p, &p) and a pair of overlapping parameters are
 * reachable, and memcpy() is undefined on either.  No identity shortcut
 * guards it -- a branch for a case memmove() already handles correctly
 * would be one more thing to keep right for no gain.
 */
static PARAMUTIL_MAYBE_UNUSED void param_snapshot(OSSL_PARAM *snapshot,
                                                  const OSSL_PARAM *param)
{
    if (snapshot == NULL || param == NULL)
        return;

    memmove(snapshot, param, sizeof *snapshot);
}

/*
 * Whether two parameters have identical representations.  Two null pointers
 * count as identical.
 *
 * THE ONE SOUND USE IS AN UNTOUCHED OBJECT AGAINST A param_snapshot() OF
 * ITSELF: the snapshot's padding was copied from the original's, so if neither
 * object is written afterwards any difference this reports was a real write.
 * That is exactly the getter invariant -- provnum_get_ takes a
 * const OSSL_PARAM * and must leave it byte-identical -- and it is what this
 * helper exists for.  A comparison between two param_build() results is sound
 * for the same kind of reason, since param_build() clears the padding of both.
 *
 * TWO USES ARE NOT SOUND, and neither is a hypothetical:
 *
 *   (a) A param_build() result against a hand-written brace initialiser.  The
 *       two may agree in all five members and still differ in padding.
 *
 *   (b) EITHER OBJECT WRITTEN AFTER IT WAS BUILT OR SNAPSHOTTED.  C99
 *       6.2.6.1p6 says that storing a value into a member of an object leaves
 *       the bytes corresponding to any padding taking unspecified values, so a
 *       byte comparison involving such an object may report a difference that
 *       no member reflects.  This rules out the tempting shape for a SETTER
 *       postcondition -- snapshot the parameter, overwrite the snapshot's
 *       return_size with the observed one, then compare representations -- in
 *       which BOTH objects have been written: `param` by the library and the
 *       expectation by the test.  Compare the five members individually
 *       instead, as tests/test_num_set.c does; the members are the whole of
 *       the observable contract, and padding is no part of it.
 *
 * Destination BUFFERS are unaffected by all of this and are still compared
 * byte for byte: they are unsigned char arrays with no padding to be
 * unspecified.
 */
static PARAMUTIL_MAYBE_UNUSED int param_identical(const OSSL_PARAM *param,
                                                  const OSSL_PARAM *snapshot)
{
    if (param == NULL || snapshot == NULL)
        return param == snapshot;

    return memcmp(param, snapshot, sizeof *param) == 0;
}

#ifdef LIBPROV_TEST_GUARD_PAGES
/*
 * ===========================================================================
 * THE PROTECTED-BOUNDARY ORACLE
 * ===========================================================================
 * A deterministic observable for the conversions' MEMORY SAFETY, available
 * under the mandated flagless command rather than only under an opt-in
 * sanitizer.
 *
 * WHY IT IS NEEDED.  Several plausible single-token defects in num.c change no
 * return code and no destination value for any input; their whole effect is an
 * access one byte outside a buffer.  Three are known concretely, each the
 * reverse of a repair the library carries:
 *
 *   - dropping "|| param->data_size == 0" from paramsign()'s guard makes it
 *     compute data_size - 1, wrap, and read the byte BEFORE the source;
 *   - relaxing the padding-strip loop's bound from > to >= lets one extra
 *     iteration evaluate rule (b) one byte before the source;
 *   - restoring the padding offset to dest.size - src.size writes past the end
 *     of a destination narrower than twice the source.
 *
 * An exactly-sized automatic buffer makes those accesses land outside a
 * distinct object, which is enough for AddressSanitizer and nothing else: in an
 * ordinary build the read returns whatever byte happens to be adjacent and the
 * answer is usually still correct.  MEASURED: with the first defect
 * reintroduced, the whole suite stayed green.  A guard page turns the same
 * access into a signal, on every run, with no extra build flag.
 *
 * HOW IT WORKS.  Three pages are mapped and the OUTER TWO are made PROT_NONE,
 * so the middle page is writable and both of its edges are cliffs: an access
 * one byte below `low` or at or above `high` faults.  A fixture placed flush
 * against an edge therefore has a hardware bounds check on that side.  Because
 * a fault would otherwise kill the test program, each fixture runs in a FORKED
 * CHILD: the child records what it observed into a shared page and _exit(0)s,
 * and the PARENT does the asserting -- both that the child completed normally
 * and that the recorded values are exactly the documented ones.  A fault is
 * therefore reported as an ordinary self-diagnosing assertion failure naming
 * the case, not as a mysteriously dead test binary.
 *
 * IT CANNOT MANUFACTURE A FAILURE.  The repaired library reads and writes only
 * inside the objects it was given, at any capacity, so there is nothing at
 * either edge for it to touch and every guarded case answers exactly as its
 * unguarded twin does.  param_guard_body_self_test() is the proof that the
 * protection is actually armed: it deliberately reads one byte below `low`, and
 * a run in which THAT completes normally means the mechanism is broken and is
 * asserted as a failure.
 *
 * WHY IT LIVES IN THIS HEADER.  The suite's headers are fixed at three, so a
 * fourth may not be added; and this oracle is for the numeric conversions,
 * whose fixtures this header already owns.  It is nevertheless compiled ONLY
 * into the two targets that define LIBPROV_TEST_GUARD_PAGES -- the numeric
 * ones -- so no other test's process or memory behaviour is disturbed by it.
 * Each target is still its own process with no shared state, so `ctest -j N`
 * remains safe.  The allocator interposer and the abort harness stay file-local
 * to tests/test_err_alloc.c and tests/test_err_death.c respectively, for the
 * same reason: confine a mechanism with global effects to the executables that
 * need it.
 *
 * THE INCLUDING FILE MUST SELECT THE FEATURE-TEST LEVEL ITSELF, before its
 * first #include, because a feature-test macro decides which declarations the C
 * library's headers make visible and comes too late once any of them has been
 * processed.  _DEFAULT_SOURCE rather than a _POSIX_C_SOURCE level, because
 * MAP_ANONYMOUS is not a POSIX flag at all -- it is a Linux and BSD extension,
 * so asking only for POSIX would not necessarily reveal it.  MEASURED on this
 * host: glibc declares mmap(), mprotect(), munmap(), fork(), waitpid() and
 * sysconf() and defines MAP_ANONYMOUS under a bare -std=c99 with no macro at
 * all, so the requirement buys portability rather than fixing anything here.
 * The check below turns a C library that does gate them into one diagnosable
 * compile error naming the cause, rather than an obscure cascade.
 */

# include <errno.h>
# include <stdio.h>
# include <unistd.h>
# include <sys/mman.h>
# include <sys/wait.h>

# if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
/* The older BSD spelling of the same flag. */
#  define MAP_ANONYMOUS MAP_ANON
# endif

# if !defined(MAP_ANONYMOUS)
#  error "LIBPROV_TEST_GUARD_PAGES needs MAP_ANONYMOUS: define a feature-test macro (_DEFAULT_SOURCE, or _BSD_SOURCE on an older glibc) before this file's first #include"
# endif

/*
 * How many destination bytes a guarded case may hand back for byte-level
 * comparison.  Larger than any destination in the suite, and fixed so the
 * shared record has a size the mapping can be made from.
 */
# define PARAM_GUARD_BYTES 64

/*
 * A writable region with a PROT_NONE page on either side.  `low` is its first
 * byte and `high` is ONE PAST its last, so `low[-1]` and `high[0]` are both
 * protected and `high - width` is the flush high-edge placement for a
 * width-byte object.
 */
struct param_guard {
    unsigned char *map;         /* the whole three-page mapping */
    size_t maplen;
    unsigned char *low;
    unsigned char *high;
};

/*
 * Everything one guarded call revealed, written by the child into shared
 * memory and read by the parent.  Plain scalars and a byte array, so it needs
 * no more of the shared mapping than sizeof itself.
 */
struct param_guard_record {
    int rc;
    size_t uvalue;
    int ivalue;
    size_t return_size;
    int param_unchanged;
    size_t nbytes;
    unsigned char bytes[PARAM_GUARD_BYTES];
};

/*
 * How a guarded child ended.  `completed` is the one predicate the parent
 * asserts for a case that must not fault: it is true only for a normal exit
 * with status 0.  It is deliberately not "was not killed by a signal", because
 * AddressSanitizer converts the fault into a report and a NON-ZERO EXIT rather
 * than a signal, and the predicate has to mean the same thing in both builds.
 * `signo` and `exitcode` are carried for the failure message, and `error`
 * distinguishes a broken harness -- fork() or waitpid() itself failing -- from
 * a verdict about the library.
 */
struct param_guard_verdict {
    int completed;
    int exitcode;
    int signo;
    int error;
};

/*
 * A guarded fixture: it may read and write only within [low, high), records
 * what it observed, and must not assert or print -- the parent owns both.
 */
typedef void param_guard_body(struct param_guard_record *record,
                              const struct param_guard *guard);

static PARAMUTIL_MAYBE_UNUSED size_t param_guard_pagesize(void)
{
    long value = sysconf(_SC_PAGESIZE);

    return value <= 0L ? (size_t)4096 : (size_t)value;
}

/*
 * Whether a flush HIGH-EDGE placement can also be correctly aligned for an
 * object needing `align` bytes of alignment.  `high` is page aligned, so
 * high - width is width-aligned exactly when the alignment divides the page
 * size -- true for every power-of-two alignment on every page size a hosted
 * implementation with mmap() uses.  Consulted BEFORE a fixture is built, in the
 * same spirit as this suite's other expressibility gates, so that an
 * inexpressible placement is reported rather than silently mis-aligned.
 */
static PARAMUTIL_MAYBE_UNUSED int param_guard_align_ok(size_t align)
{
    return align != 0 && param_guard_pagesize() % align == 0;
}

/*
 * Map the three pages and protect the outer two.  The writable page is zeroed,
 * so a fixture that seeds only part of it still starts from a known state.
 * Returns 1 on success, 0 having mapped nothing on failure; the caller must
 * assert the result, since every guarded case depends on it.
 */
static PARAMUTIL_MAYBE_UNUSED int param_guard_open(struct param_guard *guard)
{
    size_t page;
    unsigned char *base;

    if (guard == NULL)
        return 0;

    guard->map = NULL;
    guard->maplen = 0;
    guard->low = NULL;
    guard->high = NULL;

    page = param_guard_pagesize();
    base = (unsigned char *)mmap(NULL, page * 3, PROT_READ | PROT_WRITE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == (unsigned char *)MAP_FAILED)
        return 0;

    /*
     * Both cliffs, established before the region is advertised: if either
     * mprotect() fails the whole mapping is released and the caller is told
     * nothing was set up, rather than being handed a half-protected region
     * whose guarantees would be silently weaker than they look.
     */
    if (mprotect(base, page, PROT_NONE) != 0
        || mprotect(base + page * 2, page, PROT_NONE) != 0) {
        (void)munmap(base, page * 3);
        return 0;
    }

    memset(base + page, 0, page);

    guard->map = base;
    guard->maplen = page * 3;
    guard->low = base + page;
    guard->high = base + page * 2;
    return 1;
}

static PARAMUTIL_MAYBE_UNUSED void param_guard_close(struct param_guard *guard)
{
    if (guard == NULL || guard->map == NULL)
        return;

    (void)munmap(guard->map, guard->maplen);
    guard->map = NULL;
    guard->maplen = 0;
    guard->low = NULL;
    guard->high = NULL;
}

/*
 * The flush placements.  Each returns NULL when the request does not fit the
 * writable page, so a caller that asserts non-null cannot proceed with a
 * fixture that is not against the edge it believes it is against.
 */
static PARAMUTIL_MAYBE_UNUSED unsigned char *
param_guard_at_low(const struct param_guard *guard, size_t width)
{
    if (guard == NULL || guard->low == NULL)
        return NULL;
    if (width > (size_t)(guard->high - guard->low))
        return NULL;

    return guard->low;
}

static PARAMUTIL_MAYBE_UNUSED unsigned char *
param_guard_at_high(const struct param_guard *guard, size_t width)
{
    if (guard == NULL || guard->high == NULL)
        return NULL;
    if (width > (size_t)(guard->high - guard->low))
        return NULL;

    return guard->high - width;
}

/*
 * WHICH EDGE A SOURCE MUST SIT AGAINST, and why it is not simply "the low one".
 * The over-run this places a cliff in front of is num.c's srcmsb arithmetic
 * stepping ONE PLACE BEYOND the most significant byte, and which direction that
 * is depends on byte order:
 *
 *   LITTLE: srcmsb is size - 1 and srcmsb2lsb is -1 (num.c:79-80), so a step
 *           beyond the most significant end lands at index -1 -- BELOW the
 *           object -- and a size of zero makes srcmsb wrap to SIZE_MAX, which
 *           is the same byte again.  The object goes flush against `low`.
 *   BIG:    srcmsb is 0 and srcmsb2lsb is 1, so the step lands at index 1 and,
 *           for a one-byte source, one past the end; a size of zero reads index
 *           0, also one past the end.  The object goes flush against `high`.
 *
 * A width of zero is meaningful and correct here: an empty source still has an
 * address, and `low` (or `high`) is exactly the address whose over-run byte is
 * protected.  Hard-coding one edge would make every such case vacuous on the
 * other kind of host, which is the byte-order neutrality the rest of this
 * header exists to keep.
 */
static PARAMUTIL_MAYBE_UNUSED unsigned char *
param_guard_at_msb_edge(const struct param_guard *guard, size_t width)
{
    return param_host_endian() == PARAM_ENDIAN_LITTLE
           ? param_guard_at_low(guard, width)
           : param_guard_at_high(guard, width);
}

/*
 * The return code a guarded body reports when it could not build its fixture.
 * Distinct from 1 and from all four PROVNUM_E_ codes, so a case whose fixture
 * was refused fails its exact-return-code assertion with a value that names the
 * cause instead of degrading into a different, passing, case.
 */
# define PARAM_GUARD_RC_UNBUILT (-99)

/*
 * The shared record.  MAP_SHARED is what makes the child's writes visible to
 * the parent after it exits; an ordinary object would be copied on write and
 * the parent would read its own untouched copy.
 */
static PARAMUTIL_MAYBE_UNUSED struct param_guard_record *param_guard_record_open(void)
{
    void *page = mmap(NULL, sizeof(struct param_guard_record),
                      PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

    if (page == MAP_FAILED)
        return NULL;

    memset(page, 0, sizeof(struct param_guard_record));
    return (struct param_guard_record *)page;
}

static PARAMUTIL_MAYBE_UNUSED void
param_guard_record_close(struct param_guard_record *record)
{
    if (record != NULL)
        (void)munmap(record, sizeof *record);
}

/*
 * Run one fixture in a child and report how it ended.
 *
 * The record is cleared here rather than by the body, so a field the body never
 * writes reads as zero rather than as the previous case's value.  Streams are
 * flushed BEFORE the fork, so nothing already buffered by the parent is
 * duplicated by the child, and the child leaves through _exit() rather than
 * exit(), so it runs no atexit handler and flushes no stream of its own.
 */
static PARAMUTIL_MAYBE_UNUSED struct param_guard_verdict
param_guard_run(param_guard_body *body, struct param_guard_record *record,
                const struct param_guard *guard)
{
    struct param_guard_verdict verdict;
    pid_t child;
    int status = 0;

    verdict.completed = 0;
    verdict.exitcode = -1;
    verdict.signo = 0;
    verdict.error = 0;

    if (body == NULL || record == NULL || guard == NULL) {
        verdict.error = 1;
        return verdict;
    }

    memset(record, 0, sizeof *record);
    fflush(NULL);

    child = fork();
    if (child < 0) {
        verdict.error = 1;
        return verdict;
    }
    if (child == 0) {
        body(record, guard);
        _exit(0);
    }

    while (waitpid(child, &status, 0) != child) {
        /*
         * EINTR is the only way this loop can be reached, no other child
         * existing to be reported; anything else is a broken harness.
         */
        if (errno != EINTR) {
            verdict.error = 1;
            return verdict;
        }
    }

    if (WIFEXITED(status)) {
        verdict.exitcode = WEXITSTATUS(status);
        verdict.completed = verdict.exitcode == 0;
    } else if (WIFSIGNALED(status)) {
        verdict.signo = WTERMSIG(status);
    } else {
        verdict.error = 1;
    }

    return verdict;
}

/*
 * THE HARNESS SELF-TEST, and the reason every other guarded assertion means
 * anything.  It reads the byte immediately below the writable page, which the
 * protection above must make fatal.  The parent asserts that this body did NOT
 * complete: a run where it did is a run where the guard pages were not armed,
 * and every "no fault occurred" verdict in the file would be vacuous.
 *
 * `volatile` so the read cannot be discarded as dead, and the value is stored
 * into the record so it is also used.
 *
 * THIS BODY SILENCES ITS OWN STDERR, and it is the only one that does.  Its
 * fault is the expected outcome, and under the opt-in -fsanitize=address
 * configuration an expected fault prints a two-kilobyte report that would land
 * in the CTest log of a passing run -- the same reasoning as
 * tests/test_err_death.c's redirect.  Doing it inside the body confines it to
 * this child, so every other body keeps its diagnostics: there, a report is
 * evidence of a real defect and losing it would be losing the diagnosis.  The
 * freopen() result is consumed because GCC declares it warn_unused_result, and
 * a failed redirect is not worth acting on -- the fault below is the point of
 * the function either way.
 */
static PARAMUTIL_MAYBE_UNUSED void
param_guard_body_self_test(struct param_guard_record *record,
                           const struct param_guard *guard)
{
    const volatile unsigned char *below = guard->low - 1;

    (void)freopen("/dev/null", "w", stderr);

    record->ivalue = (int)*below;
    record->rc = 1;
}
#endif                          /* LIBPROV_TEST_GUARD_PAGES */

#endif                          /* LIBPROV_TESTS_PARAM_UTIL_H */
