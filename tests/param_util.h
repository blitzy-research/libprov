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
 * One fixture withholds its payload instead of supplying one:
 * param_build_poisoned() hands over an address that cannot be read, so a
 * payload the library was never entitled to touch becomes a trap rather than
 * a silence.  It is for the empty-source shortcut only -- see the note above
 * PARAM_POISON_DATA for why a wrong-type fixture must NOT withhold a payload
 * it has declared.
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
 * OSSL_PARAM_UNSIGNED_INTEGER is the ONE data type paramsign() answers at its
 * gate without reading the payload (num.c:28-29 -- the test is written the
 * positive way round, `data_type == OSSL_PARAM_UNSIGNED_INTEGER`, so every
 * other type, integer or not, falls through to the sign-byte read at
 * num.c:30).  That makes this the right builder for magnitude fixtures -- an
 * all-bits-set buffer means SIZE_MAX here and -1 under OSSL_PARAM_INTEGER --
 * and the wrong one for any fixture whose subject is what happens AT or AFTER
 * that read.
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
 * USE OSSL_PARAM_INTEGER HERE.  OSSL_PARAM_UNSIGNED_INTEGER is the one type
 * paramsign() answers at its gate without reading the payload (num.c:28-29),
 * so a null-data fixture typed that way never reaches the dereference at
 * num.c:30 and CANNOT detect a missing guard, however right its expected
 * return code looks -- that is the M10 lesson the AAP records, and it is why
 * this parameter exists rather than being hardcoded to the unsigned type.
 * OSSL_PARAM_INTEGER both reaches that read and is owed PROVNUM_E_NULL, so it
 * is the one type that makes the guard's absence observable AS the null-source
 * contract.
 * data_type stays a parameter because pairing a null buffer with a
 * non-integer type pins which guard runs first: a non-integer type reaches the
 * read too, but its documented answer is PROVNUM_E_WRONG_TYPE, so for
 * OSSL_PARAM_OCTET_STRING that is what must come back -- the third of the
 * three failing cases the AAP names for this repair.
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
 * A payload address that is NOT null and that NOTHING may read.
 *
 * Every other fixture in this header hands the library a buffer it is welcome
 * to read, which makes "the library did not read the payload" unobservable:
 * an implementation that reads a byte it had no business reading returns the
 * same answer as one that never looked.  A poisoned payload turns that
 * silence into a signal.  ONE contract in num.c is of that shape: a declared
 * size of zero must take the empty-source shortcut before the payload is
 * consulted, and it is pinned by handing the function a descriptor whose data
 * pointer cannot survive being dereferenced.
 *
 * WHAT THIS FIXTURE IS NOT FOR.  It must NOT be used for a wrong-type case.
 * paramsign() reads the sign byte of every source that is not
 * OSSL_PARAM_UNSIGNED_INTEGER (num.c:28-30), and for a descriptor that
 * declares a non-zero size over a non-null buffer that read is inside the
 * bounds the CALLER promised, so it is num.c's to make.  The guard at
 * num.c:22-23 covers exactly two shapes -- a null payload and a declared size
 * of zero -- which are the shapes where the read would fall outside an object.
 * A readable wrong-type payload is a legitimate paramsign() input, so a
 * poisoned wrong-type fixture would fail against correct code, which is the
 * one thing an oracle here must never do.  Wrong-type rejection is asserted as
 * a return code, over readable payloads, in test_num_get.c.
 *
 * ONE QUALIFICATION, AND IT DOES NOT CHANGE THE RULE.  "Inside the bounds the
 * caller promised" holds without argument for OSSL_PARAM_REAL,
 * OSSL_PARAM_UTF8_STRING and OSSL_PARAM_OCTET_STRING, where data_size is the
 * size of the object AT data.  It does not hold for OSSL_PARAM_UTF8_PTR or
 * OSSL_PARAM_OCTET_PTR: <openssl/core.h> says that for those two "only
 * pointers are manipulated for this type", and <openssl/params.h> takes the
 * REFERENCED buffer's size for them -- OSSL_PARAM_construct_utf8_ptr(key,
 * char **buf, size_t bsize) and OSSL_PARAM_get_octet_ptr(p, val, size_t
 * *used_len) -- so data_size describes what the pointer refers to and need not
 * bound the pointer object at data.  For those two types the pre-rejection
 * read can therefore fall outside the object even for a well-formed
 * descriptor.  Closing that would take a data_type gate in paramsign(), a
 * FOURTH repair to num.c, which AAP 0.8.1 and 0.8.2 exclude; the reasoning,
 * the reproduction and the citations are recorded once, at
 * test_get_wrong_types() in test_num_get.c.  The rule above is unaffected: a
 * poisoned wrong-type fixture would still fail against the code the AAP
 * freezes, so it still must not exist.
 *
 * Why address 1 cannot be read: on Linux, and on any host that reserves its
 * lowest addresses against mapping, 1 lies below the floor at which an object
 * can be placed (Linux exposes that floor as vm.mmap_min_addr, 65536 by
 * default), so no object occupies it and no mapping covers it.  A read through
 * it traps.  The wrapped form traps too, which is what makes the zero-size
 * case work: an implementation that computed data_size - 1 on a declared size
 * of zero would index SIZE_MAX, and (unsigned char *)1 + SIZE_MAX is address 0
 * -- also unmapped, also a trap.  Both mistakes land in the same unmappable
 * region rather than on some innocent neighbouring object whose bytes would
 * have been read and silently believed.  POSIX itself promises none of this,
 * which is why the limit below is stated rather than assumed away.
 *
 * Why THIS FILE contains no undefined behaviour: converting an integer to a
 * pointer is implementation-defined, not undefined (C99 6.3.2.3p5), and the
 * suite only ever stores the result in a descriptor and compares it.  It is
 * never dereferenced here, and correct library code never dereferences it
 * either -- the contract above answers before the payload is reached.  The
 * only way this pointer is followed is a library that violates it, which is
 * precisely the defect being detected.  param_snapshot() and
 * param_identical() stay usable, reading the DESCRIPTOR and not the payload.
 *
 * The honest limit: this is a trap, not a proof.  On a host that maps its
 * lowest page the read would succeed and a broken library would go
 * unnoticed -- the oracle would weaken.  It can never invert: correct code
 * does not read the payload, so this fixture cannot fail a correct
 * implementation, and there is no configuration in which a passing verdict
 * here is wrong.  That asymmetry is why it is safe in the mandatory suite,
 * needing no extra target, no fault injection and no sanitizer.
 */
#define PARAM_POISON_DATA ((void *)1)

/*
 * A parameter whose declared size is the caller's but whose payload is
 * unreadable.  The shape it exists for is OSSL_PARAM_INTEGER with a size of
 * zero, which pins the empty-source shortcut ahead of any payload read;
 * data_type stays a parameter rather than being hardcoded only so the caller
 * names the type it means at the call site.  Do NOT pass a non-integer type
 * with a non-zero size: num.c is entitled to read that payload, so such a
 * fixture would fault on correct code -- the note above PARAM_POISON_DATA
 * gives the full reasoning.  Prefer this over param_build_null_data() wherever
 * the question is "was the payload read?" rather than "was a null payload
 * rejected?": a null pointer is also the value num.c's own guard tests, so a
 * null-data fixture cannot separate a guard that returns early from one that
 * merely happens not to fault.
 */
static PARAMUTIL_MAYBE_UNUSED void
param_build_poisoned(OSSL_PARAM *param, unsigned int data_type,
                     size_t data_size)
{
    param_build(param, data_type, PARAM_POISON_DATA, data_size);
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

#endif                          /* LIBPROV_TESTS_PARAM_UTIL_H */
