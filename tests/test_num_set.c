/* CC0 license applied, see LICENSE */

/*
 * An executable specification of the contract provnum_set_size_t() and
 * provnum_set_int() offer their callers: the exact return code for every
 * reachable outcome, the exact bytes left in the destination, and the side
 * effect on OSSL_PARAM.return_size that no header documents.
 *
 * WHAT THE SETTERS ARE.  num.c:164-178 is the provnum_set_##T half of the
 * implement_provnum(T, DT) macro, instantiated twice: for size_t with
 * OSSL_PARAM_UNSIGNED_INTEGER at num.c:180, and for int with
 * OSSL_PARAM_INTEGER at num.c:181.  Each builds a destination descriptor from
 * the caller's OSSL_PARAM (num.c:167-170), builds a source descriptor whose
 * data_type is the macro's DT and whose sign is HARDCODED POSITIVE
 * (num.c:171-173), hands both to provnum_copy() (num.c:57-147), assigns the
 * result's size to param->return_size (num.c:176) and returns the result's
 * code.  Every claim in this file follows from those lines.
 *
 * SUCCESS IS EXACTLY 1, and include/prov/num.h never says so: only num.c:59's
 * "struct resultdesc result = { dest.size, 1, };" fixes it.  Every success
 * below is asserted as == 1 literally -- never >= 0, != 0 or > 0, any of which
 * would accept a value the contract forbids.
 *
 * return_size IS WRITTEN ON EVERY PATH, INCLUDING EVERY FAILURE.  num.c:176
 * assigns it unconditionally after provnum_copy() has returned, and
 * result.size was initialised to dest.size at num.c:59 and is overwritten by
 * no error path, so param->return_size == param->data_size holds whether the
 * call succeeded or returned -2 or -4.  check_set_side_effects() asserts it
 * after every call this file makes.  The side effect is undocumented but load
 * bearing: OpenSSL callers read return_size to size their buffers, so dropping
 * the assignment on the error paths would be a silent ABI break.
 *
 * ONLY TWO ERROR CODES ARE REACHABLE THROUGH THE SETTERS: -2
 * (PROVNUM_E_TOOBIG, num.c:104-107) and -4 (PROVNUM_E_NULL, num.c:111-114).
 * The other two are unreachable BY CONSTRUCTION; test_set_unreachable_docs()
 * carries the proofs together with the complementary facts that make them
 * evidence rather than assumption.
 *
 * CALL, STORE, THEN ASSERT.  C leaves the order in which function-call
 * arguments are evaluated unspecified, so reading param.return_size or the
 * destination inside the same expression that makes the call is a bug.
 * run_set_case() is the single place in this file that invokes a setter, and
 * it stores the return code, then reads the side effects, then asserts.
 *
 * NOTHING IS ASSERTED AS A LITERAL BYTE STRING.  nativeendian() (num.c:9-14)
 * steers both provnum_copy()'s padding-strip loop and its copy, so every
 * expectation here is laid out by param_util.h's host-order helpers -- the
 * same code that lays out the fixtures, so the two cannot disagree -- and
 * every boundary value is derived from sizeof and CHAR_BIT rather than
 * transcribed.  BOUNDARIES COME IN PAIRS: the largest value that fits next to
 * the smallest that does not, so an off-by-one in either direction fails.
 *
 * FIXED BYTE WIDTHS ARE GATED, NOT ASSUMED.  A handful of cases below pin a
 * destination to one, two or three bytes, because that is the only way to
 * express "narrower than the source" without knowing the ABI.  Such a case is
 * meaningful only where the native type can express what it constructs, and
 * C99 pins RANGES rather than widths: INT_MAX >= 32767 (5.2.4.2.1) and
 * SIZE_MAX >= 65535 (7.18.3) say nothing about sizeof(int) or sizeof(size_t),
 * since CHAR_BIT need only be at least 8.  Where CHAR_BIT is 32 a single byte
 * holds an entire int, so "the smallest value that does not fit one byte" is
 * not representable in an int at all and a one-byte destination is not
 * NARROWER than one either, leaving the strip loop nothing to refuse.  The
 * predicates below answer both questions from sizeof and CHAR_BIT, and every
 * affected case consults one BEFORE it constructs or casts anything: a
 * precondition asserted after the conversion has happened does not prevent it,
 * and one asserted and then ignored turns an inexpressible fixture into a
 * reported failure -- a false accusation against num.c.  On every host where a
 * fixture is expressible, which is every host an OpenSSL 3 provider runs on,
 * the case runs exactly as written and its pair stays complete.
 *
 * A gate is not on its own enough for a value composed by SHIFTING, so nothing
 * here is: a count of n whole bytes reaches the width of the type being
 * shifted as soon as that type is n bytes wide, which C99 6.5.7p3 leaves
 * undefined, and a compiler that can see the count is out of range diagnoses
 * it where it is WRITTEN whether or not the gate lets the block run.  The
 * multi-byte composition below is multiply-and-add for that reason, and the
 * width helpers in param_util.h bound their own shifts for the same one.
 *
 * EVERY CASE ASSERTS A SPECIFIC VALUE -- the exact return code, the exact
 * destination content, the exact return_size and, on every error path, that
 * the destination still holds the sentinel it was seeded with.  The one case
 * whose byte pattern is deliberately NOT asserted still asserts that the
 * destination CHANGED, and the process exit status comes from testutil.h's
 * assertion counters, so falling off the end of main() cannot manufacture a
 * pass.
 *
 * NO LIBCRYPTO.  No OSSL_PARAM_get_, OSSL_PARAM_set_ or OSSL_PARAM_construct_
 * function is called: those are the libcrypto helpers the provnum_ family
 * exists to replace.  <openssl/params.h> is genuinely absent from this
 * translation unit too, prov/num.h reaching only <openssl/core.h>, which is
 * where OSSL_PARAM comes from -- a plain public struct, built here by hand.
 *
 * THREE BEHAVIORS ARE GENUINELY AMBIGUOUS and are documented rather than
 * asserted, each under a "Class C" heading: the zero padding a negative int
 * receives in an over-wide destination (test_set_int_happy()),
 * provnum_set_int(-1) into a two-byte destination (test_set_errors()), and the
 * destination's declared data_type having no influence on the outcome
 * (test_set_unreachable_docs()).  They are deliberate non-assertions and NOT
 * gaps: pinning whatever the code emits today would enshrine an accident as a
 * contract.  Do not "complete" them by asserting the emitted value.
 *
 * THE TWO MEMORY-SAFETY REPAIRS MADE TO num.c ARE GUARDED HERE, each on both
 * instantiations, and the two guards differ in strength because the two defects
 * differ in where they touch memory.
 *
 * The padding-offset repair at num.c:129 is an out-of-bounds WRITE into the
 * DESTINATION, which the test owns, so it is caught deterministically in an
 * ORDINARY build.  Every destination buffer in this file is WIDER than the
 * capacity its OSSL_PARAM declares and the bytes past that capacity are asserted
 * to still hold the sentinel, so a regression writes into that margin and fails
 * an assertion by name -- the over-wide destination cases in test_set_int_happy()
 * and test_set_size_t_bytes() are those guards.
 *
 * The zero-capacity clamp at num.c:97 is different in kind, not merely in
 * degree: its regression is an out-of-bounds READ inside provnum_set_*'s OWN
 * stack frame -- num.c:172 builds the source descriptor over `&src` -- which no
 * fixture in this file can protect, because a protected page can only be placed
 * at an object the test owns.  The zero-capacity cases in test_set_errors() and
 * test_set_return_size_invariant() therefore pin the full documented answer
 * (-2, return_size 0, buffer untouched) in every build, which is the whole of
 * what a caller depends on, while the READ itself is caught by the opt-in
 * -fsanitize=address,undefined configuration README.md documents.  The comment
 * headed "THE ZERO-CAPACITY CLAMP: WHAT OBSERVES A REGRESSION, AND WHAT CANNOT"
 * sets out why no fixture here can do better.
 *
 * ACCUMULATOR IDIOM.  Each function keeps its own "int ret = 1;" and folds in
 * each verdict with "ret &= test;", the project's own pattern.  That local
 * shadows the file-scope accumulator testutil.h defines for the same purpose,
 * because the file-scope one is refreshed from the counters by every assertion
 * and so cannot accumulate.
 */

#include "testutil.h"
#include "param_util.h"
#include "prov/num.h"

#include <limits.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
 * Every destination buffer in this file is this wide, whatever capacity the
 * OSSL_PARAM over it declares, and the bytes beyond that capacity are
 * asserted to still hold the sentinel.  That is what turns an out-of-bounds
 * write -- the shape of the padding-offset defect num.c:129 was repaired for
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
 * PROVNUM_E_WRONG_TYPE, whose guard (num.c:61-62) tests a source data_type
 * num.c:171-173 hardcodes to an accepted one, and PROVNUM_E_UNSUPPORTED
 * (num.c:145), whose fallthrough needs a source sign the same lines hardcode
 * to POSITIVE.
 */
static int rc_is_reachable(int rc)
{
    return rc != PROVNUM_E_WRONG_TYPE && rc != PROVNUM_E_UNSUPPORTED;
}

/*
 * THE WIDTH PREDICATES the file header describes: a question about the HOST,
 * answered from sizeof and CHAR_BIT, and consulted before a fixture of that
 * width is built rather than after.  Three kinds, plus one composer:
 *
 *   _expressible  can the native type hold what a `width`-byte band builds?
 *   _refuses      that, AND is the destination genuinely narrower, so that
 *                 PROVNUM_E_TOOBIG is the documented answer at all?
 *   _refused_value  the value such a band must be refused, converted only
 *                 behind its own predicate
 *   _holds        the weaker question a byte-ORDER fixture asks, where the
 *                 destination need only be no wider than the source
 *
 * Each is a pure function of the host, so a gate costs one comparison and is
 * constant for the whole run.  None of them knows anything about num.c.
 */

/*
 * Can this host express a `width`-byte fixture for the int instantiation?
 * Every value such a fixture constructs -- the largest that fits in the
 * destination, the smallest that does not, and the destination with every bit
 * set -- is bounded by param_max_unsigned_in(width), so one comparison against
 * INT_MAX settles the whole band at once.  Gating a band rather than a single
 * case is deliberate: it keeps a boundary PAIR together, so a host can never
 * see one half of one.
 */
static int set_int_width_expressible(size_t width)
{
    return param_max_unsigned_in(width) <= (uintmax_t)INT_MAX;
}

/*
 * The same question for size_t.  The comparison is strict because one case in
 * this file constructs param_max_unsigned_in(width) + 1, which must be
 * representable too.
 */
static int set_size_t_width_expressible(size_t width)
{
    return param_max_unsigned_in(width) < (uintmax_t)SIZE_MAX;
}

/*
 * Can a `width`-byte destination REFUSE an int, as PROVNUM_E_TOOBIG?  Only if
 * it is genuinely narrower than the source: num.c:104-107 compares the
 * stripped source width against the destination's declared size, so where the
 * destination is as wide as the native type there is nothing to refuse and the
 * documented answer is 1 rather than -2.  Expressibility is required as well,
 * because the value that must be refused has to exist before it can be passed.
 */
static int set_int_width_refuses(size_t width)
{
    return width < sizeof(int) && set_int_width_expressible(width);
}

/* The same for size_t. */
static int set_size_t_width_refuses(size_t width)
{
    return width < sizeof(size_t) && set_size_t_width_expressible(width);
}

/*
 * The smallest value a `width`-byte destination cannot hold, as an int -- or 0
 * where that value is not representable in an int, in which case the only case
 * that consumes it is gated off and never reads it.  The point of routing the
 * conversion through here is that the cast is performed only once
 * set_int_width_refuses() has proved it well defined; C99 6.3.1.3p3 leaves an
 * out-of-range conversion to a signed type implementation-defined, which is
 * not something a fixture may rely on even in a value it intends to discard.
 */
static int set_int_refused_value(size_t width)
{
    return set_int_width_refuses(width)
           ? (int)(param_max_signed_in(width) + (uintmax_t)1) : 0;
}

/* The size_t counterpart, guarded for the same reason. */
static size_t set_size_t_refused_value(size_t width)
{
    return set_size_t_width_refuses(width)
           ? (size_t)(param_max_signed_in(width) + (uintmax_t)1) : (size_t)0;
}

/*
 * Can a size_t HOLD a `width`-byte value?  The question a byte-order fixture
 * asks, as against the capacity bands above: such a fixture needs the value to
 * exist and the destination to be no wider than the source, but it does not
 * need the destination to be strictly narrower, a destination exactly as wide
 * as a size_t being a perfectly good place to observe byte order.
 *
 * Three clauses, each carrying its own weight.  `width <= sizeof(size_t)` is
 * the byte-count question that C99 leaves open: 7.18.3 fixes only
 * SIZE_MAX >= 65535, a statement about the type's RANGE, which a host with
 * CHAR_BIT == 32 satisfies at sizeof(size_t) == 1.  `width <=
 * sizeof(uintmax_t)` keeps param_max_unsigned_in() on its exact branch rather
 * than its saturating one, so the third clause means what it says, and it is
 * also what makes one byte's worth of values expressible for the composition
 * below.  The comparison against SIZE_MAX is then the direct question, asked
 * with a non-strict "<=" because equality is a case this predicate wants.
 */
static int set_size_t_width_holds(size_t width)
{
    return width <= sizeof(size_t)
           && width <= sizeof(uintmax_t)
           && param_max_unsigned_in(width) <= (uintmax_t)SIZE_MAX;
}

/*
 * The size_t value a most-significant-byte-first pattern denotes, composed by
 * MULTIPLY-AND-ADD rather than by shifting, and not by writing bytes into a
 * size_t object and reading it back.  Both refusals are deliberate.
 *
 * A shift is refused because the count a three-byte pattern needs -- twice
 * CHAR_BIT -- reaches the width of the type being shifted as soon as uintmax_t
 * is two bytes wide, and C99 6.5.7p3 leaves that undefined.  Gating the CASE
 * is not enough on its own: a compiler that can see the count is out of range
 * diagnoses it where it is written, whether or not the block runs, and a
 * warning is a failure for this suite.
 *
 * Reading back an integer object's bytes is refused for the reason
 * param_util.h gives over param_sentinel_size_t(): C99 6.2.6.2 permits an
 * integer type to carry padding bits, so an object's representation is not a
 * portable way to denote a value -- which is exactly why the expectation for
 * such a fixture is laid out by param_put_msb_first() into a BYTE buffer,
 * where no padding bit exists.
 *
 * Multiplication by one byte's worth of values is defined arithmetic at every
 * width.  The caller must have established set_size_t_width_holds(count)
 * first; that is what makes every intermediate product exact rather than a
 * reduction modulo the type's range.
 */
static size_t set_size_t_from_msb_first(const unsigned char *msb_first,
                                        size_t count)
{
    const uintmax_t scale = param_max_unsigned_in(1) + (uintmax_t)1;
    uintmax_t value = 0;
    size_t pos;

    for (pos = 0; pos < count; pos++)
        value = value * scale + (uintmax_t)msb_first[pos];

    return (size_t)value;
}

/*
 * ---------------------------------------------------------------------------
 * THE ZERO-CAPACITY CLAMP: WHAT OBSERVES A REGRESSION, AND WHAT CANNOT
 * ---------------------------------------------------------------------------
 * Read this before adding a case that hopes to catch a regression of the clamp
 * at num.c:97.  The suite DOES catch one, by the contract assertions named
 * below; what it cannot do is guarantee that it always will, and the reason is
 * a property of WHERE THE MEMORY LIVES rather than of how hard a test tries.
 * No fixture closes that last gap -- not the poisoned payload that closes the
 * corresponding gap in paramsign(), for the reason given under WHY NO FIXTURE
 * IN THIS FILE CAN CONTROL THAT BYTE -- and the only thing that does is a build
 * configuration, described at the end.
 *
 * WHAT A REVERT DOES.  Removing "|| dest.size == 0" leaves the strip loop's
 * bound `end` at 0, so the loop at num.c:98-102 keeps going while src.size is
 * merely greater than zero, and its final iteration -- the one that would take
 * src.size from 1 to 0 -- evaluates rule 2 at
 *
 *     src.data[srcmsb + srcmsb2lsb]
 *
 * one position OUTSIDE the source: immediately below it on a little-endian host.
 * Whether the regressed library then answers PROVNUM_E_TOOBIG or success is
 * decided by that one out-of-bounds byte -- if its high bit differs from the pad
 * byte's, rule 2 fails, the loop breaks with src.size still 1, and 1 > 0 gives
 * PROVNUM_E_TOOBIG, the right answer reached by undefined behaviour; if it
 * matches, the loop runs to src.size == 0, the oversize test at num.c:104 no
 * longer holds, and the call returns 1.
 *
 * WHY NO FIXTURE IN THIS FILE CAN CONTROL THAT BYTE.  For a setter, the source
 * is not the test's.  num.c:172 builds the source descriptor over `&src` -- the
 * value parameter of provnum_set_size_t() or provnum_set_int() -- so the byte the
 * regressed loop reads is at ((unsigned char *)&src)[-1], inside the library
 * function's OWN stack frame.  A test controls only the memory it supplies; it
 * does not own the callee's frame and cannot put anything against it.  That is
 * also precisely why param_util.h's poisoned payload does not transfer here.  It
 * works for paramsign() because there the address that must not be read is one
 * the TEST hands over, so the test can make it unreadable; here the address is
 * one the CALLEE derives from its own parameter, and nothing passed in can reach
 * it.  A poisoned DESTINATION does not help either: with a declared capacity of
 * zero the destination is never read or written on any path, so its
 * accessibility is not observable.  Mechanisms that cannot reach it either, so
 * they are not worth attempting: painting the callee's frame from a noinline
 * scratch function (nonportable, and it makes the verdict depend on whether the
 * compiler kept that frame), sigaltstack and makecontext (the ABI's stack
 * alignment stops &src from ever landing on a page boundary), --wrap=memcpy (the
 * read does not go through memcpy), and _FORTIFY_SOURCE or UBSan (neither checks
 * bounds for pointer arithmetic on a stack object).
 *
 * WHAT IS ASSERTED DETERMINISTICALLY, IN EVERY BUILD AND ON EVERY HOST.  The
 * full documented answer for a zero-capacity destination: PROVNUM_E_TOOBIG,
 * return_size left at 0, and every byte of the caller's buffer still holding the
 * sentinel.  Both instantiations, positive and negative sources, in
 * test_set_errors() and again in test_set_return_size_invariant().  Those
 * assertions pin the CONTRACT, which is what a caller depends on.  What they
 * cannot pin is whether a particular build arrived at it by reading a byte it
 * had no business reading.
 *
 * SO A REVERTED CLAMP CHANGES THE ANSWER ONLY IF THAT ONE BYTE SAYS SO.  Where
 * it reads as padding, the loop runs to src.size == 0, the oversize test at
 * num.c:104 no longer holds, and the call returns 1 where -2 is owed -- which
 * the contract assertions below catch in the default build, with no
 * instrumentation.  Where it does not, the regressed library reaches
 * PROVNUM_E_TOOBIG by accident and passes every assertion.
 *
 * Detection here is therefore a fact about generated code rather than anything
 * the language promises, and this file does not upgrade it into one: it is a
 * weaker footing than the poisoned-payload cases in test_num_get.c stand on, and
 * it is why the sanitizer configuration below is not redundant.
 *
 * *** WHAT WOULD TURN THAT INTO A GUARANTEE IS NOT A FIXTURE AT ALL. ***
 *
 * The access is out of bounds of a VARIABLE while remaining, in general, inside
 * the FUNCTION'S FRAME -- the setter's frame also holds `endian`, `destnd`,
 * `srcnd` and the result, and which of them sits immediately below `src` is the
 * compiler's business, not this file's.  That single fact rules out every
 * mechanism a fixture could reach: a protected page can only be placed at an
 * object the test owns, and painting or a guard page below the frame cannot see
 * an access that never leaves it.  What CAN see it is a checker with
 * PER-VARIABLE redzones, which is what AddressSanitizer's stack instrumentation
 * is; and for it to see this access, num.c itself must be the thing
 * instrumented.
 *
 * That is a build configuration rather than a test case, and it is an OPT-IN
 * one.  README.md documents it: configure a separate tree with
 * -DCMAKE_C_FLAGS="-fsanitize=address,undefined -g -fno-omit-frame-pointer",
 * which instruments num.c along with everything else, and run this suite in it.
 * It is deliberately NOT wired into the default build: the suite has to run
 * under `cmake -B build && cmake --build build && ctest --test-dir build` with
 * no -D flag, so no sanitizer, coverage flag or extra target may be added to
 * the default configuration to obtain this check.
 *
 * ONE COROLLARY WORTH KNOWING, asserted by the third zero-capacity case below.
 * The loop compares the out-of-bounds byte's high bit against src.sign's, and
 * num.c:172 initialises the setter's srcnd.sign to POSITIVE -- 0x00 --
 * UNCONDITIONALLY, whatever the value's own sign.  A negative source's bytes are
 * 0xFF, they do not equal that hardcoded pad, so rule 1 fails on the FIRST
 * iteration and the loop never reaches the source's edge at all.  A negative
 * zero-capacity case therefore cannot reach the defect even in a reverted build,
 * which is why the positive cases are the ones that matter here.
 */

/*
 * Every side effect a provnum_set_ call is required and permitted to have,
 * asserted in one place so that no case can forget one.  `before` is a
 * param_snapshot() taken immediately before the call.
 *
 * "return_size is the only member a setter writes" is asserted MEMBER BY
 * MEMBER, deliberately and not for want of a shorter spelling.  A whole-struct
 * comparison would be unsound here, which is the one thing this file cannot
 * afford in an assertion: a setter stores into param->return_size, and C99
 * 6.2.6.1p6 says that storing into a member leaves the bytes of the object
 * that correspond to PADDING taking unspecified values.  Both objects that a
 * byte comparison would have to look at are written after they were built --
 * `param` by the library, and any expectation this function assembled by
 * assigning its return_size -- so on a conforming implementation the padding
 * could differ while all five members agree, and the comparison would report a
 * failure that is not one.  The five comparisons below cover every member the
 * type has, which is the whole of the observable contract; padding is not part
 * of it.  See the note on param_identical() in param_util.h, whose sound use
 * is a getter's untouched parameter against its own snapshot.
 *
 * The destination BUFFER is a different matter and is compared byte for byte:
 * run_set_case() does that against a constructed expected pattern, and bytes
 * past the declared capacity are checked to still hold the sentinel.  Those
 * are plain unsigned char arrays with no padding to be unspecified.
 */
static int check_set_side_effects(const char *what, const OSSL_PARAM *param,
                                  const OSSL_PARAM *before)
{
    int ret = 1;

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
         * Both reachable error paths -- PROVNUM_E_TOOBIG at num.c:104-107 and
         * PROVNUM_E_NULL at num.c:111-114 -- return before provnum_copy()
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
     * destination strips its source down to one byte at num.c:98-102 and is
     * then refused by num.c:104-107, so it can only ever carry an expected
     * result of PROVNUM_E_TOOBIG and has already returned above.
     */
    TEST_ASSERT_INT_EQ(c->what, memcmp(buffer, sentinel, c->capacity) != 0, 1);
    ret &= test;

    if (c->expected != NULL) {
        TEST_ASSERT_MEM_EQ(c->what, buffer, c->expected, c->capacity);
        ret &= test;
    }

    TEST_ASSERT_MEM_EQ(c->what, buffer + c->capacity, sentinel + c->capacity,
                       sizeof buffer - c->capacity);
    ret &= test;

    return ret;
}

static int test_set_int_happy(void);
static int test_set_int_extremes(void);
static int test_set_size_t_capacity(void);
static int test_set_size_t_bytes(void);
static int test_set_errors(void);
static int test_set_return_size_invariant(void);
static int test_set_unreachable_docs(void);

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
         * PADDING-OFFSET GUARD.  A destination three int widths deep takes the
         * value in its least significant sizeof(int) bytes and zero padding
         * above: num.c:129 starts the padding at src.size on a LITTLE
         * destination, and num.c:131-132 fills it with src.sign, hardcoded to
         * POSITIVE by num.c:171-173 and defined as 0x00 at num.c:7.
         *
         * This shape is chosen because the unrepaired offset, dest.size -
         * src.size, evaluates to 8 here and would write dest[8 .. 15] into a
         * twelve-byte destination.  run_set_case() asserts that the bytes past
         * the declared capacity still hold the sentinel, so the four-byte
         * overrun fails in an ordinary build rather than only under a
         * sanitizer.
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
         * src.sign (rule 1, stated at num.c:88-89 and tested at num.c:99),
         * and the high bit of the next byte down is clear (rule 2, stated at
         * num.c:90-91 and tested at num.c:100-101), so the source is stripped
         * from sizeof(int) bytes to one and the value fits.
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

    /*
     * GATED on an int being more than one byte wide, because otherwise
     * "sizeof(int) - 1" is a ZERO-capacity destination, which num.c:97 clamps
     * and num.c:104-107 then refuses with PROVNUM_E_TOOBIG -- a different case
     * with a different documented answer, already covered in
     * test_set_errors().  The gate is a property of the host, not of the
     * library.
     */
    if (sizeof(int) > 1) {
        /*
         * One byte narrower than the source: the strip loop runs exactly once
         * and then stops on its own bound, num.c:98, rather than on either
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
         * rules assume: num.c:88-89 says the byte the most significant one
         * must equal "just so happens to have the 2's complement padding
         * value", and that byte is the one compared at num.c:99, src.sign.
         * Because the destination is exactly as wide as the source no padding
         * is involved, so this case says nothing about the over-wide
         * destination that Class C #2 below leaves open.
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
         * padding memset at num.c:131-132 writes src.sign, and num.c:171-173
         * hardcodes the source descriptor's sign to POSITIVE, which num.c:7
         * defines as 0x00.  The destination's own declared data_type has no
         * say, because it is consulted only at num.c:120 where the
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
         * representation num.c:88-89 already assumes when it says that byte,
         * the one compared at num.c:99 as src.sign, has "the 2's complement
         * padding value".
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
     * eight bits wide.  An off-by-one at num.c:98 or num.c:104 breaks one
     * half or the other.
     *
     * The whole band is GATED on set_int_width_refuses(1) -- a one-byte
     * destination is narrower than an int AND the values the band constructs
     * are representable in one -- so that the pair is either present in full
     * or absent in full, and so that no cast below is performed before it has
     * been shown to be well defined.
     */
    if (set_int_width_refuses(1)) {
        /*
         * Strips cleanly: the bytes above the least significant one are
         * 0x00 == src.sign (rule 1, num.c:99), and the high bit of the
         * surviving byte is clear, which is what rule 2 (num.c:100-101)
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

    /* The other half of the pair, under the same band gate. */
    if (set_int_width_refuses(1)) {
        /*
         * One more, and the same loop refuses to strip.  The byte above the
         * least significant one is still 0x00, satisfying rule 1, but the
         * high bit of the byte below it is now SET, so rule 2
         * (num.c:100-101) fails and the loop breaks at a source size of two.
         * Two is greater than the one-byte destination, so num.c:104-107
         * answers PROVNUM_E_TOOBIG and leaves the destination alone.
         *
         * For an int destination declared OSSL_PARAM_INTEGER this is
         * unambiguous: one signed byte cannot denote this value.  The
         * surprising case is the same boundary reached through
         * provnum_set_size_t(), where the source type is unsigned; that lives
         * in test_set_size_t_capacity().
         *
         * The conversion to int runs through set_int_refused_value(), which
         * performs it only once representability has been established.  The
         * older shape of this case cast the value in the initialiser and
         * asserted representability afterwards, which is too late to prevent
         * anything: C requires INT_MAX to be at least 32767, but CHAR_BIT is
         * not limited to 8 or 16, so on a 32-bit-byte host one byte's worth of
         * value bits exceeds INT_MAX and the conversion is
         * implementation-defined (C99 6.3.1.3p3) rather than merely
         * surprising.  The band gate above is what makes the value meaningful
         * here.
         */
        struct set_case c = {
            .what = "set_int(smallest that does not fit one byte) -> 1 byte",
            .use_int = 1,
            .data_type = OSSL_PARAM_INTEGER,
            .capacity = 1,
            .ivalue = set_int_refused_value(1),
            .expected_rc = PROVNUM_E_TOOBIG,
            .expected = NULL
        };

        ret &= run_set_case(&c);
    }

    /* The far end of the same band, under the same band gate. */
    if (set_int_width_refuses(1)) {
        /*
         * Even the largest value a byte could hold if every bit were available
         * is refused, because the strip loop breaks on rule 2 the moment the
         * surviving byte has its high bit set.  This is what makes the
         * boundary above an EFFECTIVE SIGNED capacity rather than an accident
         * of one value -- the whole range from param_max_signed_in(1) + 1
         * upwards is rejected, not just its first member.
         *
         * The band gate has already established that this value is
         * representable in an int -- set_int_width_expressible(1), which
         * set_int_width_refuses(1) requires, is exactly the bound
         * param_max_unsigned_in(1) <= INT_MAX -- so the conversion below is
         * well defined by the time it runs.
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
 * The mechanism, exactly.  num.c:171-173 hardcodes the SOURCE descriptor's
 * sign to POSITIVE for the setter direction, which num.c:7 defines as 0x00.
 * The padding-strip loop at num.c:98-102 may therefore drop a leading byte
 * only while BOTH rules hold: rule 1 (stated at num.c:88-89, tested at
 * num.c:99) needs the byte being dropped to equal 0x00, and rule 2 (stated
 * at num.c:90-91, tested at num.c:100-101) needs the high bit of the next byte
 * down to match the high bit of 0x00, that is, to be clear.  A value with
 * its top byte-bit set therefore cannot be narrowed onto its own last byte,
 * the loop stops one byte early, and num.c:104-107 answers
 * PROVNUM_E_TOOBIG.
 *
 * Each pair below is written adjacently -- largest that fits, then smallest
 * that does not -- and both members are derived from param_max_signed_in() so
 * they track CHAR_BIT rather than asserting this ABI.
 *
 * Each fixed-width band is GATED on set_size_t_width_refuses(), which asks
 * both of the questions such a band depends on: is the destination genuinely
 * narrower than a size_t, and are the band's values representable in one.  A
 * band is therefore present in full or absent in full, and no value is
 * converted before the conversion has been shown to be exact.
 */
static int test_set_size_t_capacity(void)
{
    int ret = 1;

    /* PAIR at one byte. */
    if (set_size_t_width_refuses(1)) {
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

    /* The other half of the pair, under the same band gate. */
    if (set_size_t_width_refuses(1)) {
        /*
         * The headline case: one more than the value above, into the same
         * destination, is REFUSED even though a single unsigned byte plainly
         * represents it.  Nothing about the destination's declared
         * OSSL_PARAM_UNSIGNED_INTEGER type changes that; only the source
         * sign hardcoded at num.c:171-173 governs the strip loop.
         *
         * set_size_t_refused_value() derives the same value the pair's first
         * member is one below, converting it only under the gate this block
         * already stands behind.
         */
        struct set_case c = {
            .what = "set_size_t(top bit of one byte set) -> 1 byte, refused",
            .data_type = OSSL_PARAM_UNSIGNED_INTEGER,
            .capacity = 1,
            .uvalue = set_size_t_refused_value(1),
            .expected_rc = PROVNUM_E_TOOBIG,
            .expected = NULL
        };

        ret &= run_set_case(&c);
    }

    /* The rest of the band, under the same band gate. */
    if (set_size_t_width_refuses(1)) {
        /*
         * The boundary above is a capacity and not a one-value quirk: the
         * largest value a byte can hold with every bit available still does
         * not fit a one-byte destination.
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

    /*
     * Still the same band, and still the same gate -- which here also
     * guarantees that param_max_unsigned_in(1) + 1 is itself a size_t value,
     * because set_size_t_width_expressible() compares with a strict "<".
     */
    if (set_size_t_width_refuses(1)) {
        /*
         * A value that exceeds the destination's width outright, which reaches
         * the same PROVNUM_E_TOOBIG through a different route: here the strip
         * loop breaks on rule 1 (num.c:99) because the surviving upper byte
         * is not 0x00 at all, rather than on rule 2.  Both routes must answer
         * -2, and both must leave return_size at the declared data_size.
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
     * case.
     *
     * The band is GATED on set_size_t_width_refuses(2) rather than on a
     * standard guarantee, because no such guarantee exists.  C99 7.18.3 fixes
     * only SIZE_MAX >= 65535, which is a statement about the type's RANGE; it
     * says nothing about sizeof(size_t), since a single 16-bit byte
     * (CHAR_BIT == 16, which 5.2.4.2.1 permits) satisfies that range at
     * sizeof(size_t) == 1.  The gate asks the two questions this band actually
     * depends on -- 2 < sizeof(size_t), so the destination is genuinely
     * narrower and PROVNUM_E_TOOBIG is the documented answer, and
     * param_max_unsigned_in(2) < SIZE_MAX, so both members convert exactly.
     */
    if (set_size_t_width_refuses(2)) {
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

    /* The other half of the pair, under the same band gate. */
    if (set_size_t_width_refuses(2)) {
        struct set_case c = {
            .what = "set_size_t(top bit of two bytes set) -> 2 bytes, refused",
            .data_type = OSSL_PARAM_UNSIGNED_INTEGER,
            .capacity = 2,
            .uvalue = set_size_t_refused_value(2),
            .expected_rc = PROVNUM_E_TOOBIG,
            .expected = NULL
        };

        ret &= run_set_case(&c);
    }

    {
        /*
         * SIZE_MAX at the type's own width: every bit set, and accepted,
         * because a destination as wide as the source needs no stripping at
         * all -- the loop bound at num.c:98 is false on entry.  This is the
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
 * (num.c:9-14) drives both the destination offset chosen at num.c:135 and the
 * source offset at num.c:136, so every expectation here is laid out by
 * param_util.h from a logical description -- a most-significant-byte-first
 * pattern, or a value plus a padding width -- and never as a literal byte
 * string that would only be right on one byte order.
 */
static int test_set_size_t_bytes(void)
{
    int ret = 1;

    /*
     * The three-byte fixture's pattern, hoisted out of its block so the gate
     * below can be written in terms of the pattern's own width instead of
     * repeating a byte count the block would then be free to disagree with.
     */
    static const unsigned char msb_first[] = { 1, 2, 3 };

    /*
     * GATED, not asserted-then-run.  A three-byte pattern needs a size_t that
     * can hold a three-byte value, and nothing in C99 promises one:
     * set_size_t_width_holds() asks the question directly.  The shape this
     * replaces asserted sizeof(size_t) >= 3 and then ran the case regardless,
     * so on a host where the precondition failed -- CHAR_BIT == 32 meets
     * SIZE_MAX >= 65535 at sizeof(size_t) == 1 -- the run would have gone on
     * to report a mismatch, blaming the library for a property of the fixture.
     * Every platform an OpenSSL 3 provider is built for has a 32- or 64-bit
     * size_t and runs this case; a narrower one now declines it instead.
     */
    if (set_size_t_width_holds(sizeof msb_first)) {
        /*
         * Three DISTINCT bytes, so a byte-order mistake cannot hide behind a
         * symmetric pattern.  The value is composed from the same
         * most-significant-byte-first description the expectation is laid out
         * from -- significance 2 holds 1, significance 1 holds 2, significance
         * 0 holds 3 -- so the two cannot disagree about byte order, and
         * set_size_t_from_msb_first() composes it without a shift whose count
         * would be undefined on a narrow uintmax_t.  param_put_msb_first()
         * maps the same description onto the running host: on a little-endian
         * one the raw sequence 03 02 01, on a big-endian one 01 02 03.  The
         * test asserts the description, not either sequence.
         */
        unsigned char expected[SET_CASE_MAX_BYTES];
        unsigned char composed[SET_CASE_MAX_BYTES];
        const size_t width = sizeof msb_first;
        struct set_case c = {
            .what = "set_size_t(three distinct bytes) -> 3-byte UNSIGNED",
            .data_type = OSSL_PARAM_UNSIGNED_INTEGER,
            .capacity = sizeof msb_first,
            .uvalue = set_size_t_from_msb_first(msb_first, sizeof msb_first),
            .expected_rc = 1,
            .expected = expected
        };

        TEST_ASSERT_INT_EQ(c.what,
                           param_put_msb_first(expected, c.capacity, msb_first,
                                               width), 1);
        ret &= test;

        /*
         * The fixture checks ITSELF before it checks the library, which is
         * what the precondition assertion this gate replaced was reaching for
         * and did not achieve.  The value handed to provnum_set_size_t() and
         * the byte pattern its output is compared against are produced by two
         * independent routes -- multiply-and-add here, a byte move in
         * param_put_msb_first() -- so laying the composed value out in host
         * order and comparing the two proves they denote the same number.  A
         * composition that had silently reduced modulo the type's range would
         * fail HERE, naming the fixture, instead of surfacing as a mismatch
         * that reads like a defect in num.c.
         */
        TEST_ASSERT_INT_EQ(c.what,
                           param_put_host_order(composed, width,
                                                (uintmax_t)c.uvalue), 1);
        ret &= test;
        TEST_ASSERT_MEM_EQ(c.what, composed, expected, width);
        ret &= test;

        ret &= run_set_case(&c);
    }

    {
        /*
         * PADDING-OFFSET GUARD on the OTHER instantiation.  num.c:129 is
         * shared code, but each instantiation reaches it with a different
         * sizeof(T), so the size_t half needs its own over-wide destination:
         * the value lands in the least significant sizeof(size_t) bytes and
         * the rest is zero padding.  The unrepaired offset overran the buffer
         * here too, and run_set_case() asserts the bytes past the declared
         * capacity, so the regression fails without a sanitizer.
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
 * PROVNUM_E_NULL (-4) comes from num.c:111-114, the destination check, which
 * sits AFTER the oversize check at num.c:104-107 -- an ordering that matters
 * and is pinned by the last case in this group.  PROVNUM_E_TOOBIG (-2) comes
 * from num.c:104-107 and is reached here two ways: a destination with no
 * capacity at all, and a destination narrower than the value needs.
 */
static int test_set_errors(void)
{
    int ret = 1;

    {
        /*
         * A parameter with a declared size but no buffer.  provnum_copy()
         * reaches num.c:111-114 and answers PROVNUM_E_NULL; num.c:176 still
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
         * The clamp at num.c:97 exists for exactly this shape: without the
         * "|| dest.size == 0" the loop bound `end` would be 0, the condition
         * at num.c:98 would stay true until the source size reached 0, and
         * srcmsb would step one position before the start of the source
         * buffer.  The documented answer is unchanged by the repair --
         * PROVNUM_E_TOOBIG with return_size 0, because a source of
         * sizeof(size_t) bytes cannot be narrowed below one and one is greater
         * than zero -- so this case asserts the contract and the clamp keeps
         * it from being reached through undefined behaviour.
         *
         * WHAT THIS CASE DOES AND DOES NOT ESTABLISH, stated precisely because a
         * regression guard that only sometimes fires is worse than a stated
         * limit.  It pins the CONTRACT -- the exact code, the exact return_size
         * and an untouched buffer -- on every host and in every build.  It also
         * detects a reverted clamp whenever the byte one position before the
         * source reads as padding, because the loop then runs to src.size == 0
         * and the call returns 1 here instead of -2.  What is not guaranteed is
         * that it always will, because that byte lies inside the library
         * function's own stack frame and no fixture here can control it.  So
         * this is a real regression guard resting on generated code rather than
         * on the language -- weaker footing than the poisoned-payload guards in
         * test_num_get.c, and said plainly rather than rounded up.
         *
         * WHAT WOULD MAKE IT UNCONDITIONAL is the opt-in
         * -fsanitize=address,undefined configuration documented in README.md:
         * AddressSanitizer's per-variable stack redzones see the under-read
         * itself, whatever answer the byte would have produced.  The comment
         * headed "THE ZERO-CAPACITY CLAMP: WHAT OBSERVES A REGRESSION, AND WHAT
         * CANNOT" explains why per-variable instrumentation of num.c is the only
         * thing that can see an access which never leaves the library
         * function's own frame.
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
         * The same zero-capacity destination reached by a NEGATIVE source,
         * which arrives at PROVNUM_E_TOOBIG by a DIFFERENT ROUTE and is worth
         * pinning for exactly that reason.
         *
         * The setter half of implement_provnum() hardcodes srcnd.sign to
         * POSITIVE at num.c:172 whatever the value is, so rule 1 (num.c:99)
         * compares each source byte against 0x00.  A negative int's bytes are
         * 0xFF, they do not match, and the loop therefore breaks on its FIRST
         * iteration with src.size still at its full width -- which is greater
         * than a capacity of zero, so num.c:104-107 refuses it.  No iteration
         * ever approaches the source's edge.
         *
         * That first-iteration break is also why this case does NOT detect a
         * reverted clamp, and no claim is made that it does: the loop never gets
         * near the source's edge, so a num.c without the clamp answers
         * PROVNUM_E_TOOBIG here too.  What the case does establish is that the
         * refusal holds for both padding polarities, which is the corollary the
         * header comment states -- the defect can only ever be reached by an
         * all-0x00 source, so a negative zero-capacity case is outside its reach
         * whatever any fixture does.
         */
        struct set_case c = {
            .what = "set_int(-1) -> zero-capacity INTEGER destination, D2",
            .use_int = 1,
            .data_type = OSSL_PARAM_INTEGER,
            .capacity = 0,
            .ivalue = -1,
            .expected_rc = PROVNUM_E_TOOBIG,
            .expected = NULL
        };

        ret &= run_set_case(&c);
    }

    {
        /*
         * SIZE_MAX into a destination one byte narrower than a size_t.  Not a
         * single byte of the source is 0x00, so the strip loop breaks
         * immediately on rule 1 (num.c:99) and the source keeps its full
         * width; sizeof(size_t) is greater than sizeof(size_t) - 1, so
         * num.c:104-107 answers PROVNUM_E_TOOBIG.  The width is derived, so
         * this is "one byte too narrow for the widest value" on any ABI.
         *
         * No width gate, and none needed: the only host this reads differently
         * on is one with a single-byte size_t, where the capacity becomes 0
         * and the case turns into the zero-capacity destination two cases
         * above -- whose documented answer is the same PROVNUM_E_TOOBIG, by
         * the clamp at num.c:97 and the comparison at num.c:104.  The
         * expectation therefore holds at every width, which is what a gate
         * would have to establish.
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
         *
         * Ungated for the same reason as its size_t mirror: a single-byte int
         * reduces the capacity to 0, which answers PROVNUM_E_TOOBIG as well,
         * so there is no width at which the expectation is wrong.
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

    /*
     * GATED on a one-byte destination being genuinely narrower than a size_t.
     * The case below needs BOTH of its guards satisfied at once, and the
     * oversize one is only satisfied while SIZE_MAX needs more than the one
     * declared byte: where sizeof(size_t) is 1 the comparison at num.c:104 is
     * false, execution reaches num.c:111-114, and the documented answer
     * becomes PROVNUM_E_NULL -- correct behaviour that this fixture would have
     * reported as a precedence failure.  set_size_t_width_refuses(1) asks
     * exactly that question, and asserting -2 unconditionally would have made
     * the suite wrong rather than the library.
     */
    if (set_size_t_width_refuses(1)) {
        /*
         * PRECEDENCE: oversize is decided BEFORE the destination pointer is
         * checked.  num.c:104-107 runs ahead of num.c:111-114, so a parameter
         * that is simultaneously too narrow AND has no buffer must answer
         * PROVNUM_E_TOOBIG, not PROVNUM_E_NULL.  A null destination clamps the
         * loop bound to 1 at num.c:97, so the source is stripped as far as it
         * can go and the comparison at num.c:104 is against the DECLARED
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
     * would be a call that proves only that the code runs, while asserting the
     * outcome would pin one reading of an ambiguous contract.  The behaviour is
     * recorded, not exercised.
     *
     * provnum_set_int(&param, -1) into a TWO-BYTE destination answers
     * PROVNUM_E_TOOBIG.  The mechanism is the same hardcoded sign as
     * everywhere else in this file: num.c:171-173 sets the source sign to
     * POSITIVE == 0x00 (num.c:7), so the 0xFF bytes of -1 fail rule 1 at
     * num.c:99 at the first iteration, the source keeps its full sizeof(int)
     * width, and num.c:104-107 refuses it.
     *
     *   (a) -1 is exactly representable in two bytes as 0xFFFF, and a
     *       conversion helper that knows the value is negative could narrow
     *       it, so this should succeed.
     *   (b) The padding-strip rules are stated in terms of the source's own
     *       sign byte (num.c:82-92), and with that sign fixed at POSITIVE the
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
 * num.c:176 assigns param->return_size unconditionally from result.size, which
 * num.c:59 set to the DESTINATION's declared size and no other line writes, so
 * param->return_size == param->data_size holds identically on success, on
 * PROVNUM_E_TOOBIG and on PROVNUM_E_NULL.  A table that deliberately mixes all
 * three outcomes and both source widths proves the invariant is a property of
 * the function rather than of any one input.
 *
 * check_set_side_effects() is shared with run_set_case(), so the invariant has
 * a single implementation and cannot drift between the two.
 *
 * Two of the rows fix a one-byte capacity and demand PROVNUM_E_TOOBIG of it,
 * which is a claim about the host's widths as much as one about num.c, so the
 * table carries an `applies` column: a width predicate decides those two rows
 * before either is built, exactly as the gates elsewhere in this file do.  On
 * every ABI an OpenSSL 3 provider is built for, every row applies.
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
        /*
         * Whether this host can express the row at all.  It is 1 for every row
         * whose value and whose expected answer are the same at any width --
         * which is most of them, a capacity written as sizeof(int),
         * sizeof(size_t) or 0 having no width to disagree with -- and a WIDTH
         * PREDICATE for the two that fix a capacity of one byte and demand
         * PROVNUM_E_TOOBIG of it.  The predicate is consulted BEFORE the row
         * is built, so a host never converts a value the conversion would not
         * be exact for, nor demands an answer its widths cannot produce.
         */
        int applies;
    };
    /*
     * Not static const: the boundary values are computed from CHAR_BIT by
     * param_util.h at run time rather than transcribed, which C99 permits in
     * an initialiser for an object of automatic storage duration.  The same
     * licence is what lets the `applies` column call a predicate.
     */
    const struct rs_case cases[] = {
        { "rs: set_int success, exact width", 1, OSSL_PARAM_INTEGER,
          sizeof(int), 0, 0, 5, 1, 1 },
        { "rs: set_int success, over-wide destination", 1, OSSL_PARAM_INTEGER,
          sizeof(int) * 3, 0, 0, 5, 1, 1 },
        /*
         * 5 into one byte is a success at every width: where sizeof(int) is
         * greater than 1 the strip loop narrows the source onto its last byte,
         * and where it is 1 there is nothing to narrow.
         */
        { "rs: set_int success, stripped onto one byte", 1, OSSL_PARAM_INTEGER,
          1, 0, 0, 5, 1, 1 },
        /*
         * The one int row that a width can disqualify.  PROVNUM_E_TOOBIG needs
         * a destination genuinely narrower than an int, and the value a byte
         * cannot hold must be an int before it can be passed as one:
         * set_int_width_refuses(1) asks both questions and
         * set_int_refused_value(1) performs the conversion only behind it.
         */
        { "rs: set_int refused, one byte too small", 1, OSSL_PARAM_INTEGER,
          1, 0, 0, set_int_refused_value(1), PROVNUM_E_TOOBIG,
          set_int_width_refuses(1) },
        { "rs: set_int refused, no destination buffer", 1, OSSL_PARAM_INTEGER,
          sizeof(int), 1, 0, 5, PROVNUM_E_NULL, 1 },
        { "rs: set_int refused, zero-capacity destination", 1,
          OSSL_PARAM_INTEGER, 0, 0, 0, 0, PROVNUM_E_TOOBIG, 1 },
        { "rs: set_int success into an UNSIGNED destination", 1,
          OSSL_PARAM_UNSIGNED_INTEGER, sizeof(int), 0, 0, 5, 1, 1 },
        { "rs: set_size_t success, widest value at its own width", 0,
          OSSL_PARAM_UNSIGNED_INTEGER, sizeof(size_t), 0, SIZE_MAX, 0, 1, 1 },
        /*
         * Needs no gate on either count: param_max_signed_in(1) is below
         * 2^CHAR_BIT - 1 and so below SIZE_MAX at every width, and the answer
         * is 1 whether the byte is reached by stripping or is the whole of the
         * source.  Its partner below is the row that needs both.
         */
        { "rs: set_size_t success, within one byte's signed capacity", 0,
          OSSL_PARAM_UNSIGNED_INTEGER, 1, 0, (size_t)param_max_signed_in(1),
          0, 1, 1 },
        { "rs: set_size_t refused, past one byte's signed capacity", 0,
          OSSL_PARAM_UNSIGNED_INTEGER, 1, 0, set_size_t_refused_value(1), 0,
          PROVNUM_E_TOOBIG, set_size_t_width_refuses(1) },
        { "rs: set_size_t refused, no destination buffer", 0,
          OSSL_PARAM_UNSIGNED_INTEGER, sizeof(size_t), 1, 5, 0,
          PROVNUM_E_NULL, 1 },
        { "rs: set_size_t refused, zero-capacity destination", 0,
          OSSL_PARAM_UNSIGNED_INTEGER, 0, 0, 0, 0, PROVNUM_E_TOOBIG, 1 },
        { "rs: set_size_t success, destination wider than a size_t", 0,
          OSSL_PARAM_UNSIGNED_INTEGER, sizeof(size_t) + sizeof(int), 0, 5, 0,
          1, 1 }
    };
    const size_t count = sizeof cases / sizeof cases[0];
    unsigned char buffer[SET_CASE_MAX_BYTES];
    unsigned char sentinel[SET_CASE_MAX_BYTES];
    size_t index;
    size_t exercised = 0;
    int ret = 1;

    for (index = 0; index < count; index++) {
        const struct rs_case *c = &cases[index];
        OSSL_PARAM param;
        OSSL_PARAM before;
        int rc;

        /*
         * The width gate, ahead of everything the row does -- including the
         * fixture's construction, which is the point: a declined row must not
         * convert its value, not merely refrain from asserting the outcome.
         */
        if (!c->applies)
            continue;

        /*
         * Seed the destination, and a reference to compare it against, in the
         * same breath -- exactly as run_set_case() does, so the two cannot
         * drift into disagreeing about what "untouched" looks like.
         */
        param_fill_sentinel(buffer, sizeof buffer);
        param_fill_sentinel(sentinel, sizeof sentinel);

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

        /*
         * The negative destination side effect, owed by every error row here
         * just as much as by the cases run_set_case() drives.  Both reachable
         * setter error paths -- PROVNUM_E_TOOBIG at num.c:104-107 and
         * PROVNUM_E_NULL at num.c:111-114 -- return before provnum_copy()
         * writes a single byte, so the WHOLE backing buffer must still hold
         * the sentinel: not merely the declared capacity, because a
         * padding-offset defect writes past it, and a partial comparison
         * would be exactly the check that misses one.  It holds for the
         * null-data rows too, where this buffer was never handed to the
         * parameter at all, and for the zero-capacity rows, where the
         * parameter's own capacity is nothing to compare.
         *
         * Without this the six error rows in the table above would be the
         * only setter errors in the file that assert the return code and the
         * descriptor but say nothing about the destination -- and a
         * regression that made an error path scribble on it would be reported
         * by no row of this sweep.
         */
        if (c->expected_rc != 1) {
            TEST_ASSERT_MEM_EQ(c->what, buffer, sentinel, sizeof buffer);
            ret &= test;
        }

        exercised++;
    }

    /*
     * A table that silently emptied itself would assert nothing and, without
     * these, would still report success for the group.  The first says every
     * row was VISITED, which a loop bound edit would break; the second says
     * the width gates left rows to run, which is the failure a gate applied
     * too broadly would otherwise produce in silence.  On every ABI an OpenSSL
     * 3 provider is built for both counts are the same number.
     */
    TEST_ASSERT_SIZE_EQ("rs: every tabulated path was visited", index, count);
    ret &= test;
    TEST_ASSERT_INT_EQ("rs: the width gates left rows to exercise",
                       exercised > 0, 1);
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
 * CONSTRUCTION.  They are not missing coverage; the proofs below say why, and
 * the sweep at the end asserts the complementary fact that makes them evidence
 * rather than assumption.
 *
 * PROVNUM_E_WRONG_TYPE (-1) IS UNREACHABLE.  The guard at num.c:61-62 tests
 * src.data_type, and num.c:171-173 hardcodes that member to the macro
 * parameter DT: OSSL_PARAM_UNSIGNED_INTEGER at num.c:180 and
 * OSSL_PARAM_INTEGER at num.c:181, precisely the two types the guard accepts.
 * It reads the SOURCE's type and not the destination's, which is why the sweep
 * below can walk every OSSL_PARAM data type without producing -1.
 *
 * PROVNUM_E_UNSUPPORTED (-3) IS UNREACHABLE.  The fallthrough at num.c:145 is
 * reached only when the simple-case condition at num.c:117-120 is false.  Its
 * last clause is "(dest.data_type == OSSL_PARAM_INTEGER || src.sign ==
 * POSITIVE)" and num.c:171-173 hardcodes src.sign to POSITIVE; the other three
 * clauses are always true as well, because num.c:167-173 give destination and
 * source the same endianness from nativeendian(), a limbsize of 1 and a
 * limbnailbits of 0.  The condition cannot be false, so num.c:145 is dead
 * here.
 *
 * The empty-source shortcut at num.c:67-71 and the null-source guard at
 * num.c:73-76 are unreachable for the same reason: num.c:171-173 sets src.size
 * to sizeof(T), never zero, and src.data to the address of the setter's own
 * parameter, never null.  Both belong to the getter direction, where
 * tests/test_num_get.c reaches them.
 *
 * CLASS C #4 -- DELIBERATE NON-ASSERTION, NOT A GAP.  Do not "complete" this
 * by asserting the emitted value.  The outcome of a setter does not depend on
 * param->data_type at all: writing a negative value into an
 * OSSL_PARAM_UNSIGNED_INTEGER destination behaves exactly as it does into an
 * OSSL_PARAM_INTEGER one, by the same clause as the -3 proof above --
 * dest.data_type is read at num.c:120 and nowhere else in the copy, and that
 * read is already satisfied by src.sign == POSITIVE.
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
