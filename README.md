# libprov - a small library of helpers for OpenSSL 3 providers

Currently available routines:

-   ERR helpers

    OpenSSL's ERR functions do not lend themselves very well to provider's
    own error tables, because they can't pass the provider's handle to the
    error record building routines.  This is due to certain limitations with
    the base C standard requirements for OpenSSL itself (C90).

    These helpers are replacements of OpenSSL's ERR_raise() and
    `ERR_raise_data()` that take better advantage of more modern C
    standards.  C99 required.

    See the comments in `include/prov/err.h` for more information.

-   NUM helper

    Converting `OSSL_PARAM` numbers to native numbers present a bit of a
    challenge, as they are variable length, and may need some adaption
    to fit into native numbers.

    `provnum_get()` and `provnum_set()` claim to be universally applicable
    functions for converting an OSSL_PARAM number to a native integer or
    bignum implementations.

-   `OSSL_PARAM` parsing helper

    Parsing `OSSL_PARAM` keys can be done in many ways, with various
    performance problems.  A simple (even naïve) way was to loop over the
    params and `strcasecmp()` them with known names.  Depending on the
    `strcasecmp()` implementation, that can be rather slow.

    `perl/gen_param_LL.pl` takes a specification in form of a perl ARRAY,
    which contains a C function name (for example, `"parse_params"`) as
    first item, followed by a series of tuples of this form:

    ``` perl
    NAME => "key"
    ```

    Each such `NAME` becomes a couple of C macros:

    -   `S_NAME`, with the `"key"` string as its value.
    -   `V_NAME`, with a unique generated integer as its value.

    The function name that's given at the start of the function becomes a C
    function that is called with a single argument, the key to parse.  As a
    test, the following should always be true:

    ``` C
    parse_params(S_NAME) == V_NAME
    ```

    When looking through an `OSSL_PARAM` array, the easy way is to do
    something like this:

    ``` C
    const OSSL_PARAM *p;

    for (p = params; p->key != NULL; p++) {
        switch (parse_params(p->key)) {
        case V_NAME:
            /* Do whatever's needed */
            break;
        ...
        }
    }
    ```

## Testing

The unit tests for `err.c` and `num.c` live in `tests/`, and are registered
with CTest from `tests/CMakeLists.txt`.  Each one is a standalone C99
program whose exit status is derived from a count of assertions made and
assertions mismatched, so a program that asserted nothing fails rather than
passes.  No test framework, assertion library, mocking library or coverage
library is added; where an OpenSSL type is needed, the tests build it
themselves, from an `OSSL_PARAM` assembled over a test-owned buffer by the
helpers in `tests/param_util.h` to a hand-built `OSSL_DISPATCH` table of
stub callbacks and a test-local `OSSL_CORE_HANDLE`.  Nothing here needs a
running provider, and no libcrypto function is ever called.

### Running the tests

``` bash
cmake -B build && cmake --build build && ctest --test-dir build
```

That builds and runs the whole suite, and it needs no `-D` flag of any
kind: the tests are configured and built by default whenever `libprov` is
the top-level project.

One version note, because two different floors are involved.  Configuring
and building needs no more than the CMake 3.18 that the project's
`cmake_minimum_required()` declares, but `ctest --test-dir` is a CMake 3.20
addition, so the command above -- and every other `ctest --test-dir`
invocation in this document, including the coverage and sanitizer recipes
below -- needs CMake and CTest 3.20 or later.  With an older CTest the same
run is `cd build && ctest`, which is the only difference; nothing about the
suite itself changes.

### Other useful invocations

-   `ctest --test-dir build --output-on-failure` prints the output of every
    test that fails.  This is the recommended default for local
    development, and the first thing to reach for when triaging a failure.
-   `ctest --test-dir build --no-tests=error` treats an empty suite as an
    error instead of a pass, which guards against a run that is green only
    because nothing was registered.
-   `ctest --test-dir build -R test_num_get` runs a single test.
-   `ctest --test-dir build -R "test_num_.*"` runs a group of them; the
    argument is a regular expression matched against the test names.
-   `ctest --test-dir build -E test_err_death` excludes a test.
-   `ctest --test-dir build -j 8` runs the tests in parallel.  This is safe
    by design: each one is a separate process, and no two of them share any
    state.
-   `ctest --test-dir build -R test_err_raise -V` is verbose, and shows the
    per-assertion pass and fail lines that a test prints.
-   `ctest --test-dir build --output-junit results.xml` writes the results
    as JUnit XML, at a path relative to the build directory.  This one is
    optional, and it needs a newer CTest still: `--output-junit` arrived in
    CMake 3.21, one release after `--test-dir` itself.
-   `./build/tests/test_num_get` runs a test binary directly, without
    CTest.  Each test is a standalone executable whose exit status comes
    from its own assertion counters, so every one of them is just as usable
    on its own.
-   `cmake -B build -DCMAKE_C_FLAGS="-DTESTUTIL_COLOUR=0"` configures a
    suite that prints no ANSI escapes at all.  The pass and fail tags are
    colourised by default, following the maintainer's own test programs, and
    the choice is compile-time rather than an `isatty()` check, so where
    stdout goes never changes what a test prints: a terminal, a pipe, a file
    and a CTest log all get the same escapes, or all get none.  Set the
    macro to `0` for a log that is going to be archived or diffed as bytes.
    It is an ordinary compiler define, so it can share `CMAKE_C_FLAGS` with
    the coverage and sanitizer recipes below.  Nothing else changes: every
    test still runs and still passes, and the `--output-junit` XML above
    carries no escape either way.

### The `LIBPROV_TESTS` option

Whether the tests are configured at all is decided by the `LIBPROV_TESTS`
option, whose CMake description is `"Build and possibly run tests"`.  Its
default depends on how `libprov` is being built:

-   `ON` when `libprov` is the top-level project, which is what lets the
    command above work with no flag.
-   `OFF` when another project embeds `libprov` with `add_subdirectory()`.
    Such a project gets no test target unless it asks for one, exactly as
    it did before these tests existed.

The root `CMakeLists.txt` tells those two cases apart by testing
`CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR`, rather than by using
`PROJECT_IS_TOP_LEVEL`, because that variable needs CMake 3.21 while this
project declares a 3.18 floor.

To opt out in a top-level build:

``` bash
cmake -B build -DLIBPROV_TESTS=OFF
```

Two things about that flag are worth knowing, and neither is specific to this
project.  Its value follows CMake's ordinary truth rules, as every `option()`
does, and those rules are a short closed list rather than a general reading of
the word: `OFF`, `NO`, `FALSE`, `N`, `IGNORE`, `NOTFOUND`, an empty value, `0`
and any value ending in `-NOTFOUND` turn the tests off, case insensitively.
Every other value turns them **on** -- including one that was meant to be
something else, and including several that read as false but are not: `0.0`,
`00` and `-1` each enable the suite.  And test registration happens at
configure time, so switching the option in a directory that was already
configured the other way leaves the `CTestTestfile.cmake` from that earlier
configuration behind, and `ctest` goes on listing and running what it
registered there -- all eight, reported passing, because the executables the
earlier configuration built are still on disk and the stale file still names
them.  Configure the new value in a fresh `-B` directory, or delete the old one
first, and the option does exactly what it says.

`BUILD_TESTING`, the option that `include(CTest)` itself brings, has a say
over registration.  `include(CTest)` calls `enable_testing()` only when
`BUILD_TESTING` is `ON`, which it is by default, so the command under
"Running the tests" passes no flag and gets the whole suite.  With
`-DBUILD_TESTING=OFF` the picture is worth stating exactly, because it was
measured rather than assumed: configuration and the build still succeed and
still produce the eight test executables, but nothing is registered, no
`CTestTestfile.cmake` is written, and `ctest` reports that no tests were
found.  If you want no test binaries built either, that is what
`-DLIBPROV_TESTS=OFF` above is for.

Nothing is ever registered and then disabled: there is no `DISABLED`
property and no `SKIP_RETURN_CODE` anywhere in the suite.  Where a host
cannot support a target, that target is not registered at all.

### Embedding `libprov` and asking for its tests anyway

Where testing is enabled decides where `ctest` can find the tests, because
`ctest` reads `CTestTestfile.cmake` from the directory it is pointed at and
CMake writes that file only for a directory in which testing was enabled.  A
top-level `libprov` build therefore includes CTest at the source root, which
is what makes `ctest --test-dir build` see all of it.

A project that embeds `libprov` and sets `-DLIBPROV_TESTS=ON` gets a
complete, working `ctest` tree under the directory `add_subdirectory()` put
`libprov` in, because that is where `libprov` calls `include(CTest)` from.
This command therefore always works, and all eight tests pass through it:

``` bash
ctest --test-dir <parent build dir>/<the directory add_subdirectory put libprov in>
```

Whether the parent's own build root also discovers them is up to the parent,
and both outcomes were measured:

-   **The parent called `include(CTest)`** in its own top-level
    `CMakeLists.txt`, before the `add_subdirectory()` that adds `libprov`.
    A `CTestTestfile.cmake` is then written at the parent's build root as
    well, so `ctest --test-dir <parent build dir>` sees all eight too.
-   **Nothing above `libprov` enabled testing.**  The parent's build root
    gets no `CTestTestfile.cmake`, so `ctest` pointed at it reports that no
    tests were found.  The sub-build command above is unaffected.

`libprov` deliberately does not try to paper over the second case.  It
enables testing for its own directory and below, and nothing more: reaching
above itself is not a subdirectory's business, and the one-line
`include(CTest)` in the parent is both the fix and the parent's choice.
Either way configuration and the build stay warning-free -- there is no
`libprov` warning, no probing of how the parent configured itself, and no
inspection of `BUILD_TESTING`'s cache entry.

Embedded builds that leave `LIBPROV_TESTS` at its default of `OFF` are
unaffected by all of this: no test target is created, no test executable is
built, and no CTest machinery is touched.

### The tests

-   `test_num_get` covers `provnum_get_size_t()` and `provnum_get_int()`:
    the success value, the width and signedness edges, every reachable
    error code, and the order the guards are evaluated in when more than
    one of them applies.
-   `test_num_set` covers `provnum_set_size_t()` and `provnum_set_int()`:
    the return codes, the exact bytes written to the destination, and
    `return_size`, which is set on every path, including the ones that
    fail.
-   `test_err_handle` covers the handle lifecycle and the dispatch table
    scan: termination on the sentinel entry, tolerance of unrecognised
    function ids, independence from the order of the entries, duplicate
    ids, duplication and free.
-   `test_err_raise` covers what the three forwarding functions pass on,
    and the call order and call-site capture of `ERR_raise()` and
    `ERR_raise_data()`.
-   `test_err_guards` covers what an assertion-enabled build can observe:
    the dispatch table scan and the two entry points that tolerate a `NULL`
    argument.  It is compiled with an explicit `-UNDEBUG`, so `err.c`'s
    assertions stay live whatever the build type, and it deliberately calls
    none of the inputs that abort -- an abort inside the test process is a
    dead runner rather than a failing assertion.  Those inputs belong to the
    two targets below.
-   `test_err_guards_ndebug` covers the same source with `err.c` recompiled
    under `NDEBUG`, where those assertions vanish and the graceful `NULL`
    returns become reachable instead.  That is where all six invalid inputs
    -- a `NULL` core handle, a `NULL` dispatch table, an empty table, and one
    table per missing callback -- are asserted to return `NULL`.
-   `test_err_death` owns the other half of that contract and asserts it
    positively: it forks, lets the child run an aborting input, and requires
    the child to have died of `SIGABRT` specifically rather than to have
    merely failed.  It carries a 30 second timeout as a safety net, and it is
    registered only on a POSIX host.
-   `test_err_alloc` covers the two allocator paths that no input can reach,
    by interposing on the allocator with `-Wl,--wrap=malloc`.  That is the
    only allocator entry point `err.c` calls -- `err.c:56` in
    `proverr_new_handle()` and `err.c:71` in `proverr_dup_handle()` -- and it
    is the only one at which a failure can be injected.  A countdown
    `__wrap_malloc` fails the next *N* allocations, which is what makes the
    two "returns `NULL` when `malloc` fails" branches reachable, and then
    delegates to `__real_malloc` so the same run proves the interposer
    recovers.  Its eight cases run from the forced failure of
    `proverr_new_handle()`, through recovery, a forced failure of
    `proverr_dup_handle()` with the source handle proven still usable
    afterwards, a successful duplication proven to be a distinct object with
    an independent lifetime, to a two-deep countdown that shows exactly one
    decrement per intercepted allocation.  `calloc` and `realloc` are not
    wrapped, because `err.c` never calls them.
-   One thing no target in the suite can see is worth naming rather than
    leaving to be discovered.  `proverr_free_handle()` returns nothing, writes
    through nothing and calls no callback, so a body reduced to a no-op
    satisfies every assertion in every target: `test_err_handle` pins what a
    release must *not* do -- invoke a callback, disturb the observation state
    -- but the release itself is unobservable.  The opt-in sanitizer
    configuration below is the channel that closes that gap, and it was
    measured rather than assumed: against an `err.c` whose `free(handle)` had
    been replaced by a no-op, the default build still reports 105 assertions
    and 0 mismatches, while the same target under
    `-fsanitize=address,undefined` exits non-zero with
    `ERROR: LeakSanitizer: detected memory leaks` and names 128 bytes leaked
    in 4 allocations.

### The two platform-conditional targets

Six of the eight targets are registered unconditionally.  The remaining two
need facilities that not every host provides, so each sits behind a gate in
`tests/CMakeLists.txt`.  Where a gate does not hold the target is **not
registered at all**: configuration still succeeds, every other registered
target still runs -- the six unconditional ones, plus the other conditional
target where its own gate holds -- and nothing is ever registered and then
skipped or allowed to fail.

-   `test_err_death` sits behind `if(UNIX)`, and needs `fork()`,
    `waitpid()` and the wait-status macros, and `SIGABRT`.
-   `test_err_alloc` sits behind
    `if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang" AND UNIX AND NOT APPLE)`, and
    needs a **GNU-compatible linker**: one that acts on `-Wl,--wrap=malloc` by
    redirecting the call to `__wrap_malloc` and resolving `__real_malloc`.
    Those two are separate requirements, and the gate is the first of them.
    GCC and Clang drive a GNU-compatible linker by default on a non-Apple
    UNIX host, and Apple's `ld64` has no `--wrap` at all, which is why that
    platform is excluded.  The gate is therefore a **necessary** condition
    rather than a sufficient one: a driver deliberately repointed at a linker
    without `--wrap` will still be offered the target, and the build will then
    fail at the link with `undefined reference to __real_malloc`.  That is the
    intended failure mode, and it is deliberate -- a diagnostic naming the
    exact missing capability is better than a test that silently disappears.

Both gates are declarative, and that is a deliberate choice rather than a
shortcut.  Configure machinery is the one part of a test directory that the
suite cannot test: a probe that answers wrongly does not fail a test, it
silently removes one, and a removed target reports nothing at all.  A
declarative condition is readable beside the target it guards, keeps the
directory at the project's CMake 3.18 floor, and -- crucially -- is backed at
build time by a mechanism that cannot fail quietly: `test_err_alloc` will not
link without its `--wrap` option, and `tests/test_err_guards.c` and
`tests/test_err_death.c` will not compile if `NDEBUG` reaches a target that
must not see it.  Neither gate needs to be clever, because neither is the
last line of defence.

`test_err_death` requires only what `if(UNIX)` genuinely implies: `fork()`,
`waitpid()` and `SIGABRT` are the harness itself, and the one facility that
is merely *desirable* -- `setrlimit(RLIMIT_CORE)`, which stops each expected
abort from leaving a core image -- is picked up through
`__has_include(<sys/resource.h>)` and compiled out where it is unavailable.
That was measured both ways: with the header the target leaves no core file
behind, and with the block compiled out it still passes every assertion and
simply writes the images again.  So a UNIX-like host without
`<sys/resource.h>` builds and passes rather than failing to compile, which is
the failure mode a bare platform gate could otherwise have.

`test_err_alloc`'s single link option is not optional.  An unwrapped `malloc`
never fails on a machine with memory to spare, so every assertion in that
file about a failed allocation would turn vacuous.  Nothing has to *detect*
that, because the source cannot be built without the option: it references
`__real_malloc`, a name only `--wrap` creates.  That was measured rather than
assumed -- removing `-Wl,--wrap=malloc` and rebuilding stops at `undefined
reference to __real_malloc` -- so a host whose driver has been repointed at a
linker without `--wrap` gets a diagnostic naming the missing capability
instead of a target that links and then observes nothing.

`err.c`'s assertions have to stay live in `test_err_guards` and
`test_err_death`, because those two targets exist to observe them and
`-DCMAKE_BUILD_TYPE=Release` adds `-DNDEBUG` project-wide.  Undefining a
macro from the command line is a compiler-driver convention rather than a
C99 language feature -- POSIX spells it `-U name` and the standard says
nothing about it -- so the two targets carry the POSIX spelling, `-UNDEBUG`,
which both GCC and Clang accept.  Ordering is what makes that work: a target's
`COMPILE_OPTIONS` follow the per-configuration flags, so a Release build
compiles those targets with `-O3 -DNDEBUG -UNDEBUG` and the undefine has the
last word.

A driver that rejected `-UNDEBUG`, or a build that lost it, would open a hole,
and that hole is closed in the sources rather than left to the build system.
`tests/test_err_guards.c` requires at **compile** time that `NDEBUG` and
`LIBPROV_TEST_NDEBUG_VARIANT` are either both defined or neither defined, and
`tests/test_err_death.c` requires that `NDEBUG` is not defined at all; each
stops the build with an `#error` naming the cause otherwise.  The combination
that matters is `NDEBUG` reaching the default guards target, because that
target's own assertions would still pass while `err.c` no longer asserted
anything -- a green test that tests nothing, which is the one outcome this
suite exists to prevent.  It is unbuildable rather than merely unlikely.

So a POSIX host with a GNU-compatible linker registers all eight tests, and
all eight pass under the default build, under a Release build, under
`--coverage` and under `-fsanitize=address,undefined`.

### Coverage

Coverage is measured on demand, in a build tree of its own, so that the
command above stays uninstrumented:

``` bash
cmake -B build-cov -DCMAKE_C_FLAGS="--coverage"
cmake --build build-cov
ctest --test-dir build-cov
gcov -b -c build-cov/CMakeFiles/libprov.dir/num.c.gcno
```

Repeat the last step for `err.c`.  `gcov` writes its annotated report into
the directory it is run from, so run it from a scratch directory unless you
want `*.gcov` files in the tree.  For reference, the current sources give
`gcov` 58 executable lines and 58 branches in `num.c`, and 52 executable
lines and 26 branches in `err.c`, though the exact counts depend on the
compiler.  As it stands the suite leaves `gcov` reporting no never-executed
branch in either file and exactly one unexecuted line -- `err.c:31`, the
`return NULL;` that the two `assert()` calls above it dominate whenever
assertions are live, which is one of the branches the test sources name as
unreachable by construction.

Two things about those figures are worth knowing before you read a report.
The paths above name the objects compiled into `libprov`, and which targets
contribute to them was measured by running each executable on its own and
seeing which `.gcda` files appeared: `num.c`'s object is exercised by
`test_num_get` and `test_num_set`, and `err.c`'s by `test_err_handle`,
`test_err_raise` and `test_err_alloc`.  The remaining three compile `err.c`
*additionally*, with their own flags, so their coverage lands elsewhere, under
`build-cov/tests/CMakeFiles/<target>.dir/__/err.c.gcno` -- one such path for
each of `test_err_guards`, `test_err_guards_ndebug` and `test_err_death`.
And on the `libprov` object `gcov` reports the five `__assert_fail` calls as
never executed -- `Calls executed` sits at 54.55% -- because an assertion is
only ever made to fail in `test_err_death`, whose children die on `SIGABRT`
and so flush no coverage data at all.  That contract is asserted by that
target's exit-status check, not by a coverage count, which is the point of
having it.

The third figure `gcov -b` prints, *taken at least once*, is the one worth
reading closely, and it is lower than the other two by design rather than by
omission: about 83% for `num.c` and about 73% for `err.c` on the reference
toolchain.  Those are 10 of `num.c`'s 58 branches and 7 of `err.c`'s 26 never
taken, and every one of the 17 falls into a class that **no test on a single
host can take**:

-   **The big-endian arms** -- `num.c:13`, `:25`, `:79`, `:80`, `:129`,
    `:135`, `:136`.  All four `numdesc` instantiations set `endian` from
    `nativeendian()`, so `endian == BIG` holds only on a big-endian host and
    the arm is dead on a little-endian one (and vice versa).  This is a
    property of the *host*, not of the suite: the fixtures compute every
    byte-level expectation from the host's own order, so the same assertions
    exercise the other arm, and would catch a defect in it, when run on a
    big-endian machine.
-   **The descriptor-mismatch arms** -- `num.c:117`, `:118`, `:119`.  The
    same instantiations hardcode `limbsize` to 1 and `limbnailbits` to 0 on
    both sides, so the mismatch fallthrough is unsatisfiable through the
    public API; reaching it would need a change to `num.c`.
-   **The assertion-fires arms** -- `err.c:26`, `:27`, `:47`, `:48`, `:49`,
    plus the true arm of each half of the `err.c:30` guard they dominate,
    which is also why `err.c:31` is the one unexecuted line.  An assertion is
    only ever *made* to fail in `test_err_death`, whose children die on
    `SIGABRT` and therefore flush no coverage data, so that contract is
    asserted by an exit status rather than counted here.  This is the same
    effect as the `Calls executed` figure described above.

No percentage is set as a target.  What the suite aims at instead is every
reachable branch, with the reason for each unreachable one recorded -- above
for the three host- and construction-conditional classes, and in the test
sources for the error codes the setters cannot return.  There is no HTML
report step: `lcov`, `genhtml` and `gcovr` are not assumed to be present, and
nothing documented here depends on tooling that may not be installed.

### Sanitizers

The suite also runs clean under AddressSanitizer and
UndefinedBehaviorSanitizer, again in a build tree of its own:

``` bash
cmake -B build-san -DCMAKE_C_FLAGS="-fsanitize=address,undefined -g -fno-omit-frame-pointer"
cmake --build build-san && ctest --test-dir build-san --output-on-failure
```

This is an opt-in verification step and is deliberately not enabled by
default, so that the command under "Running the tests" above remains exactly
what it is.  No target carries a sanitizer flag of its own, nothing writes to
`CMAKE_C_FLAGS`, and `libprov` is never instrumented unless you ask for it
here; the configuration above is the only way a sanitizer reaches any of it.

It is also where the properties the default suite cannot observe are checked,
and the test sources name it for exactly that reason.  The division is worth
stating precisely, because it is narrower than it once was:

-   **Reading a payload it had no business reading** is caught by the
    default suite, not here.  The one fixture that must not be read hands
    `num.c` an address in memory no mapping covers, so a read that must not
    happen ends the test on a signal rather than quietly returning a
    neighbouring byte.  Removing either half of the pre-validation guard at
    `num.c:22-23` -- or the guard entirely -- ends `test_num_get` on
    `SIGSEGV` under the command above with no instrumentation at all; all
    three variants were built and run to confirm it.  What this tree adds is
    the diagnosis: the same removals name `paramsign` at `num.c:30`, and the
    caller above it, instead of reporting only a signal number.

    What that guard does not cover -- and what no fixture here may pin,
    because a fixture that did would fail against the library as it stands
    -- is a payload the caller *declares* but that cannot be read.
    `paramsign()` runs at `num.c:158`, inside the descriptor initialiser,
    before `provnum_copy()` reaches its type whitelist at `num.c:61-65`, so
    a wrong-type descriptor pointing at an unreadable address with a
    declared size of `1` faults for all five non-integer types on both
    getters, where the same descriptor with a declared size of `0` returns
    `-1`.  The guard at `num.c:22-23` is exactly the repair the frozen plan
    specifies, and widening it is excluded by that plan; the reasoning, the
    reproduction and the citations are recorded once, at
    `test_get_wrong_types()` in `tests/test_num_get.c`.
-   **`num.c`'s zero-capacity clamp** is caught by the default suite too, and
    what catches it is specific: reverting the clamp makes `provnum_set_*`
    answer `1` where `-2` is owed, and `test_num_set` reports
    `set_size_t(0) -> zero-capacity UNSIGNED destination, D2: actual 1,
    expected -2` -- one of four mismatches under the mandated build.  That was
    measured, not assumed: the reverted library was detected on **200 runs out
    of 200**, and at `-O0`, `-O1`, `-O2`, `-O3` and `-Os` as well as at the
    mandated build's own flags.  What is *not* guaranteed is which assertions
    fire: the count varied between one and four across those levels, because
    detection rests on a byte inside the library function's own stack frame
    that no fixture can control.  Here it is unconditional:
    AddressSanitizer's per-variable stack redzones report the revert as a
    `stack-buffer-underflow` at `num.c:100 in provnum_copy` whatever that byte
    would have said.
-   **Whether `proverr_free_handle()` releases anything at all** is *not*
    caught by the default suite, and this tree is where it is caught.  Only
    `malloc` is wrapped, so a release is unobservable to `test_err_alloc`;
    reducing that function to a no-op leaves the default build reporting 105
    assertions and 0 mismatches.  Both halves of that claim were measured
    against a modified copy of `err.c`: the default build passes, while the
    same target configured as above exits non-zero with `ERROR:
    LeakSanitizer: detected memory leaks` and names 128 bytes leaked in 4
    allocations, at the allocation site inside `proverr_new_handle`.  This is
    the one property in the suite for which the opt-in tree is the primary
    oracle rather than a second opinion, which is why it is stated here, in
    `tests/test_err_alloc.c` and in `tests/test_err_handle.c` rather than
    left for a reader to discover.

All three were measured against a modified copy of the library rather than
reasoned about, and the test sources name the same spot-checks beside the
assertions that carry them.

### Build artifacts

`.gitignore` carries seven patterns for what these commands produce:
`build/`, `CMakeCache.txt`, `CMakeFiles/` and `Testing/` for the default
build and for anyone who configures in the source tree, and `*.gcno`,
`*.gcda` and `*.gcov` for `gcov`, whose output lands in whatever directory it
was run from.  The mandated command therefore leaves `git status` showing
only what you actually edited.

An in-source configure -- `cmake -S . -B .` -- is covered only in part, and
that is a judgement rather than an omission.  `CMakeCache.txt`, `CMakeFiles/`
and `Testing/` are ignored wherever they land, but the generator's own output
is not: such a configure also writes `Makefile`, `cmake_install.cmake`,
`CTestTestfile.cmake` and `DartConfiguration.tcl` at the source root and a
`Makefile`, a `cmake_install.cmake` and a `CTestTestfile.cmake` under
`tests/`, and `git status` lists all seven.  Patterns wide enough to hide them
would also hide a `Makefile` or a `.cmake` file someone meant to commit, which
is the same trade the optional build trees below are refused.  Configure out
of source, as the command above does, and none of it arises.

`Testing/` earns its entry twice over, because it is not only a source-tree
artifact: a `Testing/` directory appears inside whichever tree is in use, and
two different steps put it there.  `include(CTest)` creates it at configure
time, empty but for a `Temporary/` subdirectory, and `ctest --test-dir` then
writes `LastTest.log` and `CTestCostData.txt` into it; where `LIBPROV_TESTS`
was turned off so that `include(CTest)` never ran, `ctest --test-dir` creates
the directory itself.  The pattern is a bare directory name with no leading or
embedded slash, so it matches at any depth -- inside `build/`, inside the
optional trees named below, and at the source root alike.

The optional recipes above name their own build trees, and those are **not**
ignored, deliberately: an ignore pattern broad enough to cover an arbitrary
`build-<something>/` would also hide a mistakenly committed directory.
Remove them explicitly when you are done:

``` bash
rm -rf build-cov build-san
```

The JUnit file needs no cleanup of its own.  `--output-junit` resolves a
relative path against the build directory, so the invocation above writes
`build/results.xml`, which the `build/` pattern already covers; point it
somewhere else and tidying up is your own affair.

Core images are not ignored either, and the reason is a judgement rather than
an oversight.  An unexpected core file is a defect worth seeing in
`git status`; ignoring the pattern would hide the regression instead of
preventing it.

What prevents it on the hosts that allow it is `test_err_death` dropping
`RLIMIT_CORE` to zero in the forked child before anything can fault, so the
aborts it deliberately provokes write no image.  That is **hygiene, and it is
conditional** -- it is not a guarantee the suite makes everywhere:

-   Where `<sys/resource.h>` and `RLIMIT_CORE` are unavailable the block is
    compiled out, and the expected aborts write core images again, wherever
    `/proc/sys/kernel/core_pattern` (or the platform equivalent) directs them.
-   Where they are available the `setrlimit()` result is deliberately cast
    away rather than checked.  A soft-limit *decrease* cannot fail under
    POSIX, and a host that somehow refused one would simply go back to
    writing the dumps it wrote before.

Neither condition is promoted into a registration gate or a test assertion,
on purpose.  Refusing to register the target would trade the whole abort
contract -- the only positive proof that `err.c`'s assertions fire -- for
tidiness, and failing the target over an unwritten-image regression would be
a false negative: the suite's tests are there to fail for bugs in the
library, not for properties of the host.  The abort contract itself is
unaffected either way, because `WIFSIGNALED()`/`WTERMSIG()` report the signal
whether or not the kernel also wrote an image.

Both behaviours were measured, with `ulimit -c unlimited` in force so that the
kernel was free to write.  As shipped, a direct run of `test_err_death` leaves
**no** core file.  With the suppression block compiled out, the same source
still passes every assertion and leaves **exactly six** images -- one per
aborting case -- of roughly 440 KiB each, wherever `core_pattern` directs
them.  So on a host without `RLIMIT_CORE`, expect them and clean them up;
`git status` showing them is the intended outcome, not a defect in the
suite.

### Prerequisites

-   A C99 compiler.  GCC 13 is the reference the suite is verified with.
    Every test source is standard C99; the two facilities that are not part
    of the language -- a command-line option that undefines a macro, and a
    linker that implements `--wrap` -- are named directly rather than probed
    at configure time, and each is backed where it can be checked without
    guessing: the sources refuse to **compile** if `NDEBUG` reaches them, and
    the allocator target refuses to **link** without its `--wrap` option.
    The paragraphs above say what happens on a host that lacks either.
-   CMake and CTest.  The project's own configure floor is the 3.18 that
    `cmake_minimum_required()` declares, and the test wiring stays well under
    it: the newest thing `tests/CMakeLists.txt` uses is
    `target_link_options`, at 3.13.  The `ctest --test-dir`
    invocations documented above need 3.20 or later, and `--output-junit`
    needs 3.21 or later.  3.23.3 is the reference the suite is verified with.
-   An OpenSSL 3.0 or later development installation that CMake can
    discover.  `find_package(OpenSSL 3.0 REQUIRED)` resolves both an include
    directory and the crypto library -- `FindOpenSSL` lists both among the
    variables it requires when no component is named -- so headers alone are
    not enough to configure the project, even though nothing built here
    links OpenSSL.  Consumption really is headers-only: `libprov`
    references no libcrypto symbol at all, and in the default,
    non-sanitized build a linked test binary's only dynamic dependencies are
    the vDSO, the C library and the loader.  The coverage recipe above does
    not change that either, since what it links is static.  The opt-in
    sanitizer configuration above is the one thing that does, and what it
    adds is the sanitizer runtimes and what they in turn pull in.  No target
    carries a sanitizer flag of its own, so nothing is instrumented unless
    that configuration asks for it.  What none of this adds is an OpenSSL
    library: no binary built by any configuration on this page links one.
-   Nothing else.  There are no environment variables to set, no service or
    database to start, no network access and no fixture files on disk;
    every test input is constructed in memory, which is what makes the
    suite hermetic and independent of the working directory.
-   Optionally, `gcov` for the coverage recipe, AddressSanitizer and
    UndefinedBehaviorSanitizer runtimes for the sanitizer recipe, and what
    the two platform-conditional targets need: `fork()`, `waitpid()`,
    `freopen()` and `SIGABRT` for `test_err_death`, and a linker that acts
    on `--wrap` for `test_err_alloc`.  `setrlimit()` with `RLIMIT_CORE` is
    used by `test_err_death` when `<sys/resource.h>` is available and
    compiled out when it is not, so it is a nicety rather than a
    requirement.  None of this is required: a host without one of them loses
    the corresponding target and configures, builds and runs everything else
    cleanly.
-   Optionally, for a **Release-style** build only, a compiler that accepts
    `-UNDEBUG`.  `test_err_guards` and `test_err_death` need `err.c`'s
    assertions to survive the `-DNDEBUG` that `-DCMAKE_BUILD_TYPE=Release`
    adds project-wide, and that option is how it is done; GCC and Clang both
    accept it, and it is the spelling POSIX gives for `c99`.  A default build
    defines `NDEBUG` nowhere and needs it for nothing, so on a driver that
    rejected it the default build is unaffected and only a Release-style
    build is refused -- at compile time, by the sources' own pins, with a
    diagnostic naming the cause.
