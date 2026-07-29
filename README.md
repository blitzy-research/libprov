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
top-level `libprov` build therefore includes CTest at the source root, which is
what makes `ctest --test-dir build` see all of it.

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
-   `test_err_alloc` covers the out-of-memory paths, which no input can
    reach, by wrapping the allocator with `-Wl,--wrap=malloc`.  `free` is
    deliberately left unwrapped, so this target interposes on exactly one
    function and nothing in stdio is disturbed -- interposing on every
    deallocation the process makes is the one thing that could make an
    allocation-failure test non-deterministic.  What that leaves out is worth
    knowing precisely: the suite requires a duplicate to be a distinct object
    and the source handle to outlive a freed copy, which rules out a release
    that let go of the source, but **no target run by the command above
    observes a release positively** -- reduce `proverr_free_handle()` to a
    no-op and all eight still pass.  That property is covered by the
    sanitizer configuration described further down, where the allocator is
    the witness by construction and the same change raises leak reports in
    five of the eight targets.  Registered only where the toolchain supplies
    GNU-`ld`-style `--wrap`.

### The two platform-conditional targets

Six of the eight targets are registered unconditionally and need nothing
beyond standard C99.  The remaining two need interfaces that not every host
provides, so each sits behind a gate in `tests/CMakeLists.txt`.  Where a
gate does not hold the target is **not registered at all**: configuration
still succeeds, the other six (or seven) still run, and nothing is ever
registered and then skipped or allowed to fail.

-   `test_err_death` sits behind `if(UNIX)`, and needs `fork()`,
    `waitpid()` and the wait-status macros, and `SIGABRT`.
-   `test_err_alloc` sits behind
    `if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang" AND UNIX AND NOT APPLE)`,
    and needs a linker that acts on `-Wl,--wrap=malloc`: one that creates
    `__wrap_malloc` and resolves `__real_malloc`.

A gate is a coarser instrument than a per-interface probe, and the sources
are written so that nothing finer is needed.  `test_err_death` requires only
what `if(UNIX)` genuinely implies: `fork()`, `waitpid()` and `SIGABRT` are
the harness itself, and the one facility that is merely *desirable* --
`setrlimit(RLIMIT_CORE)`, which stops each expected abort from leaving a
core image -- is picked up through `__has_include(<sys/resource.h>)` and
compiled out where it is unavailable.  That was measured both ways: with the
header the target leaves no core file behind, and with the block compiled
out it still passes every assertion and simply writes the images again.  So
a UNIX-like host without `<sys/resource.h>` builds and passes rather than
failing to compile, which is the failure mode a bare platform gate could
otherwise have.

`test_err_alloc`'s gate names the compiler driver and the platform because
`--wrap` is a GNU-`ld` facility and Apple's linker does not provide it.  The
link option is not optional for that target: an unwrapped `malloc` never
fails on a machine with memory to spare, so every "returns `NULL`"
assertion would turn vacuous.  The source therefore refuses to link without
it -- it references `__real_malloc`, a name only `--wrap` creates -- so a
missing option is a link error rather than a silently passing test.

`-UNDEBUG` is applied to `test_err_guards` and `test_err_death` literally
and unconditionally.  It is what keeps `err.c`'s assertions live even under
`-DCMAKE_BUILD_TYPE=Release`, which adds `-DNDEBUG` project-wide; making it
conditional would trade a compile-time diagnostic on a hypothetical host for
a silent hole on a real one.

So a POSIX host with GNU-`ld`-style `--wrap` registers all eight tests, and
all eight are registered and pass under the default build, under a Release
build, under `--coverage` and under `-fsanitize=address,undefined`.

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
The paths above name the objects compiled into `libprov`, which is what six
of the eight targets link; `err.c` is *additionally* compiled into
`test_err_guards`, `test_err_guards_ndebug` and `test_err_death` with their
own flags, and each of those has its own `.gcno` under
`build-cov/tests/CMakeFiles/<target>.dir/__/`.  And on the `libprov` object
`gcov` reports the five `__assert_fail` calls as never executed -- `Calls
executed` sits at 54.55% -- because an assertion is only ever made to fail
in `test_err_death`, whose children die on `SIGABRT` and so flush no coverage
data at all.  That contract is asserted by that target's exit-status check,
not by a coverage count, which is the point of having it.

No percentage is set as a target.  What the suite aims at instead is every
reachable branch, and the branches that are unreachable by construction are
named, with the reason each is unreachable, in the test sources.  There is
no HTML report step: `lcov`, `genhtml` and `gcovr` are not assumed to be
present, and nothing documented here depends on tooling that may not be
installed.

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
    default suite, not here.  The fixtures that must not be read hand
    `num.c` an address in memory no mapping covers, so a read that must not
    happen ends the test on a signal rather than quietly returning a
    neighbouring byte.  Reverting the type gate in `paramsign()`, or either
    half of its pre-validation guard, fails `test_num_get` under the
    command above with no instrumentation at all.  What this tree adds is
    the diagnosis: the same revert reports `SEGV ... in paramsign num.c:27`
    with a stack trace instead of only a signal number.
-   **`num.c`'s zero-capacity clamp** is caught by the default suite too,
    and less firmly.  Reverting it makes `provnum_set_*` answer `1` where
    `-2` is owed, which the existing assertions do detect -- measured on 200
    runs of 200, at every optimisation level tried -- but only because a
    byte inside the library function's own stack frame happens to say so,
    and no fixture can control that byte.  Here it is unconditional:
    AddressSanitizer's per-variable stack redzones report the revert as a
    `stack-buffer-underflow` at `num.c:94 in provnum_copy` whatever that
    byte would have said.
-   **Whether `proverr_free_handle()` releases anything at all** is the one
    property the default suite genuinely cannot see, and this is where it is
    covered.  Reduce that function to a no-op and all eight targets still
    pass above; in this tree LeakSanitizer reports leaks in five of them.

Each of those was measured, and each is re-checked by the mutation
spot-checks the test sources describe.

### Build artifacts

`.gitignore` carries seven patterns for what these commands produce:
`build/`, `CMakeCache.txt`, `CMakeFiles/` and `Testing/` for the default
build and for anyone who configures in the source tree, and `*.gcno`,
`*.gcda` and `*.gcov` for `gcov`, whose output lands in whatever directory it
was run from.  The mandated command therefore leaves `git status` showing
only what you actually edited.

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

Core images are not ignored either.  The one place the suite forks --
`test_err_death` -- drops `RLIMIT_CORE` to zero in the child before anything
can fault, so the aborts it deliberately provokes write no image and there is
nothing to hide.  An unexpected core file is a defect worth seeing in
`git status`, and ignoring it would hide the regression rather than prevent
it.

### Prerequisites

-   A C99 compiler.  GCC 13 is the reference the suite is verified with.
-   CMake and CTest.  The project's own configure floor is the 3.18 that
    `cmake_minimum_required()` declares; the `ctest --test-dir` invocations
    documented above need 3.20 or later, and `--output-junit` needs 3.21 or
    later.  3.23.3 is the reference the suite is verified with.
-   An OpenSSL 3.0 or later development installation that CMake can
    discover.  `find_package(OpenSSL 3.0 REQUIRED)` resolves both an include
    directory and the crypto library -- `FindOpenSSL` lists both among the
    variables it requires when no component is named -- so headers alone are
    not enough to configure the project, even though nothing built here
    links OpenSSL.  Consumption really is headers-only: `libprov`
    references no libcrypto symbol at all, and in the default,
    non-sanitized build a linked test binary's only dynamic dependencies are
    the vDSO, the C library and the loader.  The opt-in sanitizer
    configuration above is the one exception, and what it adds is the
    sanitizer runtimes and what they in turn pull in -- still no OpenSSL
    library.
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
    cleanly.  The six unconditional targets need nothing beyond standard
    C99.
