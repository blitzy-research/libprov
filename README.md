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

`BUILD_TESTING`, the option CTest itself provides, also has a say, and it has
the last word: with `-DBUILD_TESTING=OFF` no test target is created at all,
and configuration says so.  That is deliberate rather than incidental —
`BUILD_TESTING=OFF` means nothing called `enable_testing()`, so `add_test()`
would be silently dropped and a build would otherwise produce a directory full
of test executables with no registered test behind any of them.  Nothing is ever
registered and then disabled; there is no `DISABLED` property and no
`SKIP_RETURN_CODE` anywhere in the suite.  The command under "Running the
tests" passes no flag, so `BUILD_TESTING` is at its default of `ON` there and
that command builds and runs everything.

### Embedding `libprov` and asking for its tests anyway

Where testing is enabled decides where `ctest` can find the tests, because
`ctest` reads `CTestTestfile.cmake` from the directory it is pointed at and
CMake writes that file only for a directory in which testing was enabled.  A
top-level `libprov` build therefore includes CTest at the source root, which is
what makes `ctest --test-dir build` see all of it.

A project that embeds `libprov` and sets `-DLIBPROV_TESTS=ON` gets one of two
outcomes, and configuration tells it which:

-   **The parent project included CTest** — it calls `include(CTest)` in its own
    top-level `CMakeLists.txt`, before the `add_subdirectory()` that adds
    `libprov`, and leaves `BUILD_TESTING` `ON`.  `libprov`'s tests then register
    into the parent's test tree and run from the parent's build root, with no
    warning:

    ``` bash
    ctest --test-dir <parent build dir>
    ```

-   **Nothing in the build included CTest** — configuration warns that `libprov`
    cannot confirm the top level enabled testing, and registers the tests in
    `libprov`'s own subtree, which is a complete `ctest` tree of its own.  That
    subtree always works:

    ``` bash
    ctest --test-dir <parent build dir>/<the directory add_subdirectory put libprov in>
    ```

    `libprov` cannot fix this from where it sits: enabling CTest from a
    subdirectory would write `CTestTestfile.cmake` under that subdirectory and
    leave the build root without one, which is the worst of the options — tests
    that exist and are invisible to `ctest` at the top level.  The warning names
    the sub-build command to use and the one-line change that gives top-level
    discovery instead.

The two cases are told apart by the **cache entry type** of `BUILD_TESTING`,
which is `BOOL` exactly when the CTest module created it.  Mere existence would
not do: a bare `-DBUILD_TESTING=ON` defines the variable without any module
having run, and gating on existence was measured building every test,
leaving the parent build root with no `CTestTestfile.cmake`, and saying nothing
at all — the silent case this warning exists to prevent.  A parent that calls
bare `enable_testing()` instead of `include(CTest)` leaves no `BUILD_TESTING`
behind either, so it is warned as unconfirmed even though its own build root
does discover the tests; nothing in the message claims otherwise, and both
commands above are accurate for it.

Embedded builds that leave `LIBPROV_TESTS` at its default of `OFF` are
unaffected by all of this: no test target is created, no CTest machinery is
touched, no capability probe even runs, and there is no warning.

### The tests

-   `test_num_get` covers `provnum_get_size_t()` and `provnum_get_int()`:
    the success value, the width and signedness edges, every reachable
    error code, and the order the guards are evaluated in when more than
    one of them applies.  Where the protected-page probe below succeeds it
    also carries the guard-page group.
-   `test_num_set` covers `provnum_set_size_t()` and `provnum_set_int()`:
    the return codes, the exact bytes written to the destination, and
    `return_size`, which is set on every path, including the ones that
    fail.  It carries the same guard-page group, on the same condition.
-   `test_num_set_memory` is that same source compiled a second time,
    together with `num.c`, under `-fsanitize=address`.  It exists for one
    thing the other targets cannot see: `num.c` has a guard whose only
    purpose is to keep an index inside a buffer, and removing it makes the
    library read one byte below its OWN stack parameter.  A protected page
    can only be placed at an object a test allocates, so nothing else in
    the suite can bound that access; per-variable instrumentation of `num.c`
    can, which is why `num.c` is named in this target's source list.  The
    flags are applied to this target alone, so `libprov`, the ordinary
    `test_num_set` and every other target compile exactly as they would
    without it, and `CMAKE_C_FLAGS` is untouched.  Its first case is a
    deliberate out-of-bounds read that is required to be caught, so a build
    where the instrumentation was somehow inert fails rather than passing
    vacuously.
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
    registered only where the capability probe below succeeds.
-   `test_err_alloc` covers the out-of-memory paths, which no input can
    reach, by wrapping the allocator with `-Wl,--wrap=malloc` and
    `-Wl,--wrap=free`.  Registered only where the linker probe below
    succeeds.

### Optional mechanisms and how configuration decides on them

Six of those nine targets are always registered.  The rest of the suite is
optional because it needs interfaces that not every host provides, and which
of those parts are used is decided by **capability probes** run at configure
time -- never by the name of the platform or the brand of the compiler.  Each
probe compiles, links and in one case RUNS a program that names every
interface the corresponding source actually uses, at the same feature-test
level and with the same flags the real target is built with.  A probe that
fails costs exactly the mechanism it covers: configuration still succeeds, and
nothing is registered and then skipped or allowed to fail.

| Probe | What it must find | If it fails |
|---|---|---|
| the protected-page oracle | `mmap`, `mprotect`, `munmap` with `MAP_ANONYMOUS` (or `MAP_ANON`), `MAP_PRIVATE`, `MAP_SHARED` and the `PROT_*` flags; `sysconf(_SC_PAGESIZE)`; `fork`, `waitpid` and the wait-status macros; `<sys/resource.h>` with `setrlimit` and `RLIMIT_CORE`; `freopen` | `LIBPROV_TEST_GUARD_PAGES` is not defined.  `test_num_get` and `test_num_set` are **still registered and still run**, one guarded group lighter; every other case in them is unchanged |
| the abort harness | `fork`, `waitpid` and the wait-status macros; `SIGABRT`; `<sys/resource.h>` with `setrlimit` and `RLIMIT_CORE`; `_exit`; `freopen` | `test_err_death` is **not registered at all** |
| `-UNDEBUG` | that the compiler accepts the option | the option is not applied.  `test_err_guards` and `test_err_death` are still registered, and assert what the build type leaves reachable |
| allocator interposition | that the **active linker**, given `-Wl,--wrap=malloc` and `-Wl,--wrap=free`, really routes the allocator through `__wrap_malloc`/`__wrap_free` and resolves `__real_malloc`/`__real_free` | `test_err_alloc` is **not registered at all** |
| memory instrumentation | that an instrumented one-byte under-read, actually RUN in a forked child, is caught | `test_num_set_memory` is **not registered at all** |

The two `<sys/resource.h>` entries are not decoration: both harnesses lower
`RLIMIT_CORE` to zero in the child they fork, so an expected fatal signal
leaves no core image behind.  A host with `fork()` but without that interface
is exactly the case a platform-name check gets wrong, and it was measured:
with an `if(UNIX)` gate such a host failed to **build**, and with the probes it
configures cleanly and runs the suite one target and one group lighter.

The linker probe decides on the same evidence, and on nothing weaker.  What it
links is the shape `test_err_alloc` itself links: a program that defines
`__wrap_malloc` and `__wrap_free`, allocates through them, and reaches
`__real_malloc`/`__real_free` -- names that exist only because `--wrap` creates
them.  Merely *accepting* the flag is not the test, and CMake's own
`CheckLinkerFlag` documentation says why: a positive result there means only
that the compiler issued no diagnostic, so acceptance is neither necessary nor
sufficient.  It is measurably worse than that -- gating on acceptance rejects
this target under `--coverage`, where the `libgcov` that gets linked in has its
own `malloc` and `free` calls rewritten and the flag-check's own trivial
program supplies no `__wrap_*` to satisfy them, while the target itself builds
and passes there.  A compiler's identity is never consulted either: `cc` can be
pointed at a linker without `--wrap`, and a linker with `--wrap` can be driven
by a compiler CMake names something else.

The instrumentation probe is the one that has to RUN rather than merely link,
for the same class of reason: a driver can accept `-fsanitize=address` on a
host where the runtime is unavailable or stack instrumentation is off, and a
target registered on that answer would pass having proved nothing.

A probe that fails says so.  Configuration prints one `-- libprov tests: ...`
line naming the interfaces that were missing and what it cost, so a smaller
number in the `ctest` summary is explained rather than mysterious; a host that
supports everything prints nothing.

So a fully capable host registers all nine tests.  Each of the counts below was
verified by forcing the corresponding probe to fail, and in every case
configuration and the build stayed warning-free and every registered test
passed:

| Forced to fail | Registered | Effect |
|---|---|---|
| nothing | 9 | the reference host |
| the protected-page oracle | 8 | both numeric targets run without their guarded groups, and the instrumentation probe is not even asked, since its cases run inside that harness |
| the abort harness | 8 | `test_err_death` absent |
| allocator interposition | 8 | `test_err_alloc` absent |
| memory instrumentation | 8 | `test_num_set_memory` absent |
| `-UNDEBUG` | 9 | nothing is dropped; the option is simply not applied |
| all four mechanisms | 6 | only the six unconditional targets |

All nine are registered under the default build, under `--coverage` and under
`-fsanitize=address,undefined`.

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
the directory it is run from.  For reference, the current sources give
`gcov` 58 executable lines and 58 branches in `num.c`, and 52 executable
lines and 26 branches in `err.c`, though the exact counts depend on the
compiler.

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
default, so that the command under "Running the tests" above remains
exactly what it is.  The one exception is not an exception to that: the
`test_num_set_memory` target described above carries `-fsanitize=address`
through `target_compile_options` and `target_link_options`, on that target
and no other.  `CMAKE_C_FLAGS` is never written to, `libprov` is not
instrumented, and the whole-project run above is still the only way to put a
sanitizer on everything.

### Build artifacts

Everything the commands on this page produce is ignored, so running any of
them leaves `git status` showing only what you actually edited.  `.gitignore`
covers `build/` and, through `build-*/`, the `build-cov/` and `build-san/`
trees the two recipes above create; `gcov`'s `*.gcno`, `*.gcda` and `*.gcov`
output, which lands in whatever directory `gcov` was run from; the
`results.xml` that `--output-junit` writes; and `CMakeCache.txt`,
`CMakeFiles/` and `Testing/` for anyone who configures in the source tree.

Core images are deliberately **not** ignored.  Both places the suite forks --
the protected-page harness and the abort harness -- drop `RLIMIT_CORE` to
zero in the child before anything can fault, so the deaths those two
deliberately provoke write no image and there is nothing to hide.  An
unexpected core file is a defect worth seeing in `git status`, and ignoring
it would hide the regression rather than prevent it.

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
-   Optionally, `gcov` for coverage, and whatever the capability probes
    described under "Optional mechanisms" ask for: `mmap()`, `mprotect()`,
    `munmap()`, `fork()`, `waitpid()`, `setrlimit()`, `sysconf()`,
    `freopen()` and `MAP_ANONYMOUS` (or `MAP_ANON`) for the protected-page
    fixtures, the same process and resource-limit interfaces plus `SIGABRT`
    for `test_err_death`, a linker that really acts on `--wrap` for
    `test_err_alloc`, and a working AddressSanitizer runtime for
    `test_num_set_memory`.  None of these is required: a host without one
    loses the corresponding target or group and configures, builds and runs
    everything else cleanly.  The six mandatory targets need nothing beyond
    standard C99.
