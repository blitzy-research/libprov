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
themselves, from an `OSSL_PARAM` brace initialiser over a test-owned buffer
to a hand-built `OSSL_DISPATCH` table of stub callbacks and a test-local
`OSSL_CORE_HANDLE`.  Nothing here needs a running provider, and no
libcrypto function is ever called.

### Running the tests

``` bash
cmake -B build && cmake --build build && ctest --test-dir build
```

That builds and runs the whole suite, and it needs no `-D` flag of any
kind: the tests are configured and built by default whenever `libprov` is
the top-level project.

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
    optional: `--output-junit` needs CMake 3.21 or later, while the project
    itself requires only 3.18.
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
-   `test_err_guards` covers the invalid-input contract with the project's
    default flags, where `err.c`'s assertions are live.
-   `test_err_guards_ndebug` covers the same source with `err.c` compiled
    under `NDEBUG`, where those assertions vanish and the graceful `NULL`
    returns become reachable instead.
-   `test_err_death` asserts the abort contract positively: it forks, lets
    the child run an aborting input, and requires the child to have died of
    `SIGABRT`.  POSIX only, and it carries a 30 second timeout as a safety
    net.
-   `test_err_alloc` covers the out-of-memory paths, which no input can
    reach, by wrapping the allocator with `-Wl,--wrap=malloc` and
    `-Wl,--wrap=free`.  GNU `ld` only.

The last two are platform-conditional.  Where a host has no POSIX process
control, or no GNU `ld` `--wrap`, the affected test is simply not
registered: never registered and skipped, and never allowed to fail.
Configuration still succeeds there, and the other six run normally.

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
exactly what it is.

### Prerequisites

-   A C99 compiler.  GCC 13 is the reference the suite is verified with.
-   CMake and CTest.  The project declares a 3.18 floor, and 3.23.3 is the
    reference the suite is verified with.
-   OpenSSL 3.0 or later development headers on the include path, which is
    what `find_package(OpenSSL 3.0 REQUIRED)` needs.  No OpenSSL library is
    linked and only the headers are consumed: `libprov` references no
    libcrypto symbol at all, and a linked test binary's only dynamic
    dependencies are the vDSO, the C library and the loader.
-   Nothing else.  There are no environment variables to set, no service or
    database to start, no network access and no fixture files on disk;
    every test input is constructed in memory, which is what makes the
    suite hermetic and independent of the working directory.
-   Optionally, `gcov` for coverage, a POSIX host for `test_err_death`, and
    GNU `ld` for `test_err_alloc`.
