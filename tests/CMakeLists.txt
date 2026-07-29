# CC0 license applied, see LICENSE
#
# ===========================================================================
# tests/CMakeLists.txt -- registration of the libprov unit test suite
# ===========================================================================
#
# This listfile is the single place where the suite is wired to CTest.  It
# defines one helper, libprov_add_test(), and uses it to register eight test
# executables:
#
#   test_num_get            provnum_get_size_t() / provnum_get_int():
#                           contract, boundaries, widths, signedness,
#                           error-code precedence and -- on POSIX hosts --
#                           guarded memory-safety boundaries
#   test_num_set            provnum_set_size_t() / provnum_set_int():
#                           contract, capacity edges, byte-level output, the
#                           return_size-on-every-path invariant and -- on POSIX
#                           hosts -- guarded memory-safety boundaries
#   test_err_handle         proverr_new_handle() dispatch resolution plus
#                           duplication and free semantics
#   test_err_raise          argument-forwarding fidelity, ERR_raise /
#                           ERR_raise_data ordering and call-site capture
#   test_err_guards         err.c's guards with assertions LIVE
#   test_err_guards_ndebug  the same source with err.c compiled under NDEBUG,
#                           where the graceful NULL returns become reachable
#   test_err_death          the POSITIVE assertion that the live assertions
#                           really abort (POSIX only)
#   test_err_alloc          err.c's out-of-memory contract, via deterministic
#                           allocation-failure injection (GNU ld only)
#
# The suite is meant to be run with no configure-time flag of any kind:
#
#     cmake -B build && cmake --build build && ctest --test-dir build
#
# Useful variations, none of which this file has to provide anything for:
# --output-on-failure, -R <pattern>, -E <pattern>, -j <N>, and
# --no-tests=error (which must now exit 0 -- it exited 8 while the suite was
# empty).  Coverage and sanitizers are opt-in through CMAKE_C_FLAGS and are
# deliberately absent from this file, so the command above stays exactly the
# command above.
#
# ---------------------------------------------------------------------------
# DIVISION OF RESPONSIBILITY WITH THE ROOT LISTFILE
# ---------------------------------------------------------------------------
# The root CMakeLists.txt owns the decision to build tests at all:
#
#     if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
#       set(LIBPROV_TESTS_DEFAULT ON)
#     else()
#       set(LIBPROV_TESTS_DEFAULT OFF)
#     endif()
#     option(LIBPROV_TESTS "Build and possibly run tests"
#            ${LIBPROV_TESTS_DEFAULT})
#
#     if(LIBPROV_TESTS)
#       include(CTest)
#       add_subdirectory(tests)
#     endif()
#
# Everything this file must NOT do follows from that block, and each omission
# below is deliberate rather than forgotten:
#
#   no enable_testing()       the root's include(CTest) already called it, and
#                             it ran before add_subdirectory(tests)
#   no include(CTest)         likewise the root's, and including it twice is
#                             pointless noise
#   no option(LIBPROV_TESTS)  redefining it here would shadow the root's
#                             computed default and break the flagless command.
#                             The name and the description string are the
#                             maintainer's own and are preserved verbatim.
#   no if(LIBPROV_TESTS)      the root already guards the add_subdirectory()
#                             call; a second guard would be redundant and
#                             would silently yield an empty suite if the
#                             variable were ever scoped differently
#   no cmake_minimum_required(), no project()
#                             this is a subdirectory listfile, not a project
#
# A project that embeds libprov with add_subdirectory() therefore still gets
# the maintainer's opt-out: LIBPROV_TESTS defaults OFF there, this file is
# never read, and not one test target is created.  Nothing here creates a
# target outside that guard.
#
# ---------------------------------------------------------------------------
# NO USER-SPECIFIED RULES EXIST FOR THIS PROJECT
# ---------------------------------------------------------------------------
# The rules facility reports, in full, "No user rules provided."  No rule has
# been invented to stand in for the ones that do not exist, and their absence
# is not treated as licence to lower the bar.  What binds this file is the
# request itself: the exact flagless command above must work; no test may be
# deleted, skipped, weakened or relaxed; no non-test source may be modified;
# and the tests must run independently and in parallel.  Beyond that it is
# held to ordinary enterprise practice.
#
# ---------------------------------------------------------------------------
# VERSION FLOOR
# ---------------------------------------------------------------------------
# The project declares cmake_minimum_required(VERSION 3.18 FATAL_ERROR), so
# nothing here may need more than 3.18.  Everything used below is at or under
# that floor: cmake_parse_arguments (3.5), target_include_directories and
# target_compile_definitions (2.8.11), target_compile_options (2.8.12),
# target_link_options (3.13), add_test(NAME.. COMMAND..) (2.8),
# set_tests_properties, and the UNIX / APPLE / CMAKE_C_COMPILER_ID variables.
# PROJECT_IS_TOP_LEVEL (3.21) is avoided -- the root computes the same thing
# from CMAKE_SOURCE_DIR -- and ctest --output-junit (3.21) is documented in
# the README as an optional invocation and never wired into the build.

# ---------------------------------------------------------------------------
# libprov_add_test(<name> [SOURCES <src>...] [DEFS <def>...]
#                         [COPTS <opt>...]  [LINKOPTS <opt>...])
# ---------------------------------------------------------------------------
# Builds one test executable and registers it with CTest.  The body is the
# maintainer's own four-step per-directory pattern -- add_executable,
# target_link_libraries(PRIVATE libprov), target_include_directories(PRIVATE
# ${OPENSSL_INCLUDE_DIR}), add_test -- plus the three optional per-target
# knobs the eight registrations below need.  Keeping it in a function is what
# stops eight copies of that pattern from drifting apart.
#
# All four keywords are multi-value: SOURCES takes two entries for the targets
# that compile err.c in, and DEFS takes two for the NDEBUG variant.  There are
# no options and no single-value keywords.  ${ARGN} excludes <name>, which is
# the function's own positional parameter.
function(libprov_add_test name)
  cmake_parse_arguments(A "" "" "SOURCES;DEFS;COPTS;LINKOPTS" ${ARGN})

  add_executable(${name} ${A_SOURCES})

  # The CMake TARGET name is libprov.  It is not "prov": that is only the
  # OUTPUT_NAME the root sets, so the archive on disk is libprov.a while the
  # target that produces it is libprov.  Linking "prov" would look plausible
  # and fail.  Linking libprov also brings its PUBLIC include directory along,
  # which is what makes #include "prov/err.h" and "prov/num.h" resolve.
  target_link_libraries(${name} PRIVATE libprov)

  # MANDATORY on every single target, and the likeliest thing to get wrong in
  # the whole suite.  The root declares the OpenSSL include directory PRIVATE
  # on libprov, so -- unlike the PUBLIC include/ directory -- it does NOT
  # propagate through target_link_libraries.  Without this line the tests fail
  # to find openssl/core.h, reached transitively from prov/num.h and
  # prov/err.h.  On a host where OPENSSL_INCLUDE_DIR happens to be /usr/include
  # the omission is masked by the compiler's default search path, which makes
  # it a portability bug rather than a build failure -- the worse of the two.
  # The fix is here, never in the root: that file is append-only and its
  # PRIVATE declaration is part of the build interface being preserved.
  target_include_directories(${name} PRIVATE ${OPENSSL_INCLUDE_DIR})

  # The test sources include their shared fixtures in quoted form --
  # "testutil.h", "mock_core.h", "param_util.h" -- which a compiler normally
  # resolves relative to the including file.  That is not enough for the
  # targets whose source list also names a file from outside this directory
  # (${PROJECT_SOURCE_DIR}/err.c): naming this directory explicitly makes the
  # lookup independent of the including file's location, of the generator, and
  # of how the generator spells the path it hands to the compiler.
  target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

  # Each optional knob is applied only when it was supplied.  An unguarded
  # call with an empty list would be a configure error, not a no-op.
  if(A_DEFS)
    target_compile_definitions(${name} PRIVATE ${A_DEFS})
  endif()
  if(A_COPTS)
    target_compile_options(${name} PRIVATE ${A_COPTS})
  endif()
  if(A_LINKOPTS)
    target_link_options(${name} PRIVATE ${A_LINKOPTS})
  endif()

  # Everything above is PRIVATE because these are leaf executables: nothing
  # links them, so there is no usage requirement to hand on.
  #
  # Naming the TARGET as the COMMAND -- rather than a path -- lets CMake
  # substitute wherever it actually put the executable.  That is what makes
  # ctest --test-dir build work without this file touching any output
  # directory property, and it keeps the binaries at the default
  # build/tests/<name> location the README documents.
  add_test(NAME ${name} COMMAND ${name})
endfunction()

# ---------------------------------------------------------------------------
# The protected-boundary oracle for the two numeric targets (POSIX hosts)
# ---------------------------------------------------------------------------
# Three of num.c's guards exist only to keep an index inside its buffer, and
# removing any of them changes no return code and no destination value for any
# input: paramsign()'s zero-size guard (num.c:24-25), the padding-strip loop's
# bound (num.c:100) and the padding offset (num.c:132).  MEASURED: with the
# first of those reintroduced, all eight targets stayed green.  Their only
# observable is an access one byte outside an object, and the mandated command
# passes no sanitizer flag, so without a mechanism here they are untested under
# the command that matters.
#
# LIBPROV_TEST_GUARD_PAGES switches on param_util.h's oracle, which maps three
# pages, makes the outer two PROT_NONE, places a fixture flush against an edge
# and runs it in a forked child so the resulting fault is reported as a named
# assertion failure instead of killing the test binary.  It changes NO existing
# case: it adds one group to each numeric target and leaves everything else
# byte for byte as it was.
#
# One defect is deliberately NOT claimed here.  Reverting the zero-capacity
# clamp at num.c:99 makes the strip loop read one byte below provnum_set_*'s own
# `src` parameter -- inside the library function's stack frame, which a test owns
# no part of and can put no page against, so whether that revert changes any
# answer is decided by a byte no fixture controls (measured here: it does, 200
# runs out of 200, which is a fact about this host and not a mechanism).  The two
# numeric targets pin that input's full documented answer in every build, the
# guarded groups pin the neighbouring property that a zero-capacity call touches
# no destination byte, and the read itself is detected by the opt-in
# -fsanitize=address configuration the specification names for that purpose and
# equally forbids making a default.  tests/test_num_set.c records the reasoning
# and the alternatives that were tried and rejected.
#
# It rides on the two EXISTING registrations through a computed variable rather
# than through extra libprov_add_test() calls, because the registered target
# count is part of this suite's shape: eight targets, named in the header above,
# and this mechanism is a property of two of them rather than a target of its
# own.  The definition is applied per target, so the six error targets are
# untouched and neither the allocator interposer nor the abort harness -- each
# file-local to its own executable -- shares a process with it.
#
# mmap(), mprotect(), fork() and waitpid() are POSIX, so on a host without them
# the definition is simply not made: the two targets are still registered and
# still run, one group lighter.  That mirrors how test_err_death and
# test_err_alloc are handled -- never registered and skipped, never registered
# and allowed to fail -- so there is still no DISABLED property, no
# SKIP_RETURN_CODE and no exclusion filter anywhere in this file.  The numeric
# sources set their own feature-test level before their first #include, and
# param_util.h fails the compile with a diagnostic naming the cause if a C
# library still hides MAP_ANONYMOUS.
set(LIBPROV_NUM_DEFS "")
if(UNIX)
  list(APPEND LIBPROV_NUM_DEFS LIBPROV_TEST_GUARD_PAGES)
endif()

# ---------------------------------------------------------------------------
# The four straightforward targets
# ---------------------------------------------------------------------------
# Nothing special: one source each, the project's default flags, and err.c and
# num.c reached through the libprov archive.  Each target is named after its
# source's basename so that ctest -R test_num_get and ctest -R "test_num_.*"
# select what a reader expects them to.
#
# The two numeric targets carry ${LIBPROV_NUM_DEFS} from the block above, which
# is empty on a non-POSIX host; libprov_add_test() applies DEFS only when the
# list is non-empty, so an empty one is a genuine no-op rather than a configure
# error.
libprov_add_test(test_num_get     SOURCES test_num_get.c
                                  DEFS ${LIBPROV_NUM_DEFS})
libprov_add_test(test_num_set     SOURCES test_num_set.c
                                  DEFS ${LIBPROV_NUM_DEFS})
libprov_add_test(test_err_handle  SOURCES test_err_handle.c)
libprov_add_test(test_err_raise   SOURCES test_err_raise.c)

# ---------------------------------------------------------------------------
# The two build variants of err.c's guard contract
# ---------------------------------------------------------------------------
# proverr_new_handle() has two mutually exclusive contracts, and which one is
# in force is decided by the preprocessor, not by any input:
#
#   assertions live (the default build)   an invalid core handle, an invalid
#                                         dispatch table, or a table that
#                                         fails to supply all three callbacks
#                                         ABORTS -- err.c:26, :27, :47, :48,
#                                         :49
#   NDEBUG defined                        those assertions vanish, the guard
#                                         at err.c:51-54 becomes reachable,
#                                         and the same inputs return NULL
#
# No single set of flags can exhibit both, so the one source below is compiled
# twice, into two targets, and asserts the contract that its own build makes
# reachable.  Neither half may be dropped: without the default target the
# aborts are unasserted, and without the NDEBUG target the graceful returns
# are unasserted.
#
# WHY err.c IS IN THE SOURCE LIST, AND WHY THE OBVIOUS ALTERNATIVE FAILS
#
# The obvious arrangement -- one target, DEFS NDEBUG, linking libprov -- does
# not work.  assert() expands according to the NDEBUG state of the translation
# unit that CONTAINS the call, and every call that matters here is inside
# err.c.  libprov compiles err.c exactly once, with the project's own flags
# and no NDEBUG, so a definition on the TEST target cannot reach the object
# already sitting in the archive: such a variant would still abort, and its
# every "returns NULL" assertion would be fiction rather than test.
# Recompiling err.c per target is what actually puts the guard state under the
# test's control.
#
# Compiling err.c into a target is not modifying it.  The file on disk is
# untouched byte for byte; only an additional compilation of it exists.  That
# keeps this arrangement compatible with the constraint that no non-test
# source may be modified -- and no defect was found in err.c, so it is read
# here and nothing more.
#
# Linking stays unambiguous even though libprov is still linked, which it must
# be for num.c and for the PUBLIC include directory: a definition in an object
# file named on the link line satisfies the reference before any archive is
# searched, so the corresponding libprov member is simply never extracted and
# each binary holds exactly one proverr_new_handle().  `nm` confirms both that
# and that the flags landed -- the ndebug binary contains no reference to
# __assert_fail while the default binary does.
#
# WHY -UNDEBUG ON THE DEFAULT VARIANT
#
# Because NDEBUG is not this suite's to own.  -DCMAKE_BUILD_TYPE=Release adds
# -DNDEBUG to every target in the project, which would silently turn the
# default variant into a second NDEBUG variant -- err.c's assertions gone,
# while the test body still asserted that they fire.  The explicit -UNDEBUG
# pins the default target's err.c to live assertions whatever the build type.
#
# WHY THE MARKER DEFINE, AND NOT NDEBUG, SELECTS THE TEST BODY
#
# For the mirror-image reason: test_err_guards.c branches on
# LIBPROV_TEST_NDEBUG_VARIANT, a name exactly one target sets and nothing else
# in the project defines.  Had it branched on NDEBUG, a Release build would
# have flipped the default target's body too -- asserting graceful NULL
# returns against an err.c whose own -UNDEBUG kept the aborts live.  The
# ndebug target therefore needs BOTH defines and they do different jobs:
# NDEBUG reconfigures err.c, and the marker tells the test body which of the
# two contracts to assert.
libprov_add_test(test_err_guards
                 SOURCES test_err_guards.c ${PROJECT_SOURCE_DIR}/err.c
                 COPTS -UNDEBUG)
libprov_add_test(test_err_guards_ndebug
                 SOURCES test_err_guards.c ${PROJECT_SOURCE_DIR}/err.c
                 DEFS NDEBUG LIBPROV_TEST_NDEBUG_VARIANT)

# ---------------------------------------------------------------------------
# The abort contract, asserted positively (POSIX hosts)
# ---------------------------------------------------------------------------
# test_err_death.c forks, lets the child run an aborting input, and requires
# WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT of the wait status -- a
# strictly stronger claim than "the process failed", and one that no CTest
# property can express.  Both candidates were tried and both report a
# SIGABRT child as "(Subprocess aborted)" regardless: PASS_REGULAR_EXPRESSION
# despite documenting that the exit code is ignored, and WILL_FAIL TRUE
# despite documenting that it inverts the verdict.
#
# fork(), waitpid() and the wait-status macros are POSIX, so the target is
# registered only where they exist.  On a host without them it is NOT
# REGISTERED AT ALL -- never registered and skipped, never registered and
# allowed to fail.  Configuration still succeeds there and every other target
# runs normally, which is why there is no DISABLED property, no
# SKIP_RETURN_CODE and no exclusion filter anywhere in this file.
#
# err.c is compiled in and -UNDEBUG applied for the same reason as the default
# guards target above: the assertions this file exists to observe must be live
# in the translation unit that holds them, in every build type.
#
# TIMEOUT 30 is the one runner-level property in the suite.  It is a safety
# net, not a budget -- the file completes in milliseconds -- so that a defect
# in the harness degrades into a reported timeout instead of a hung suite.  It
# is not a skip mechanism and it excuses no failure.
if(UNIX)
  libprov_add_test(test_err_death
                   SOURCES test_err_death.c ${PROJECT_SOURCE_DIR}/err.c
                   COPTS -UNDEBUG)
  set_tests_properties(test_err_death PROPERTIES TIMEOUT 30)
endif()

# ---------------------------------------------------------------------------
# The out-of-memory contract (GNU ld hosts)
# ---------------------------------------------------------------------------
# err.c returns NULL when malloc() fails, at err.c:56 in proverr_new_handle()
# and at err.c:71 in proverr_dup_handle().  Neither branch is reachable from
# any input, so without fault injection both are invisible -- and an
# out-of-memory path that is never exercised is exactly where a missing NULL
# check becomes a NULL dereference in production.  -Wl,--wrap=malloc redirects
# the calls to the countdown interposer inside test_err_alloc.c, which fails
# the next N allocations and then delegates to __real_malloc.
#
# -Wl,--wrap=free is here for the mirror-image reason: deallocation is
# otherwise not observable at all.  err.c:82 is a bare free() inside
# proverr_free_handle(), which returns no value, writes no output parameter and
# invokes no callback, so a proverr_free_handle() whose body were deleted
# outright would leave every other assertion in this suite passing.  With free
# wrapped, the released pointer, the call count and the running balance between
# blocks supplied and blocks released all become values test_err_alloc.c
# compares.  calloc and realloc are deliberately NOT wrapped: err.c never calls
# them, so wrapping them would be scope creep with no contract behind it.
#
# Note what this target does NOT do: it does not compile a private copy of
# err.c.  --wrap works at LINK time on undefined references, so the `malloc`
# references already inside libprov's err.c.o are rewritten without err.c
# being recompiled or even aware.  Adding err.c to the source list here would
# be redundant at best.
#
# Neither option can go missing unnoticed, which matters because every
# assertion in that file would turn vacuous if it did: __real_malloc and
# __real_free are names only --wrap creates, so a build without both options
# fails to LINK rather than producing a binary that quietly proves nothing.
#
# --wrap is a GNU ld feature.  Where it is unavailable this target is, again,
# NOT REGISTERED AT ALL rather than skipped or allowed to fail.  APPLE is
# excluded because ld64 has no --wrap.
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang" AND UNIX AND NOT APPLE)
  libprov_add_test(test_err_alloc SOURCES test_err_alloc.c
                   LINKOPTS "-Wl,--wrap=malloc" "-Wl,--wrap=free")
endif()
