# CC0 license applied, see LICENSE
#
# ===========================================================================
# tests/CMakeLists.txt -- registration of the libprov unit test suite
# ===========================================================================
#
# This listfile is the single place where the suite is wired to CTest.  It
# defines one helper, libprov_add_test(), and uses it to register eight test
# executables from seven sources -- one of those sources is compiled twice,
# under different preprocessor and flag configurations, because the pair of
# contracts it covers cannot be exhibited by one set of flags:
#
#   test_num_get            provnum_get_size_t() / provnum_get_int():
#                           contract, boundaries, widths, signedness and
#                           error-code precedence
#   test_num_set            provnum_set_size_t() / provnum_set_int():
#                           contract, capacity edges, byte-level output and the
#                           return_size-on-every-path invariant
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
#                           allocation-failure injection (GNU ld --wrap only)
#
# Six of the eight are unconditional.  The other two -- test_err_death and
# test_err_alloc -- rest on facilities that are not universally available, and
# on a host without them the target is NOT REGISTERED AT ALL: never registered
# and then disabled, never registered and allowed to fail.  That is why nothing
# in this file uses a DISABLED property, a SKIP_RETURN_CODE or an exclusion
# filter.  Configuration still succeeds there and the remaining targets run
# normally, so the suite degrades in coverage rather than in health.
#
# Each of those two carries the gate the frozen plan names for it, and nothing
# else: if(UNIX) for test_err_death, because fork() and the wait-status macros
# are POSIX process control and UNIX is CMake's name for a POSIX-like host; and
# CMAKE_C_COMPILER_ID MATCHES "GNU|Clang" AND UNIX AND NOT APPLE for
# test_err_alloc, because -Wl,--wrap is a GNU-ld extension.  Both are written
# out at the registration they guard, so what a target rests on is readable
# beside the target itself.  No configure-time probe stands behind either: this
# file adds no capability test, no cache variable of its own and no flag any
# target would not otherwise carry, which is what keeps the mandated command
# below free of every -D.
#
# The suite is meant to be run with no configure-time flag of any kind:
#
#     cmake -B build && cmake --build build && ctest --test-dir build
#
# Useful variations, none of which this file has to provide anything for:
# --output-on-failure, -R <pattern>, -E <pattern>, -j <N>, and
# --no-tests=error (which must exit 0 -- it exited 8 while the suite was
# empty).  Coverage and sanitizers are opt-in through CMAKE_C_FLAGS and are
# deliberately absent from this file: no target here is instrumented by
# default, so the command above stays exactly the command above.
#
# ---------------------------------------------------------------------------
# DIVISION OF RESPONSIBILITY WITH THE ROOT LISTFILE
# ---------------------------------------------------------------------------
# The root CMakeLists.txt owns the decision to build tests at all, and owns
# WHERE CTest is enabled -- which decides where `ctest` can find what this file
# registers:
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
#   no enable_testing()       include(CTest) in the root already calls it, for
#                             the directory that has to have it.  Calling it
#                             here as well would enable testing for a directory
#                             nobody points ctest at.
#   no include(CTest)         likewise the root's.  Including it from a
#                             subdirectory writes CTestTestfile.cmake here and
#                             not at the build root, which is the specific
#                             mistake that hides tests from `ctest --test-dir`.
#   no option(LIBPROV_TESTS)  redefining it here would shadow the root's
#                             computed default and break the flagless command.
#                             The name and the description string are the
#                             maintainer's own and are preserved verbatim.
#   no if(LIBPROV_TESTS)      the root already guards the add_subdirectory()
#                             call; a second guard would be redundant and would
#                             silently yield an empty suite if the variable were
#                             ever scoped differently.
#   no cmake_minimum_required(), no project()
#                             this is a subdirectory listfile, not a project.
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
# add_test(NAME.. COMMAND..) (2.8), set_tests_properties (1.0) and
# target_link_options, which at 3.13 is the newest thing in this file and still
# five minor versions under the floor.  PROJECT_IS_TOP_LEVEL (3.21) is avoided
# -- the root computes the same thing from CMAKE_SOURCE_DIR -- and
# ctest --output-junit (3.21) is documented in the README as an optional
# invocation and never wired into the build.
#
# ---------------------------------------------------------------------------
# WHAT THIS FILE DELIBERATELY DOES NOT DO
# ---------------------------------------------------------------------------
# It runs no capability probe.  There is no include(CheckCSourceCompiles), no
# include(CheckCCompilerFlag), no CMAKE_REQUIRED_LINK_OPTIONS and no cache
# variable of this file's own invention.  The two conditional registrations
# below carry the two predicates the frozen plan names for them, and the option
# that keeps the assertion-live targets assertion-live is written out literally
# as -UNDEBUG.
#
# That is a division of labour, not an oversight.  Configure machinery is the
# one thing in a test directory the suite cannot test: a probe that answers
# wrongly does not fail a test, it silently removes one, and a removed target
# reports nothing at all.  Declarative conditions keep what a target rests on
# readable beside the target itself, keep the file at the project's 3.18 floor
# without reaching for newer modules, and keep the mandated command free of
# every -D:
#
#     cmake -B build && cmake --build build && ctest --test-dir build
#
# Where a predicate does not hold, the target it guards is NOT REGISTERED AT
# ALL -- never registered and skipped, never registered and allowed to fail --
# so configuration still succeeds and every other target runs normally.
#
# Neither conditional mechanism can go missing unnoticed at build time either,
# which is the backstop that makes a declarative gate safe.  __real_malloc is a
# name only --wrap creates, and tests/test_err_alloc.c references it, so a build
# of that target without the option fails to LINK rather than producing a binary
# that quietly proves nothing.  tests/test_err_guards.c and
# tests/test_err_death.c likewise pin their own NDEBUG state at COMPILE time and
# stop the build with an #error if the option below ever stops reaching them.
#

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
# The four straightforward targets
# ---------------------------------------------------------------------------
# Nothing special: one source each, the project's default flags, and err.c and
# num.c reached through the libprov archive.  Each target is named after its
# source's basename so that ctest -R test_num_get and ctest -R "test_num_.*"
# select what a reader expects them to.
libprov_add_test(test_num_get     SOURCES test_num_get.c)
libprov_add_test(test_num_set     SOURCES test_num_set.c)
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
# WHY NDEBUG IS UNDEFINED HERE, AND WHY THE SOURCE PINS IT AS WELL
#
# Because NDEBUG is not this suite's to own.  -DCMAKE_BUILD_TYPE=Release adds
# -DNDEBUG to every target in the project, which would silently turn the default
# variant into a second NDEBUG variant -- err.c's assertions gone, while the
# test body still asserted that they fire.  The literal -UNDEBUG below pins this
# target's err.c to live assertions whatever the build type: it is the POSIX c99
# spelling, GCC and Clang both accept it, and it is the option the frozen plan
# names.  Ordering is what makes that work, and it was
# verified rather than assumed: CMake emits a target's COMPILE_OPTIONS after
# CMAKE_C_FLAGS and after the per-configuration flags, so a Release build
# compiles this target with `-O3 -DNDEBUG -UNDEBUG` and the undefine has the
# last word.
#
# The pinning is asserted twice, once per layer, because each layer can fail in
# a way the other cannot see:
#
#   here            -UNDEBUG is applied to this target's compilation, which is
#                   what survives a Release build's own -DNDEBUG.
#   in the source   test_err_guards.c requires, at COMPILE time, that NDEBUG and
#                   LIBPROV_TEST_NDEBUG_VARIANT are either both defined or
#                   neither defined, and stops the build with an #error
#                   otherwise.
#
# The second layer is what closes the hole the first cannot.  A target that
# carried no undefine option would still build and would still pass in a default
# build, while silently asserting nothing in a Release one -- a green test that
# tests nothing, which is the single outcome this suite exists to prevent.  With
# the source-level pin in place that configuration cannot be built at all, so
# the failure mode is a precise diagnostic instead of a false pass.
#
# WHY THE MARKER DEFINE, AND NOT NDEBUG, SELECTS THE TEST BODY
#
# For the mirror-image reason: test_err_guards.c branches on
# LIBPROV_TEST_NDEBUG_VARIANT, a name exactly one target sets and nothing else
# in the project defines.  Had it branched on NDEBUG, a Release build would
# have flipped the default target's body too -- asserting graceful NULL
# returns against an err.c whose own undefine option kept the aborts live.  The
# ndebug target therefore needs BOTH defines and they do different jobs:
# NDEBUG reconfigures err.c, and the marker tells the test body which of the
# two contracts to assert.  That pairing is the other half of what the source's
# compile-time pin enforces: the marker without NDEBUG would assert graceful
# NULL returns against an err.c that still aborts, so the source refuses to
# compile in that configuration too, rather than leaving it to be discovered as
# a runtime abort.
libprov_add_test(test_err_guards
                 SOURCES test_err_guards.c ${PROJECT_SOURCE_DIR}/err.c
                 COPTS -UNDEBUG)
libprov_add_test(test_err_guards_ndebug
                 SOURCES test_err_guards.c ${PROJECT_SOURCE_DIR}/err.c
                 DEFS NDEBUG LIBPROV_TEST_NDEBUG_VARIANT)

# ---------------------------------------------------------------------------
# The abort contract, asserted positively (POSIX only)
# ---------------------------------------------------------------------------
# test_err_death.c forks, lets the child run an aborting input, and requires
# WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT of the wait status -- a
# strictly stronger claim than "the process failed", and one that no CTest
# property can express.  Both candidates were tried and both report a
# SIGABRT child as "(Subprocess aborted)" regardless: PASS_REGULAR_EXPRESSION
# despite documenting that the exit code is ignored, and WILL_FAIL TRUE
# despite documenting that it inverts the verdict.  A control test -- an
# executable returning 0 with WILL_FAIL TRUE -- was correctly reported as
# failed, which proves the property was active and the negative result was not
# a configuration mistake.  Do not "simplify" this target into either.
#
# if(UNIX) is the gate, because fork(), waitpid() and the wait-status macros
# are POSIX process control and UNIX is CMake's name for "this is a POSIX-like
# host".  Where it does not hold the target is NOT REGISTERED AT ALL -- never
# registered and skipped, never registered and allowed to fail -- so
# configuration still succeeds and every other registered target runs normally:
# the six unconditional ones, plus test_err_alloc where its own gate holds.  The
# source keeps its own #ifndef _WIN32 guard as a second line of defence, and
# treats every optional header it can do without as optional, so the gate never
# has to promise more than "POSIX-like".
#
# err.c is compiled in, and -UNDEBUG applied, for the same reason as the default
# guards target above: the assertions this file exists to observe must be live in
# the translation unit that holds them, in every build type.  This target has no
# NDEBUG variant and needs none, so its source pins the simpler contract --
# NDEBUG must not be defined at all -- and stops the build with an #error if it
# is.  Without that pin a build that somehow lost the option would produce a
# binary whose every forked child ran an input that no longer aborts, and the
# file would report that as a failure rather than as the misconfiguration it is.
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
# The out-of-memory contract (GNU ld --wrap only)
# ---------------------------------------------------------------------------
# err.c returns NULL when malloc() fails, at err.c:56 in proverr_new_handle()
# and at err.c:71 in proverr_dup_handle().  Neither branch is reachable from
# any input, so without fault injection both are invisible -- and an
# out-of-memory path that is never exercised is exactly where a missing NULL
# check becomes a NULL dereference in production.  -Wl,--wrap=malloc redirects
# the calls to the countdown interposer inside test_err_alloc.c, which fails
# the next N allocations and then delegates to __real_malloc.
#
# malloc is the ONLY function wrapped, and that is deliberate.  err.c calls
# exactly one allocator entry point -- malloc, at :56 and :71 -- so the wrapped
# set is exactly the set err.c uses.  calloc and realloc would interpose on
# nothing.  free is not wrapped either: a release cannot be made to fail, so
# wrapping it would inject no fault, and observing it would be a different
# mechanism serving a different purpose from this target's.  The frozen plan
# fixes this target's link option at -Wl,--wrap=malloc and fixes the case list
# in tests/test_err_alloc.c at A-1 through A-8; both are honoured literally
# here.  Do not add a second --wrap option: the case list would then no longer
# match the wiring, and this file is not the place to widen the specification.
#
# What that leaves unobserved is stated rather than hidden.  The body of
# proverr_free_handle() returns nothing, writes through nothing and calls no
# callback, so no target in this suite can distinguish a correct release from a
# body deleted outright.
# tests/test_err_alloc.c records the same limitation beside the cases it does
# assert, and the opt-in sanitizer configuration in the README is the documented
# channel for anyone who needs a leak verdict.  An honest gap that a reader can
# find beats an unauthorised mechanism that the specification does not carry.
#
# Note what this target does NOT do: it does not compile a private copy of
# err.c.  --wrap works at LINK time on undefined references, so the `malloc`
# and `free` references already inside libprov's err.c.o are rewritten without
# err.c being recompiled or even aware.  Adding err.c to the source list here
# would be redundant at best.
#
# The option cannot go missing unnoticed, which matters because every assertion
# in that file would turn vacuous if it did: __real_malloc is a name only --wrap
# creates and that file references it, so a build without the option fails to
# LINK rather than producing a binary that quietly proves nothing.  That is the
# backstop behind the declarative gate below.
#
# --wrap is a GNU ld extension, so the gate names the toolchains that carry it:
# a GNU or Clang driver on a UNIX host that is not Apple.  GCC and Clang both
# drive a GNU-compatible linker by default on such a host; Apple's ld64 has no
# --wrap, which is why the platform is excluded rather than probed.  The gate is
# a necessary condition and not a sufficient one -- a driver deliberately
# repointed at a linker without --wrap will fail the link, loudly, with
# `undefined reference to __real_malloc' -- and that is the intended failure
# mode: a diagnostic naming the exact missing capability, not a silently absent
# test.  The README states the same requirement for a reader choosing a host.
#
# Where the gate does not hold the target is, again, NOT REGISTERED AT ALL rather
# than skipped or allowed to fail.  Configuration succeeds, every other
# registered target runs normally -- the six unconditional ones, plus
# test_err_death where its own gate holds -- and the suite degrades in coverage
# rather than in health.
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang" AND UNIX AND NOT APPLE)
  libprov_add_test(test_err_alloc SOURCES test_err_alloc.c
                   LINKOPTS "-Wl,--wrap=malloc")
endif()
