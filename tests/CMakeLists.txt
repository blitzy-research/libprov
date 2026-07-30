# CC0 license applied, see LICENSE
#
# ===========================================================================
# tests/CMakeLists.txt -- registration of the libprov unit test suite
# ===========================================================================
#
# The single place where the suite is wired to CTest.  It defines one helper,
# libprov_add_test(), and registers eight executables from seven sources: one
# source is compiled twice, because the pair of contracts it covers cannot be
# exhibited by one set of preprocessor flags.
#
#   test_num_get            provnum_get_size_t() / provnum_get_int()
#   test_num_set            provnum_set_size_t() / provnum_set_int()
#   test_err_handle         dispatch resolution, duplication, free
#   test_err_raise          argument forwarding and the ERR_raise macros
#   test_err_guards         err.c's guards with assertions LIVE
#   test_err_guards_ndebug  the same source, err.c compiled under NDEBUG
#   test_err_death          the aborts really abort (POSIX only)
#   test_err_alloc          the out-of-memory contract (GNU ld --wrap only)
#
# Six are unconditional.  test_err_death and test_err_alloc rest on facilities
# that are not universally available, and where those do not hold the target is
# NOT REGISTERED AT ALL -- never registered and then disabled, never registered
# and allowed to fail.  That is why nothing here uses a DISABLED property, a
# SKIP_RETURN_CODE or an exclusion filter: configuration still succeeds and the
# remaining targets run normally, so the suite degrades in coverage rather than
# in health.  Each gate is written out at the registration it guards, so what a
# target rests on is readable beside the target itself.
#
# The suite must run with no configure-time flag of any kind:
#
#     cmake -B build && cmake --build build && ctest --test-dir build
#
# Nothing here adds a cache variable of its own or a flag a target would not
# otherwise carry, and coverage and sanitizers stay opt-in through
# CMAKE_C_FLAGS.
#
# ---------------------------------------------------------------------------
# DIVISION OF RESPONSIBILITY WITH THE ROOT LISTFILE
# ---------------------------------------------------------------------------
# The root CMakeLists.txt owns whether tests are built and WHERE CTest is
# enabled, through a top-level-aware option(LIBPROV_TESTS ...) followed by
# include(CTest) and add_subdirectory(tests).  Four omissions here follow from
# that: no enable_testing() and no include(CTest), because calling either from a
# subdirectory writes CTestTestfile.cmake here instead of at the build root,
# which is the mistake that hides tests from `ctest --test-dir`; no
# option(LIBPROV_TESTS), because redefining it would shadow the root's computed
# default and break the flagless command; and no cmake_minimum_required() or
# project(), because this is a subdirectory listfile.  An embedding project
# therefore still gets the maintainer's opt-out: LIBPROV_TESTS defaults OFF
# there, so this file is never read and no test target is created.
#
# ---------------------------------------------------------------------------
# VERSION FLOOR AND WHY THE GATES ARE DECLARATIVE
# ---------------------------------------------------------------------------
# The project declares cmake_minimum_required(VERSION 3.18), so nothing here may
# need more: target_link_options (3.13) is the newest feature used and
# PROJECT_IS_TOP_LEVEL (3.21) is avoided, the root computing the same thing from
# CMAKE_SOURCE_DIR.  ctest --output-junit (3.21) is documented in the README as
# an optional invocation, never wired into the build.
#
# The gates are declarative rather than probed because a probe that answers
# wrongly does not fail a test, it silently removes one, and a removed target
# reports nothing.  Both mechanisms fail loudly at BUILD time instead if they
# ever stop reaching their target: test_err_alloc.c references __real_malloc, a
# name only --wrap creates, so the link fails; test_err_guards.c and
# test_err_death.c #error on the wrong NDEBUG state.

# ---------------------------------------------------------------------------
# libprov_add_test(<name> [SOURCES <src>...] [DEFS <def>...]
#                         [COPTS <opt>...]  [LINKOPTS <opt>...])
# ---------------------------------------------------------------------------
# Builds one test executable and registers it with CTest, following the
# maintainer's own per-directory pattern plus the three optional per-target knobs
# the eight registrations need; keeping it in a function stops eight copies of
# that pattern from drifting apart.  All four keywords are multi-value -- SOURCES
# takes two entries for the targets that compile err.c in, DEFS two for the
# NDEBUG variant -- and ${ARGN} excludes <name>.
function(libprov_add_test name)
  cmake_parse_arguments(A "" "" "SOURCES;DEFS;COPTS;LINKOPTS" ${ARGN})

  add_executable(${name} ${A_SOURCES})

  # The CMake TARGET name is libprov, not "prov": that is only the OUTPUT_NAME
  # the root sets, so the archive is libprov.a while the target is libprov, and
  # linking "prov" would look plausible and fail.  Linking libprov also brings
  # its PUBLIC include directory, which is what resolves "prov/err.h".
  target_link_libraries(${name} PRIVATE libprov)

  # MANDATORY on every target, and the likeliest thing to get wrong here: the
  # root declares the OpenSSL include directory PRIVATE on libprov, so -- unlike
  # the PUBLIC include/ directory -- it does NOT propagate through
  # target_link_libraries, and without this line the tests fail to find
  # openssl/core.h.  Where OPENSSL_INCLUDE_DIR happens to be /usr/include the
  # omission is masked by the compiler's default search path, making it a
  # portability bug rather than a build failure -- the worse of the two.
  target_include_directories(${name} PRIVATE ${OPENSSL_INCLUDE_DIR})

  # The sources include their shared fixtures in quoted form, which a compiler
  # resolves relative to the including file.  That is not enough for the targets
  # whose source list also names a file from outside this directory
  # (${PROJECT_SOURCE_DIR}/err.c): naming this directory explicitly makes the
  # lookup independent of the including file's location and of the generator.
  target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})

  # Each optional knob is applied only when supplied.  An unguarded call with
  # an empty list would be a configure error, not a no-op.
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
  # links them, so there is no usage requirement to hand on.  Naming the TARGET
  # as the COMMAND lets CMake substitute wherever it put the executable, which
  # is what makes `ctest --test-dir build` work without this file touching any
  # output-directory property.
  add_test(NAME ${name} COMMAND ${name})
endfunction()

# ---------------------------------------------------------------------------
# The four straightforward targets
# ---------------------------------------------------------------------------
# One source each, the project's default flags, and err.c and num.c reached
# through the libprov archive.  Each target is named after its source's
# basename so that ctest -R test_num_get and ctest -R "test_num_.*" select what
# a reader expects.
libprov_add_test(test_num_get     SOURCES test_num_get.c)
libprov_add_test(test_num_set     SOURCES test_num_set.c)
libprov_add_test(test_err_handle  SOURCES test_err_handle.c)
libprov_add_test(test_err_raise   SOURCES test_err_raise.c)

# ---------------------------------------------------------------------------
# The two build variants of err.c's guard contract
# ---------------------------------------------------------------------------
# proverr_new_handle() has two mutually exclusive contracts, and which one is
# in force is decided by the preprocessor rather than by any input: with
# assertions live an invalid core handle, an invalid dispatch table or a table
# missing any of the three callbacks ABORTS (err.c:26, :27, :47, :48, :49);
# with NDEBUG defined those assertions vanish, the guard at err.c:51-54 becomes
# reachable, and the same inputs return NULL.  No single set of flags exhibits
# both, so the one source is compiled twice and each target asserts the
# contract its own build makes reachable.  Neither half may be dropped.
#
# err.c IS IN THE SOURCE LIST because assert() expands according to the NDEBUG
# state of the translation unit CONTAINING the call.  libprov compiled err.c
# once, with the project's own flags, so a definition on the TEST target cannot
# reach that object and a variant built that way would still abort while
# asserting that it returns NULL.  Recompiling err.c per target puts the guard
# state under the test's control and modifies nothing on disk.  libprov is still
# linked, for num.c and the PUBLIC include directory, and stays unambiguous: a
# definition in an object named on the link line satisfies the reference before
# any archive is searched, so the libprov member is never extracted.
#
# -UNDEBUG is literal because -DCMAKE_BUILD_TYPE=Release adds -DNDEBUG to every
# target, which would turn the default variant into a second NDEBUG variant --
# err.c's assertions gone while the test body still asserted that they fire.
# CMake emits a target's COMPILE_OPTIONS after CMAKE_C_FLAGS and the
# per-configuration flags, so a Release build compiles this target with
# `-O3 -DNDEBUG -UNDEBUG` and the undefine has the last word.
#
# The NDEBUG target carries LIBPROV_TEST_NDEBUG_VARIANT as well because the
# source branches on that marker rather than on NDEBUG: had it branched on
# NDEBUG, a Release build would have flipped the default target's body too,
# asserting graceful NULL returns against an err.c whose undefine kept the
# aborts live.  NDEBUG reconfigures err.c; the marker tells the body which
# contract to assert.  test_err_guards.c requires the two to be defined together
# or not at all and #errors otherwise, which is what stops a target that lost its
# undefine from passing in a default build while silently asserting nothing in a
# Release one.
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
# strictly stronger claim than "the process failed", and one no CTest property
# can express: CTest reports a SIGABRT child as "(Subprocess aborted)" under
# PASS_REGULAR_EXPRESSION and under WILL_FAIL TRUE alike, because their
# documented exit-code handling does not extend to signal terminations.  Do not
# "simplify" this target into either.
#
# if(UNIX) is the gate, because fork(), waitpid() and the wait-status macros are
# POSIX process control and UNIX is CMake's name for a POSIX-like host; where it
# does not hold the target is NOT REGISTERED AT ALL.  The source keeps its own
# #ifndef _WIN32 guard as a second line of defence and treats every optional
# header it can do without as optional, so the gate never has to promise more
# than "POSIX-like".  err.c is compiled in with -UNDEBUG for the same reason as
# the guards target above, and having no NDEBUG variant this source pins the
# simpler contract -- NDEBUG must not be defined at all -- with an #error.
#
# TIMEOUT 30 is the one runner-level property in the suite: a safety net, not a
# budget, so a defect in the harness degrades into a reported timeout instead of
# a hung suite.  It is not a skip mechanism and it excuses no failure.
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
# and at err.c:71 in proverr_dup_handle().  Neither branch is reachable from any
# input, so without fault injection both are invisible -- and an out-of-memory
# path that is never exercised is exactly where a missing NULL check becomes a
# NULL dereference in production.  -Wl,--wrap=malloc redirects those calls to
# the countdown interposer inside test_err_alloc.c, which fails the next N
# allocations and then delegates to __real_malloc.
#
# malloc is the ONLY function wrapped: it is the one allocator entry point err.c
# calls, and free cannot be made to fail, so wrapping anything else would
# interpose on nothing or inject no fault.  Do not add a second --wrap option;
# the cases in tests/test_err_alloc.c are written to this one, and that file
# documents the rest -- including what a suite that cannot observe
# proverr_free_handle() therefore cannot prove.
#
# This target does NOT compile a private copy of err.c: --wrap works at LINK
# time on undefined references, so the `malloc` reference already inside
# libprov's err.c.o is rewritten without err.c being recompiled or even aware.
# A build that lost the option fails to LINK on __real_malloc -- a name only
# --wrap creates -- rather than producing a binary whose every assertion is
# vacuous, which is the backstop behind this declarative gate.
#
# --wrap is a GNU ld extension, so the gate names the toolchains that carry it:
# GCC and Clang both drive a GNU-compatible linker on a non-Apple UNIX host,
# while Apple's ld64 has no --wrap, which is why the platform is excluded rather
# than probed.  The gate is necessary and not sufficient -- a driver repointed at
# a linker without --wrap fails the link, which is the intended failure mode.
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang" AND UNIX AND NOT APPLE)
  libprov_add_test(test_err_alloc SOURCES test_err_alloc.c
                   LINKOPTS "-Wl,--wrap=malloc")
endif()
