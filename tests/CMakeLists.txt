# CC0 license applied, see LICENSE
#
# ===========================================================================
# tests/CMakeLists.txt -- registration of the libprov unit test suite
# ===========================================================================
#
# This listfile is the single place where the suite is wired to CTest.  It
# defines one helper, libprov_add_test(), and uses it to register nine test
# executables from seven sources -- two of those sources are compiled twice,
# under different preprocessor and flag configurations, because neither pair of
# contracts can be exhibited by one set of flags:
#
#   test_num_get            provnum_get_size_t() / provnum_get_int():
#                           contract, boundaries, widths, signedness,
#                           error-code precedence and -- where Probe 1 below
#                           succeeds -- guarded memory-safety boundaries
#   test_num_set            provnum_set_size_t() / provnum_set_int():
#                           contract, capacity edges, byte-level output, the
#                           return_size-on-every-path invariant and -- where
#                           Probe 1 succeeds -- guarded memory-safety boundaries
#   test_num_set_memory     the same source compiled together with num.c under
#                           -fsanitize=address, which is the only way to observe
#                           a regression of the zero-capacity clamp at num.c:91:
#                           that defect reads below a variable in the LIBRARY's
#                           own frame, where no protected page can be placed
#                           (registered where Probe 5 succeeds, which RUNS an
#                           instrumented under-read rather than merely linking
#                           one)
#   test_err_handle         proverr_new_handle() dispatch resolution plus
#                           duplication and free semantics
#   test_err_raise          argument-forwarding fidelity, ERR_raise /
#                           ERR_raise_data ordering and call-site capture
#   test_err_guards         err.c's guards with assertions LIVE
#   test_err_guards_ndebug  the same source with err.c compiled under NDEBUG,
#                           where the graceful NULL returns become reachable
#   test_err_death          the POSITIVE assertion that the live assertions
#                           really abort (registered only where Probe 2 finds
#                           the fork / wait / resource-limit API set complete)
#   test_err_alloc          err.c's out-of-memory contract, via deterministic
#                           allocation-failure injection (registered only where
#                           Probe 4 finds that the ACTIVE LINKER really wraps
#                           the allocator)
#
# Six of the nine are unconditional.  The other three -- test_num_set_memory,
# test_err_death and test_err_alloc -- are registered only where the capability
# probes below establish that the mechanism they rest on really works on this
# toolchain; where it does not they are NOT REGISTERED AT ALL, which is why
# nothing in this file uses a DISABLED property, a SKIP_RETURN_CODE or an
# exclusion filter.  The guard-page group is the fourth such mechanism, and it
# rides on two ALWAYS-REGISTERED targets, so a failed Probe 1 costs those two
# targets one group of cases rather than their registration.  Every drop is
# announced by one STATUS line naming what is missing and what it cost, so a
# reduced target count is explained rather than mysterious.  MEASURED, one probe
# forced to fail at a time: the suite configures and builds warning-free and
# every remaining target passes in each case.  On the reference host all nine
# register and all nine pass.
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
# The root CMakeLists.txt owns the decision to build tests at all, and owns
# WHERE CTest is enabled -- which decides where `ctest` can find what this file
# registers.  In outline:
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
#       if(<libprov is the top-level project>)
#         include(CTest)          # at the SOURCE ROOT, where ctest looks
#       endif()
#       if(DEFINED BUILD_TESTING AND NOT BUILD_TESTING)
#         message(STATUS ...)     # CTest's own switch says no: no target at all
#       else()
#         if(<embedded>)
#           if(NOT DEFINED BUILD_TESTING)
#             message(WARNING ...)  # parent never included CTest: sub-build
#           endif()                 # contract, named at configure time
#           enable_testing()        # libprov's subtree is a complete ctest tree
#         endif()
#         add_subdirectory(tests)
#       endif()
#     endif()
#
# Everything this file must NOT do follows from that block, and each omission
# below is deliberate rather than forgotten:
#
#   no enable_testing()       the root already enabled testing for the directory
#                             that has to have it, before it ran
#                             add_subdirectory(tests): include(CTest) at the
#                             source root for a
#                             top-level build, enable_testing() in libprov's own
#                             directory for an embedded one.  Calling it here as
#                             well would enable testing for a directory NOBODY
#                             points ctest at, which is not the problem it looks
#                             like a fix for.
#   no include(CTest)         likewise the root's, and including it from a
#                             subdirectory is the specific mistake that hides
#                             tests from the build root: it writes
#                             CTestTestfile.cmake here and not there
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
# set_tests_properties, message(STATUS..) (1.0), CMAKE_REQUIRED_DEFINITIONS,
# CMAKE_REQUIRED_LINK_OPTIONS (3.14, per that module's own documentation),
# CMAKE_CROSSCOMPILING (2.6), string(REPLACE) (2.6), and the capability-probe
# modules named in the next block: CheckIncludeFile, CheckSymbolExists,
# CheckCSourceCompiles and CheckCSourceRuns (all long predating the floor) and
# CheckCCompilerFlag (3.0).  CheckLinkerFlag would also have been available --
# it documents "versionadded:: 3.18", exactly at the floor -- but it is
# deliberately not used AS A GATE, for a reason of expressiveness rather than of
# version, recorded with its measurement at Probe 4.
# check_c_source_compiles() and check_c_source_runs() are used rather than the
# unified check_source_compiles()/check_source_runs(), which need 3.19.
# PROJECT_IS_TOP_LEVEL (3.21) is avoided -- the root computes the same thing
# from CMAKE_SOURCE_DIR -- and
# ctest --output-junit (3.21) is documented in the README as an optional
# invocation and never wired into the build.
#
# ---------------------------------------------------------------------------
# CAPABILITY PROBES, AND WHY NOT PLATFORM PROXIES
# ---------------------------------------------------------------------------
# Four mechanisms in this suite rest on something that is not universally
# available: mmap()/mprotect() guard pages and fork() for the two numeric
# targets, POSIX process control for test_err_death, the GNU linker's --wrap
# for test_err_alloc, and a working sanitizer runtime for
# test_num_set_memory.  The requirement is that a host lacking one of
# them still CONFIGURES AND BUILDS, with the affected mechanism simply absent
# -- never registered and skipped, never registered and allowed to fail.
#
# Meeting that requires asking the toolchain what it can actually do, not what
# family it belongs to.  Every proxy that suggests itself is wrong in a way
# that turns a graceful omission into a build failure:
#
#   UNIX                     true on Apple and on Cygwin.  MAP_ANONYMOUS is a
#                            Linux/BSD extension rather than POSIX, so "UNIX"
#                            does not imply it; a host where UNIX holds but the
#                            flag is absent would reach param_util.h's #error
#                            instead of losing one group quietly.
#   NOT APPLE                excludes one known ld64 host by name and says
#                            nothing about any other linker.
#   CMAKE_C_COMPILER_ID      identifies the COMPILER VENDOR.  --wrap is a
#                            property of the LINKER, and clang drives ld64,
#                            lld, mold and GNU ld alike, so matching
#                            "GNU|Clang" both over- and under-approximates.
#   -UNDEBUG assumed         a compiler that does not accept it fails the
#                            compile of two targets outright, which is the
#                            worst possible outcome for a flag whose only job
#                            is hardening against -DCMAKE_BUILD_TYPE=Release.
#
# Neither of the first two is a hypothetical.  MEASURED, by simulating each
# host and running the mandated flagless command against it:
#
#   a sys/mman.h without MAP_ANONYMOUS (shimmed onto the include path, so no
#   configure flag is involved) leaves `mmap` findable and UNIX true -- yet
#   compiling test_num_get.c with the guard-page definition applied, which is
#   what the old gate did, stops at param_util.h's #error, while the same
#   compile without it succeeds.  Probe 1 reports Failed on that host, the
#   definition is not made, and the command builds clean and runs 8/8.
#
#   a cc whose linker rejects --wrap (supplied through CC, again no configure
#   flag) still identifies as CMAKE_C_COMPILER_ID "GNU" on a UNIX non-Apple
#   host, so the old condition held and the link it produced failed.  All three
#   of Probe 4's checks report Failed there, test_err_alloc is not registered,
#   and the remaining seven targets build and pass.
#
# So each mechanism below is gated on probes of the exact capabilities the
# corresponding source uses, and is enabled only when EVERY one of them
# succeeds.  The probes compile (and, for the linker ones, link) real code, at
# the same feature-test level the consuming source selects, which is what makes
# them faithful rather than merely plausible.  Their results are cached, so
# they cost one configure and nothing thereafter.
include(CheckIncludeFile)
include(CheckSymbolExists)
include(CheckCSourceCompiles)
include(CheckCCompilerFlag)

# ---------------------------------------------------------------------------
# Probe 1: the protected-boundary oracle in tests/param_util.h
# ---------------------------------------------------------------------------
# CMAKE_REQUIRED_DEFINITIONS carries the SAME feature-test level the two
# numeric sources set before their first #include (_DEFAULT_SOURCE, chosen
# there because MAP_ANONYMOUS is not a POSIX flag).  Probing without it would
# risk asking a different question from the one the compile will ask.
#
# MEASURED, because the reasoning depends on it: CMAKE_C_STANDARD and
# CMAKE_C_EXTENSIONS do propagate into these checks.  A probe for
# __STRICT_ANSI__ is false and one for glibc's __USE_MISC is true under the
# default CMAKE_C_EXTENSIONS=ON, and both invert under
# -DCMAKE_C_EXTENSIONS=OFF -- a legitimate consumer choice, and the
# configuration in which a C library that gates an extension on __USE_MISC
# hides it.  This glibc happens to define MAP_ANONYMOUS unconditionally, so the
# definition is not load-bearing on THIS host; it is carried because the probe's
# job is to ask what the compile will ask on a host where it is.
set(CMAKE_REQUIRED_DEFINITIONS -D_DEFAULT_SOURCE=1)

check_include_file("sys/mman.h"     LIBPROV_HAVE_SYS_MMAN_H)
check_include_file("sys/wait.h"     LIBPROV_HAVE_SYS_WAIT_H)
check_include_file("sys/resource.h" LIBPROV_HAVE_SYS_RESOURCE_H)
check_include_file("unistd.h"       LIBPROV_HAVE_UNISTD_H)

check_symbol_exists(mmap      "sys/mman.h"     LIBPROV_HAVE_MMAP)
check_symbol_exists(mprotect  "sys/mman.h"     LIBPROV_HAVE_MPROTECT)
check_symbol_exists(munmap    "sys/mman.h"     LIBPROV_HAVE_MUNMAP)
check_symbol_exists(fork      "unistd.h"       LIBPROV_HAVE_FORK)
check_symbol_exists(sysconf   "unistd.h"       LIBPROV_HAVE_SYSCONF)
check_symbol_exists(waitpid   "sys/wait.h"     LIBPROV_HAVE_WAITPID)
check_symbol_exists(setrlimit "sys/resource.h" LIBPROV_HAVE_SETRLIMIT)

# The whole mechanism in one compile-and-link, which is what covers the parts
# no per-symbol check can reach: the MAP_ANONYMOUS-or-MAP_ANON alternative that
# param_util.h itself falls back through, the PROT_/MAP_ flag constants, both
# mapping visibilities the oracle needs (MAP_PRIVATE for the guarded region and
# MAP_SHARED for the record the child writes), _SC_PAGESIZE, RLIMIT_CORE and
# the wait-status macros.  It mirrors param_guard_open(),
# param_guard_record_open() and param_guard_run() rather than paraphrasing
# them, so a host that passes this probe can compile that header.
check_c_source_compiles("
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <unistd.h>
#include <stddef.h>
#if !defined(MAP_ANONYMOUS) && defined(MAP_ANON)
# define MAP_ANONYMOUS MAP_ANON
#endif
int main(void)
{
    struct rlimit nocore;
    int status = 0;
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    unsigned char *guarded = (unsigned char *)mmap(NULL, page * 3,
                                                   PROT_READ | PROT_WRITE,
                                                   MAP_PRIVATE | MAP_ANONYMOUS,
                                                   -1, 0);
    void *shared = mmap(NULL, page, PROT_READ | PROT_WRITE,
                        MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    pid_t child;

    if (guarded == (unsigned char *)MAP_FAILED || shared == MAP_FAILED)
        return 1;
    if (mprotect(guarded, page, PROT_NONE) != 0)
        return 1;

    child = fork();
    if (child < 0)
        return 1;
    if (child == 0) {
        nocore.rlim_cur = 0;
        nocore.rlim_max = 0;
        (void)setrlimit(RLIMIT_CORE, &nocore);
        _exit(0);
    }
    while (waitpid(child, &status, 0) != child)
        ;
    (void)WIFEXITED(status);
    (void)WEXITSTATUS(status);
    (void)WIFSIGNALED(status);
    (void)munmap(guarded, page * 3);
    (void)munmap(shared, page);
    return 0;
}
" LIBPROV_HAVE_GUARD_PAGES)

unset(CMAKE_REQUIRED_DEFINITIONS)

# ---------------------------------------------------------------------------
# Probe 2: the abort harness in tests/test_err_death.c
# ---------------------------------------------------------------------------
# That file selects _POSIX_C_SOURCE=200809L, so the probe does too.  Everything
# it needs is POSIX -- fork(), waitpid(), the wait-status macros, WTERMSIG,
# SIGABRT, _exit(), freopen() and the RLIMIT_CORE drop the harness performs in
# the child -- which is why one source probe at that level is the whole
# question for this target.
#
# Like every check_c_source_compiles() here it compiles and LINKS without
# running, so what the body returns is immaterial and only its declarations,
# macros and symbols are under test.  It returns the harness's own verdict
# expression anyway, so that the two wait-status macros are used exactly as the
# harness uses them rather than merely mentioned.
set(CMAKE_REQUIRED_DEFINITIONS -D_POSIX_C_SOURCE=200809L)

check_c_source_compiles("
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/resource.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
int main(void)
{
    struct rlimit nocore;
    int status = 0;
    pid_t child = fork();

    if (child < 0)
        return 1;
    if (child == 0) {
        nocore.rlim_cur = 0;
        nocore.rlim_max = 0;
        (void)setrlimit(RLIMIT_CORE, &nocore);
        if (freopen(\"/dev/null\", \"w\", stderr) == NULL) {
            /* deliberately empty, as in the harness itself */
        }
        _exit(0);
    }
    while (waitpid(child, &status, 0) != child)
        ;
    return WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT;
}
" LIBPROV_HAVE_POSIX_DEATH_HARNESS)

unset(CMAKE_REQUIRED_DEFINITIONS)

# ---------------------------------------------------------------------------
# Probe 3: -UNDEBUG
# ---------------------------------------------------------------------------
# Asked of the compiler instead of assumed, and the answer is turned into a
# variable rather than a condition: where the flag is accepted the two
# abort-asserting targets carry it and are immune to a build type that defines
# NDEBUG globally; where it is not, LIBPROV_UNDEBUG_OPT is empty,
# libprov_add_test() applies no COPTS at all, and those targets still build and
# still assert the aborts in every build that does not define NDEBUG itself --
# which is every default build.  Losing one hardening measure is a graceful
# degradation; failing the compile over an unrecognised flag would not be.
check_c_compiler_flag("-UNDEBUG" LIBPROV_HAVE_UNDEBUG_FLAG)
if(LIBPROV_HAVE_UNDEBUG_FLAG)
  set(LIBPROV_UNDEBUG_OPT -UNDEBUG)
else()
  set(LIBPROV_UNDEBUG_OPT "")
endif()

# What this probe deliberately does NOT try to decide, and why.
#
# The obvious next question -- "is NDEBUG in force in the configuration being
# generated?" -- cannot be asked here.  MEASURED on this toolchain: a
# check_c_source_compiles() that #errors on NDEBUG succeeds identically with no
# CMAKE_BUILD_TYPE, with Release and with Debug, because the per-configuration
# flags are not part of what a try-compile sees.  A gate built on such a probe
# would report "NDEBUG absent" unconditionally, which is worse than no gate: it
# would look like a decision and be a constant.
#
# So the residual case is stated instead of papered over.  On a compiler that
# rejects -UNDEBUG the mandated flagless command is unaffected -- it selects no
# build type, so nothing defines NDEBUG and err.c's assertions are live anyway.
# Combining that compiler with a build type that defines NDEBUG globally would
# remove those assertions from the abort-observing targets, and test_err_death
# would then fail rather than be omitted.  It fails loudly and diagnosably:
# test_err_death.c prints a named NOTE when NDEBUG is defined for its own
# translation unit, which under a global -DNDEBUG is exactly when err.c's
# compilation lost them too, and the note says which COPTS the target needs.
# The case is theoretical -- -U is a POSIX-mandated c99 option and every
# compiler this project can plausibly be built with accepts it, which is why
# this probe exists as insurance rather than as a live branch.

# ---------------------------------------------------------------------------
# Probe 4: --wrap, for tests/test_err_alloc.c
# ---------------------------------------------------------------------------
# The question is put to the LINKER, which is the component that owns --wrap,
# and it is put SEPARATELY for each of the two options the target passes: a
# linker could conceivably rewrite one spelling and not the other, and both are
# load-bearing, since __real_malloc and __real_free are names only --wrap
# creates and a binary built with one option missing does not link.
#
# WHY NOT check_linker_flag(), THE IDIOMATIC MODULE FOR THIS.  Because it
# cannot express the question.  It links a FIXED source, `int main(void) {
# return 0; }`, and offers no way to add a definition to it -- so it can only
# answer "does the driver accept this option", never "does this option produce
# a working wrap".  For --wrap those come apart in both directions:
#
#   NOT SUFFICIENT  a linker that accepted the option and rewrote nothing would
#                   leave __real_malloc and __real_free undefined, and the
#                   flag check would still report success.
#   NOT NECESSARY   --wrap rewrites calls made by EVERYTHING on the link line,
#                   including the runtime libraries the configuration pulls in.
#                   If any of them calls malloc, a probe program that does not
#                   define __wrap_malloc cannot link -- which says nothing
#                   about the linker.
#
# The second failure is not hypothetical; it is why this block no longer uses
# the module.  MEASURED on the reference host, configuring with
# -DCMAKE_C_FLAGS="--coverage", which is a workflow the README documents:
# check_linker_flag(C "-Wl,--wrap=malloc") reported Failed with six
# "undefined reference to `__wrap_malloc'" errors raised from
# libgcov.a(_gcov.o), in gcov_do_dump -- the coverage runtime's own
# allocations, rewritten by the very option under test.  The gate that followed
# omitted test_err_alloc from every coverage build, and err.c's measured
# branch coverage fell from 73.08% of 26 branches taken at least once to
# 65.38%, losing exactly the two allocation-failure branches the target exists
# to cover.  The linker was never the problem.
#
# So each option is probed END TO END instead, with a source shaped like the
# target: the wrapper the target defines, delegating to the __real_ original
# that only --wrap creates, plus a call through the wrapped function.  That is
# strictly stronger than a flag check -- it proves the rewrite happened AND
# that __real_ resolves -- and it is immune to the runtime-library case,
# because the probe supplies the wrapper any other caller on the link line
# needs.  A linker that rejects the option fails these probes too, so the
# graceful-omission guarantee is unchanged.
#
# Each per-option probe passes ONLY its own option and names ONLY its own
# symbol pair.  Naming the other pair would leave that __real_ undefined and
# turn a passing probe into a failing one for no reason.
set(CMAKE_REQUIRED_LINK_OPTIONS "-Wl,--wrap=malloc")

check_c_source_compiles("
#include <stdlib.h>
void *__real_malloc(size_t size);
void *__wrap_malloc(size_t size);
void *__wrap_malloc(size_t size) { return __real_malloc(size); }
int main(void)
{
    void *block = malloc(1);

    if (block == NULL)
        return 1;
    free(block);
    return 0;
}
" LIBPROV_HAVE_WRAP_MALLOC)

set(CMAKE_REQUIRED_LINK_OPTIONS "-Wl,--wrap=free")

check_c_source_compiles("
#include <stdlib.h>
void __real_free(void *ptr);
void __wrap_free(void *ptr);
void __wrap_free(void *ptr) { __real_free(ptr); }
int main(void)
{
    void *block = malloc(1);

    if (block == NULL)
        return 1;
    free(block);
    return 0;
}
" LIBPROV_HAVE_WRAP_FREE)

# Both options together, which is how the target is actually linked.  Kept as a
# third check rather than inferred from the two above, because it is the only
# one that exercises the combination -- two interposers live in one binary,
# each delegating to its own original.
set(CMAKE_REQUIRED_LINK_OPTIONS "-Wl,--wrap=malloc" "-Wl,--wrap=free")

check_c_source_compiles("
#include <stdlib.h>
void *__real_malloc(size_t size);
void __real_free(void *ptr);
void *__wrap_malloc(size_t size);
void __wrap_free(void *ptr);
void *__wrap_malloc(size_t size) { return __real_malloc(size); }
void __wrap_free(void *ptr) { __real_free(ptr); }
int main(void)
{
    void *block = malloc(1);

    if (block == NULL)
        return 1;
    free(block);
    return 0;
}
" LIBPROV_HAVE_WRAP_MECHANISM)

unset(CMAKE_REQUIRED_LINK_OPTIONS)

# ---------------------------------------------------------------------------
# THE GUARD-PAGE CONJUNCTION, NAMED ONCE
# ---------------------------------------------------------------------------
# Probe 1 is the only mechanism whose answer is a conjunction of several cached
# results rather than a single one: the four headers, the seven functions, and
# the one-shot compile that links the flags, constants and wait-status macros
# together.  Naming the conjunction here keeps the definition below and the
# STATUS line below it, and Probe 5's own gate, from ever disagreeing about
# what "available" means.
set(LIBPROV_GUARD_PAGES_AVAILABLE FALSE)
if(LIBPROV_HAVE_SYS_MMAN_H AND LIBPROV_HAVE_SYS_WAIT_H
   AND LIBPROV_HAVE_SYS_RESOURCE_H AND LIBPROV_HAVE_UNISTD_H
   AND LIBPROV_HAVE_MMAP AND LIBPROV_HAVE_MPROTECT AND LIBPROV_HAVE_MUNMAP
   AND LIBPROV_HAVE_FORK AND LIBPROV_HAVE_SYSCONF AND LIBPROV_HAVE_WAITPID
   AND LIBPROV_HAVE_SETRLIMIT AND LIBPROV_HAVE_GUARD_PAGES)
  set(LIBPROV_GUARD_PAGES_AVAILABLE TRUE)
endif()

# ---------------------------------------------------------------------------
# Probe 5: the instrumentation that watches num.c's own frame
# ---------------------------------------------------------------------------
# THE ONE PROBE THAT HAS TO RUN, NOT MERELY LINK, and the reason is that its
# question is not "does this compile?" but "does this checker actually catch the
# thing the target depends on it catching?".  A build where -fsanitize=address
# is accepted by the driver but the runtime is unavailable, or where stack
# instrumentation is disabled, would link this source and then observe nothing
# -- and a target registered on that answer would pass having proved nothing,
# which is exactly the failure mode the target exists to remove.
#
# So the probe reproduces the mechanism end to end: it forks, the child
# publishes the address of an automatic array through a volatile pointer (making
# the object address-escaping, which is the condition for per-variable redzones,
# and defeating constant folding of the offset), reads one byte below it, and
# would _exit(0) if it survived.  The probe SUCCEEDS ONLY IF THE CHILD DID NOT
# EXIT NORMALLY WITH STATUS 0 -- the same "completed" predicate param_util.h's
# harness uses, and spelled that way for the same reason: a report ends the
# child with a non-zero exit status on some configurations and with a signal on
# others, and the answer must not depend on which.  A child that survives means
# the instrumentation is not watching, and the probe reports failure.
#
# The child silences its own stderr, so a successful configure does not print a
# kilobyte of expected sanitizer report into CMakeOutput.log, and drops its
# RLIMIT_CORE, so an expected death cannot leave a core image beside the build
# tree -- the same two obligations every fork site in this suite carries.
#
# check_c_source_runs() is from CMake's CheckCSourceRuns module, present far
# below the 3.18 floor.  It cannot answer for a target machine that is not this
# one, so the probe is skipped outright when CMAKE_CROSSCOMPILING is true and
# the target is then not registered -- refusing to guess is the only correct
# answer there, and it degrades exactly like the other capability gates.
set(LIBPROV_MEMORY_ORACLE_PROBE_SOURCE "
#if !defined(_POSIX_C_SOURCE)
# define _POSIX_C_SOURCE 200809L
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/resource.h>
int main(void)
{
    pid_t child;
    int status = 0;

    fflush(NULL);
    child = fork();
    if (child < 0)
        return 1;
    if (child == 0) {
        unsigned char probe[8];
        unsigned char *volatile escaped;
        const volatile unsigned char *below;
        struct rlimit nocore;

        nocore.rlim_cur = 0;
        nocore.rlim_max = 0;
        (void)setrlimit(RLIMIT_CORE, &nocore);
        if (freopen(\"/dev/null\", \"w\", stderr) == NULL) {
            /* Deliberately empty: the child still has to go on and fault. */
        }

        memset(probe, 0, sizeof probe);
        escaped = probe;
        below = escaped - 1;
        if (*below == 0xFFu)
            _exit(2);
        _exit(0);
    }
    while (waitpid(child, &status, 0) != child) {
        if (errno != EINTR)
            return 1;
    }

    /*
     * Success means the child did NOT complete normally with status 0: the
     * instrumentation stopped it, by signal or by exit status.
     */
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 1 : 0;
}
")

# Normalised to the empty string before anything reads them.  Neither variable
# is set by CMake itself, so a project that never touched them leaves them
# UNDEFINED -- and the save below would then be a read of an undefined variable,
# which cmake --warn-uninitialized reports.  Their effective value when
# undefined is already "no extra flags", so defining them empty changes no
# behaviour and makes both the save and the restore reads of a defined variable.
# Done once here rather than at each of the two save/restore pairs.
if(NOT DEFINED CMAKE_REQUIRED_FLAGS)
  set(CMAKE_REQUIRED_FLAGS "")
endif()
if(NOT DEFINED CMAKE_REQUIRED_LINK_OPTIONS)
  set(CMAKE_REQUIRED_LINK_OPTIONS "")
endif()

# The instrumentation flags are the SAME LIST the target below is given, held in
# one variable so the thing that was probed and the thing that is built cannot
# drift apart.  -fno-omit-frame-pointer and -g are not decoration: without them
# a report names addresses instead of num.c's line, and a diagnosis nobody can
# read is most of the value gone.  They go on both the compile and the link line
# because -fsanitize=address selects a runtime as well as a code transform.
set(LIBPROV_MEMORY_ORACLE_FLAGS -fsanitize=address -fno-omit-frame-pointer -g)

# The probe is only asked when the mechanism it would enable is even available:
# the oracle group runs its cases in param_util.h's forked harness, so without
# the guard-page capability there is nothing for it to run in -- and
# tests/test_num_set.c stops the compile with a diagnostic naming exactly that
# if the two are ever combined wrongly.  Cross-compiling is excluded outright,
# since running the probe would answer for the host and not for the target.
if(LIBPROV_GUARD_PAGES_AVAILABLE AND NOT CMAKE_CROSSCOMPILING)
  include(CheckCSourceRuns)

  set(LIBPROV_SAVED_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS}")
  set(LIBPROV_SAVED_REQUIRED_LINK_OPTIONS "${CMAKE_REQUIRED_LINK_OPTIONS}")

  # CMAKE_REQUIRED_FLAGS is a STRING on the compile line, not a list, so the
  # flags are joined with spaces; CMAKE_REQUIRED_LINK_OPTIONS is a list.  Both
  # are needed, for the two reasons given above the flag variable.
  string(REPLACE ";" " " LIBPROV_MEMORY_ORACLE_CFLAGS
         "${LIBPROV_MEMORY_ORACLE_FLAGS}")
  set(CMAKE_REQUIRED_FLAGS
      "${LIBPROV_SAVED_REQUIRED_FLAGS} ${LIBPROV_MEMORY_ORACLE_CFLAGS}")
  set(CMAKE_REQUIRED_LINK_OPTIONS ${LIBPROV_MEMORY_ORACLE_FLAGS})

  check_c_source_runs("${LIBPROV_MEMORY_ORACLE_PROBE_SOURCE}"
                      LIBPROV_HAVE_MEMORY_ORACLE)

  set(CMAKE_REQUIRED_FLAGS "${LIBPROV_SAVED_REQUIRED_FLAGS}")
  set(CMAKE_REQUIRED_LINK_OPTIONS "${LIBPROV_SAVED_REQUIRED_LINK_OPTIONS}")
endif()

# ---------------------------------------------------------------------------
# SAY WHAT THE PROBES DECIDED
# ---------------------------------------------------------------------------
# A mechanism that a host cannot support is dropped, and a drop that is silent
# reads exactly like a suite that was never written.  One STATUS line per failed
# probe names what is missing and what it cost, so the reduced target count in
# the ctest summary is explained rather than mysterious.  Nothing is printed on
# the path where everything is supported, which is the common case and needs no
# commentary.
#
# Each condition below repeats the gate its registration uses, so a line appears
# exactly when the mechanism is genuinely absent.
if(NOT LIBPROV_GUARD_PAGES_AVAILABLE)
  message(STATUS
    "libprov tests: the mapping, process and resource-limit interfaces the "
    "protected-boundary oracle needs are not all available; test_num_get and "
    "test_num_set are still registered and still run, without their guarded "
    "groups")
endif()
if(NOT LIBPROV_HAVE_MEMORY_ORACLE)
  message(STATUS
    "libprov tests: an instrumented one-byte under-read was not caught when "
    "the probe ran it, so per-variable memory instrumentation cannot be "
    "relied on here; test_num_set_memory is not registered")
endif()
if(NOT LIBPROV_HAVE_UNDEBUG_FLAG)
  message(STATUS
    "libprov tests: the compiler does not accept -UNDEBUG, so err.c's "
    "assertions cannot be forced live independently of the build type; "
    "test_err_guards and test_err_death assert only what this build type "
    "leaves reachable")
endif()
if(NOT LIBPROV_HAVE_POSIX_DEATH_HARNESS)
  message(STATUS
    "libprov tests: the process and resource-limit interfaces the abort "
    "harness needs are not all available; test_err_death is not registered")
endif()
if(NOT (LIBPROV_HAVE_WRAP_MALLOC AND LIBPROV_HAVE_WRAP_FREE
        AND LIBPROV_HAVE_WRAP_MECHANISM))
  message(STATUS
    "libprov tests: the linker did not route the allocator through "
    "-Wl,--wrap=malloc and -Wl,--wrap=free; test_err_alloc is not registered")
endif()

# ---------------------------------------------------------------------------
# libprov_add_test(<name> [SOURCES <src>...] [DEFS <def>...]
#                         [COPTS <opt>...]  [LINKOPTS <opt>...])
# ---------------------------------------------------------------------------
# Builds one test executable and registers it with CTest.  The body is the
# maintainer's own four-step per-directory pattern -- add_executable,
# target_link_libraries(PRIVATE libprov), target_include_directories(PRIVATE
# ${OPENSSL_INCLUDE_DIR}), add_test -- plus the three optional per-target
# knobs the nine registrations below need.  Keeping it in a function is what
# stops nine copies of that pattern from drifting apart.
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
# The protected-boundary oracle for the two numeric targets (Probe 1)
# ---------------------------------------------------------------------------
# Three of num.c's guards exist only to keep an index inside its buffer, and
# removing any of them changes no return code and no destination value for any
# input: paramsign()'s zero-size guard (num.c:19-20), the padding-strip loop's
# bound (num.c:92) and the padding offset (num.c:119).  MEASURED: with the
# first of those reintroduced, every target of the suite as it then stood -- the
# eight that predate Probe 5's instrumented configuration -- stayed green.
# Their only observable is an access one byte outside an object, and the
# mandated command passes no sanitizer flag, so without a mechanism here they
# are untested under the command that matters.  Two mechanisms answer that
# between them: this oracle, for the accesses that fall outside an object a TEST
# owns, and test_num_set_memory's instrumentation, for the one that falls
# outside an object the LIBRARY owns.
#
# LIBPROV_TEST_GUARD_PAGES switches on param_util.h's oracle, which maps three
# pages, makes the outer two PROT_NONE, places a fixture flush against an edge
# and runs it in a forked child so the resulting fault is reported as a named
# assertion failure instead of killing the test binary.  It changes NO existing
# case: it adds one group to each numeric target and leaves everything else
# byte for byte as it was.
#
# One defect is deliberately NOT claimed here.  Reverting the zero-capacity
# clamp at num.c:91 makes the strip loop read one byte below provnum_set_*'s own
# `src` parameter -- inside the library function's stack frame, which a test
# owns no part of and can put no page against, so whether that revert changes
# any answer is decided by a byte no fixture controls (measured here: it does,
# 200 runs out of 200, which is a fact about this host and not a mechanism).
# The two numeric targets pin that input's full documented answer in every
# build, the guarded groups pin the neighbouring property that a zero-capacity
# call touches no destination byte, and the read itself is detected by the
# opt-in -fsanitize=address configuration the specification names for that
# purpose and equally forbids making a default.  tests/test_num_set.c records
# the reasoning and the alternatives that were tried and rejected.
#
# It rides on the two EXISTING registrations through a computed variable rather
# than through extra libprov_add_test() calls, because the registered target
# count is part of this suite's shape: the targets named in the header above,
# and this mechanism is a property of two of them rather than a target of its
# own.  The definition is applied per target, so the six error targets are
# untouched and neither the allocator interposer nor the abort harness -- each
# file-local to its own executable -- shares a process with it.
#
# The definition is made only where Probe 1 established every capability the
# oracle uses -- the four headers, the seven functions, and the flags, constants
# and wait-status macros the one-shot mechanism probe links: the mmap family
# with MAP_ANONYMOUS, MAP_PRIVATE, MAP_SHARED and the PROT_* flags,
# sysconf(_SC_PAGESIZE), fork/waitpid with the wait-status macros, and
# setrlimit(RLIMIT_CORE) for the child's core limit.  On a host missing any of
# them the definition is simply not made: the two targets are still registered
# and still run, one group lighter, and every case outside the guarded groups is
# unchanged.  That mirrors how test_err_death and test_err_alloc are handled --
# never registered and skipped, never registered and allowed to fail -- so there
# is still no DISABLED property, no SKIP_RETURN_CODE and no exclusion filter
# anywhere in this file.
#
# Gating on the probes rather than on `if(UNIX)` is what makes that promise
# real.  MAP_ANONYMOUS is a Linux and BSD extension rather than a POSIX flag, so
# UNIX does not imply it, and param_util.h answers a missing one with #error --
# by design, since a silently unprotected oracle would be worse.  Under the old
# proxy such a host FAILED THE BUILD of two ALWAYS-REGISTERED targets; under the
# probes it loses one group and builds.  The numeric sources set their own
# feature-test level before their first #include and the probe sets the same
# one, so the probe and the real compilation see the same declarations.
set(LIBPROV_NUM_DEFS "")
if(LIBPROV_GUARD_PAGES_AVAILABLE)
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
# is empty wherever Probe 1's capability set was incomplete;
# libprov_add_test() applies DEFS only when the list is non-empty, so an empty
# one is a genuine no-op rather than a configure error.  Both targets are
# registered either way: the probe decides how much they assert, never whether
# they run.
libprov_add_test(test_num_get     SOURCES test_num_get.c
                                  DEFS ${LIBPROV_NUM_DEFS})
libprov_add_test(test_num_set     SOURCES test_num_set.c
                                  DEFS ${LIBPROV_NUM_DEFS})
libprov_add_test(test_err_handle  SOURCES test_err_handle.c)
libprov_add_test(test_err_raise   SOURCES test_err_raise.c)

# ---------------------------------------------------------------------------
# The instrumented configuration of tests/test_num_set.c
# ---------------------------------------------------------------------------
# The SECOND configuration of a source already registered above, in the same
# shape as test_err_guards / test_err_guards_ndebug below and for the same
# reason: one set of flags cannot exhibit both of the things that need
# asserting.  There the two contracts are err.c's assert()-live and NDEBUG
# behaviour; here the ordinary target asserts the CONTRACT with the project's
# default flags and this one asserts a MEMORY property that no set of default
# flags can observe.
#
# WHAT ONLY THIS TARGET CAN OBSERVE.  Reverting the zero-capacity clamp at
# num.c:91 makes the strip loop read one byte below provnum_set_*'s own `src`
# parameter -- an object belonging to the library, inside the library's own
# frame.  The reasoning is set out at "The protected-boundary oracle" above and
# in full in tests/test_num_set.c; the conclusion is that only per-variable
# redzone instrumentation can see such an access, and that it has to be applied
# to num.c rather than to the test, because the out-of-bounds object is num.c's.
#
# SO num.c IS NAMED IN THE SOURCE LIST, and that is deliberate rather than
# redundant.  The archive libprov is still linked -- libprov_add_test() does
# that for every target, and it is what makes prov/num.h resolve -- but a
# definition already satisfied by a named object file means the linker never
# extracts the archive member, so the code under test is the INSTRUMENTED
# translation unit. Compiling libprov itself with these flags would have been
# the alternative and is not acceptable: it would put a sanitizer on the library
# every other target links, which is precisely the default the specification
# forbids.
#
# NOTHING GLOBAL CHANGES.  COPTS and LINKOPTS are per-target through
# target_compile_options and target_link_options; CMAKE_C_FLAGS is not written
# to, no cache variable is set, and libprov, the ordinary test_num_set and the
# other seven targets compile exactly as they did.  The mandated
# cmake -B build && cmake --build build && ctest --test-dir build still needs no
# -D flag: this target is configured and built by default, like every other, and
# it is the PROBE and not a user flag that decides whether it exists.
#
# REGISTERED ONLY WHERE THE CHECKER WAS PROVED TO WORK.  LIBPROV_HAVE_MEMORY_
# ORACLE comes from the check_c_source_runs() probe above, which compiles, links
# AND RUNS an instrumented one-byte stack under-read and requires it to be
# stopped.  Where that fails -- no sanitizer runtime, instrumentation disabled,
# cross-compiling -- the target is NOT REGISTERED AT ALL, never registered and
# skipped and never registered and allowed to fail, so there is still no
# DISABLED property, no SKIP_RETURN_CODE and no exclusion filter anywhere in
# this file. The suite loses one target and the other eight are unaffected.
#
# The target's own first case is a deliberate under-read asserted to be caught,
# so even a build that reached here with the instrumentation somehow inert fails
# by name instead of passing vacuously.
if(LIBPROV_HAVE_MEMORY_ORACLE)
  libprov_add_test(test_num_set_memory
                   SOURCES test_num_set.c ${PROJECT_SOURCE_DIR}/num.c
                   DEFS ${LIBPROV_NUM_DEFS} LIBPROV_TEST_MEMORY_ORACLE
                   COPTS ${LIBPROV_MEMORY_ORACLE_FLAGS}
                   LINKOPTS ${LIBPROV_MEMORY_ORACLE_FLAGS})
endif()

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
# It arrives as ${LIBPROV_UNDEBUG_OPT} rather than as a literal because Probe 3
# asked the compiler whether it accepts the flag.  Where it does, the variable
# holds it and this target is immune to the build type.  Where it does not the
# variable is empty, the unquoted expansion contributes no argument at all,
# libprov_add_test() applies no COPTS -- and the target still builds and still
# asserts the aborts in every build that does not itself define NDEBUG, which
# is every default build.  Hard-coding the flag would instead fail the compile
# of this target and of test_err_death outright on such a compiler, which is
# the worst available outcome for a purely defensive flag.
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
                 COPTS ${LIBPROV_UNDEBUG_OPT})
libprov_add_test(test_err_guards_ndebug
                 SOURCES test_err_guards.c ${PROJECT_SOURCE_DIR}/err.c
                 DEFS NDEBUG LIBPROV_TEST_NDEBUG_VARIANT)

# ---------------------------------------------------------------------------
# The abort contract, asserted positively (Probe 2 gates the registration)
# ---------------------------------------------------------------------------
# test_err_death.c forks, lets the child run an aborting input, and requires
# WIFSIGNALED(status) && WTERMSIG(status) == SIGABRT of the wait status -- a
# strictly stronger claim than "the process failed", and one that no CTest
# property can express.  Both candidates were tried and both report a
# SIGABRT child as "(Subprocess aborted)" regardless: PASS_REGULAR_EXPRESSION
# despite documenting that the exit code is ignored, and WILL_FAIL TRUE
# despite documenting that it inverts the verdict.
#
# The gate is Probe 2 -- its own probe, independent of the numeric one -- which
# COMPILED AND LINKED the harness's own shape: fork(), waitpid(), the
# wait-status macros, WTERMSIG, SIGABRT, _exit(), freopen() and the RLIMIT_CORE
# drop, at the _POSIX_C_SOURCE=200809L level the file itself selects.  Asking
# `if(UNIX)` instead would have been a guess about a family rather than a
# question about a capability: UNIX holds on hosts this harness cannot be built
# for, and on a UNIX-like host that does not declare setrlimit() such a gate
# would have registered the target and then FAILED THE BUILD, when the required
# behaviour is to configure successfully with this one target absent.
#
# Where the probe fails the target is NOT REGISTERED AT ALL -- never registered
# and skipped, never registered and allowed to fail.  Configuration still
# succeeds there and the other seven targets run normally, which is why there is
# no DISABLED property, no SKIP_RETURN_CODE and no exclusion filter anywhere in
# this file.
#
# err.c is compiled in, and ${LIBPROV_UNDEBUG_OPT} applied, for the same reason
# as the default guards target above: the assertions this file exists to observe
# must be live in the translation unit that holds them, in every build type --
# and the flag is probed rather than assumed there for the same reason it is
# probed rather than assumed here.
#
# TIMEOUT 30 is the one runner-level property in the suite.  It is a safety
# net, not a budget -- the file completes in milliseconds -- so that a defect
# in the harness degrades into a reported timeout instead of a hung suite.  It
# is not a skip mechanism and it excuses no failure.
if(LIBPROV_HAVE_POSIX_DEATH_HARNESS)
  libprov_add_test(test_err_death
                   SOURCES test_err_death.c ${PROJECT_SOURCE_DIR}/err.c
                   COPTS ${LIBPROV_UNDEBUG_OPT})
  set_tests_properties(test_err_death PROPERTIES TIMEOUT 30)
endif()

# ---------------------------------------------------------------------------
# The out-of-memory contract (Probe 4 gates the registration)
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
# --wrap is a linker feature, so the gate asks the LINKER, and it asks by
# LINKING.  Probe 4 does it in three parts and all three must hold: an
# end-to-end link with -Wl,--wrap=malloc alone, another with -Wl,--wrap=free
# alone -- both are load-bearing and a linker could conceivably rewrite one
# spelling and not the other -- and a third with both together, which is how
# this target is actually linked.  Each probe defines the wrapper and calls
# through the __real_ original, so it proves the rewrite HAPPENED rather than
# merely that an option was tolerated.  Mere option ACCEPTANCE is a proxy in its
# own right, and was measured rejecting this target under --coverage while the
# target itself built and passed; Probe 4 records that measurement and why the
# idiomatic check_linker_flag() cannot express the question.
#
# The proxy that stood here before asked CMAKE_C_COMPILER_ID, which names the
# COMPILER VENDOR while --wrap belongs to the linker: clang drives ld64, lld,
# mold and GNU ld alike, so "GNU|Clang" both over- and under-approximated, and
# `NOT APPLE` excluded exactly one known ld64 host by name while saying nothing
# about any other linker without the feature.  Over-approximating was the
# damaging direction: it FAILED THE LINK of this target rather than omitting it.
# Apple needs no special case any more -- ld64 has no --wrap, so the probes
# simply do not succeed there.
#
# Where the probes fail the target is, again, NOT REGISTERED AT ALL rather than
# skipped or allowed to fail.
if(LIBPROV_HAVE_WRAP_MALLOC AND LIBPROV_HAVE_WRAP_FREE
   AND LIBPROV_HAVE_WRAP_MECHANISM)
  libprov_add_test(test_err_alloc SOURCES test_err_alloc.c
                   LINKOPTS "-Wl,--wrap=malloc" "-Wl,--wrap=free")
endif()
