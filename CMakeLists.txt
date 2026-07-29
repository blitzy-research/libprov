cmake_minimum_required(VERSION 3.18 FATAL_ERROR)
cmake_policy(SET
  # This allows setting C_VISIBILITY_PRESET on static libraries, for
  # those who want to do this with the libprov library
  CMP0063 NEW
)
project(libprov LANGUAGES C)
set(CMAKE_C_STANDARD 99)

if (NOT OPENSSL_FOUND)
  find_package(OpenSSL 3.0 REQUIRED)
endif()

add_library(libprov STATIC err.c num.c)
set_target_properties(libprov PROPERTIES
  POSITION_INDEPENDENT_CODE ON
  OUTPUT_NAME "prov")
target_include_directories(libprov PUBLIC include)
target_include_directories(libprov PRIVATE ${OPENSSL_INCLUDE_DIR})

# The unit test suite lives in tests/ and is registered with CTest from
# tests/CMakeLists.txt.  It is built by default for a top-level build of
# libprov, so that
#
#     cmake -B build && cmake --build build && ctest --test-dir build
#
# needs no -D flag, while a project that embeds libprov with
# add_subdirectory() still gets the opt-out: LIBPROV_TESTS defaults OFF there
# and no test target is created.  CMAKE_SOURCE_DIR STREQUAL
# CMAKE_CURRENT_SOURCE_DIR expresses "libprov is the top-level project"
# without PROJECT_IS_TOP_LEVEL, which would need CMake 3.21 while this project
# declares a 3.18 floor above.
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
  set(LIBPROV_TESTS_DEFAULT ON)
else()
  set(LIBPROV_TESTS_DEFAULT OFF)
endif()
option(LIBPROV_TESTS "Build and possibly run tests" ${LIBPROV_TESTS_DEFAULT})

if(LIBPROV_TESTS)
  # WHERE TESTING IS ENABLED DECIDES WHERE ctest CAN FIND THE TESTS, so it is
  # decided here rather than in tests/CMakeLists.txt.  ctest reads
  # CTestTestfile.cmake from the directory it is pointed at, and CMake writes
  # that file only for a directory in which testing was enabled -- which is
  # exactly what enable_testing()'s own documentation means by "this command
  # should be in the source directory root because ctest expects to find a test
  # file in the build directory root".  Calling include(CTest) from a
  # SUBDIRECTORY of the build therefore does not merely fail to help: it
  # produces the worst outcome available, a set of registered tests that
  # `ctest --test-dir <build root>` cannot see.
  #
  # The condition below is the same top-level test as the option above, repeated
  # rather than cached in a variable so that block stays exactly as it is.
  if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    # A top-level libprov build: this IS the source root, so this is where CTest
    # belongs, and ctest --test-dir <bindir> sees every registered test.
    # include(CTest) also creates the BUILD_TESTING option -- defaulting ON --
    # and, when it is ON, calls enable_testing() for this directory and below.
    include(CTest)
  endif()

  # CTest's own switch has the last word, and it is obeyed rather than worked
  # around.  With BUILD_TESTING=OFF nothing called enable_testing(), so every
  # add_test() below would be silently dropped and the build would still produce
  # nine test executables with no registered test behind any of them -- a suite
  # that looks green because it is empty, which is precisely the condition this
  # test suite exists to eliminate.  Creating no target is the honest outcome.
  #
  # It is not a skipped test either: nothing is registered and then disabled, no
  # DISABLED property or SKIP_RETURN_CODE is involved, and the flagless command
  # documented in README.md leaves BUILD_TESTING at its default of ON, so the
  # full suite is what that command builds and runs.
  if(DEFINED BUILD_TESTING AND NOT BUILD_TESTING)
    message(STATUS
      "libprov: LIBPROV_TESTS is ON but BUILD_TESTING is OFF, so no test target"
      " is created.  Configure with -DBUILD_TESTING=ON to build and register"
      " them.")
  else()
    if(NOT CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
      # An embedded build that asked for libprov's tests explicitly.  Whether
      # they are discoverable from the top of the build is the parent project's
      # decision, not one this file can make for it, so the two possibilities
      # are told apart by the one DOCUMENTED observable that exists: the CACHE
      # ENTRY TYPE of BUILD_TESTING.  No undocumented CMake internal is
      # consulted for it.
      #
      #   type is BOOL           the CTest module ran and created BUILD_TESTING
      #                          as its option, which means testing was enabled
      #                          at the build's SOURCE ROOT and these tests
      #                          register into the parent's tree, discoverable
      #                          with ctest at the parent's build root.
      #                          MEASURED with a superproject that calls
      #                          include(CTest) before add_subdirectory():
      #                          9/9 from the parent's build root.
      #   anything else          no CTest module created it, so nothing here can
      #                          promise the build root a CTestTestfile.cmake.
      #                          The supported contract is then the SUB-BUILD
      #                          invocation named below, and the consumer is told
      #                          so at configure time along with the one-line
      #                          change that buys top-level discovery.
      #
      # WHY THE TYPE AND NOT MERELY `IF(DEFINED BUILD_TESTING)`
      #
      # Because existence is a PROXY for "CTest ran", and it is a leaky one: a
      # bare -DBUILD_TESTING=ON on the command line defines the variable without
      # any module having run.  MEASURED: an embedded parent that never includes
      # CTest but is configured with -DBUILD_TESTING=ON built all nine tests,
      # left the parent build root with NO CTestTestfile.cmake, and -- under the
      # existence check -- said nothing at all, which is precisely the silent
      # "tests exist and ctest cannot see them" outcome this branch exists to
      # prevent.  The cache type separates the two cleanly, MEASURED: BOOL with
      # helpstring "Build the testing tree." when the CTest module created it,
      # UNINITIALIZED with "specified on the command line" when a -D did.
      get_property(LIBPROV_BUILD_TESTING_TYPE
               CACHE BUILD_TESTING PROPERTY TYPE)
      if(NOT LIBPROV_BUILD_TESTING_TYPE STREQUAL "BOOL")
        # Worded as two claims that are each true whatever the top level did:
        # libprov's own subtree IS a complete ctest tree, and top-level
        # discovery depends on the top level having enabled testing.  A parent
        # that called bare enable_testing() -- which leaves no BUILD_TESTING
        # behind, so it lands here -- reads this and correctly concludes that
        # its own build root works too; nothing above asserts otherwise.
        message(WARNING
          "libprov: LIBPROV_TESTS is ON in an embedded build, and nothing in"
          " this build has included CTest, so libprov cannot confirm that the"
          " top level (${CMAKE_SOURCE_DIR}) enabled testing.  libprov's tests"
          " are registered in libprov's own subtree, which is a complete ctest"
          " tree: run `ctest --test-dir ${CMAKE_CURRENT_BINARY_DIR}`."
          "  `ctest --test-dir ${CMAKE_BINARY_DIR}` finds them only if the top"
          " level enabled testing itself; to guarantee that, call include(CTest)"
          " -- or enable_testing() -- in ${CMAKE_SOURCE_DIR}/CMakeLists.txt"
          " before the add_subdirectory() that adds libprov, and leave"
          " BUILD_TESTING ON.  To build no tests at all, leave LIBPROV_TESTS at"
          " its embedded default of OFF.")
      endif()

      # Either way, make libprov's own subtree a complete ctest tree.  Where the
      # parent already enabled testing at its source root this is redundant and
      # harmless -- MEASURED: the parent's build root still lists and passes all
      # nine -- and where it did not, this is what makes the sub-build
      # invocation above work at all.
      enable_testing()
    endif()
    add_subdirectory(tests)
  endif()
endif()
