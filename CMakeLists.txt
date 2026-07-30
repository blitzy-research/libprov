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

# include(CTest) is what makes the tests discoverable: it enables testing for
# this directory and below, so CMake writes a CTestTestfile.cmake into the
# build root and `ctest --test-dir build` sees everything tests/ registers.
# It also brings CTest's own BUILD_TESTING option, which the flagless command
# above leaves at its default of ON.  enable_testing() is deliberately NOT
# called in addition -- include(CTest) already calls it, and calling both
# would be redundant.
if(LIBPROV_TESTS)
  include(CTest)
  add_subdirectory(tests)
endif()
