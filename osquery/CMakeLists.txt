#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

cmake_policy(SET CMP0068 NEW)

# Generate and define platform mask
include(cmake/platform_mask.cmake)

# Global defines
add_definitions("-DOSQUERY_PLATFORM_MASK=${PLATFORM_MASK}")
add_definitions("-DOSQUERY_BUILD_VERSION=${OSQUERY_BUILD_VERSION}")

# Finally a set of 'core' tests and kernel-tests, and benchmark tests, is kept.
set(OSQUERY_TESTS "")
set(OSQUERY_KERNEL_TESTS "")
set(OSQUERY_BENCHMARKS "")
set(OSQUERY_KERNEL_BENCHMARKS "")
set(OSQUERY_TABLES_TESTS "")

include(cmake/core_compile_options.cmake)

# Main library
add_library(libosquery STATIC main/lib.cpp)
set_target_properties(libosquery PROPERTIES OUTPUT_NAME osquery)

if(DEFINED ENV{SANITIZE})
  if(DEFINED ENV{SANITIZE_THREAD})
    ADD_OSQUERY_LINK_CORE(-fsanitize=thread)
  elseif(DEFINED ENV{SANITIZE_UNDEFINED})
    ADD_OSQUERY_LINK_CORE(-fsanitize=undefined)
  else()
    ADD_OSQUERY_LINK_CORE(-fsanitize=address -fsanitize=leak)
  endif()
  ADD_OSQUERY_LINK_CORE(-fsanitize-blacklist=${SANITIZE_BLACKLIST})
  if(DEFINED ENV{FUZZ})
    ADD_OSQUERY_LINK_CORE(-fsanitize=fuzzer)
  endif()
endif()

include(cmake/default_libraries.cmake)

set(CMAKE_MACOSX_RPATH 0)
set(CMAKE_SKIP_RPATH TRUE)

include(config/CMakeLists.txt)
include(core/CMakeLists.txt)
include(database/CMakeLists.txt)
include(devtools/CMakeLists.txt)
include(dispatcher/CMakeLists.txt)
include(distributed/CMakeLists.txt)
include(events/CMakeLists.txt)
include(extensions/CMakeLists.txt)
include(filesystem/CMakeLists.txt)
include(logger/CMakeLists.txt)
include(registry/CMakeLists.txt)
include(remote/CMakeLists.txt)
include(sql/CMakeLists.txt)
include(utils/CMakeLists.txt)

target_sources(libosquery
    PRIVATE
      "$<TARGET_OBJECTS:osquery_sqlite>"
)

target_group_sources(libosquery "${CMAKE_CURRENT_LIST_DIR}")

# third-party objects
if(NOT FREEBSD)
  target_sources(libosquery
    PRIVATE
      "$<TARGET_OBJECTS:linenoise-ng>"
)
endif()

#tables
add_library(libosquery_tables STATIC)

if(NOT SKIP_CARVER)
  include(carver/CMakeLists.txt)
endif()

# Add externals directory from parent
if(NOT DEFINED ENV{FUZZ})
  add_subdirectory("${CMAKE_SOURCE_DIR}/external" "${CMAKE_BINARY_DIR}/external")
endif()

if(NOT OSQUERY_BUILD_SDK_ONLY)
  if(NOT SKIP_TABLES)
    include(tables/CMakeLists.txt)

    # Amalgamate the utility tables needed to compile.
    GENERATE_UTILITIES("${CMAKE_SOURCE_DIR}")
    AMALGAMATE("${CMAKE_SOURCE_DIR}" "utils" AMALGAMATION_UTILS)
    add_library(osquery_amalgamation OBJECT ${AMALGAMATION_UTILS})

    # Generate the osquery additional tables (the non-util).
    GENERATE_TABLES("${CMAKE_SOURCE_DIR}")
    AMALGAMATE("${CMAKE_SOURCE_DIR}" "additional" AMALGAMATION)
    add_library(osquery_additional_amalgamation OBJECT ${AMALGAMATION})

    AMALGAMATE("${CMAKE_SOURCE_DIR}" "foreign" AMALGAMATION_FOREIGN)
    add_library(osquery_foreign_amalgamation OBJECT ${AMALGAMATION_FOREIGN})
    
    target_sources(libosquery_tables 
      PRIVATE 
        "$<TARGET_OBJECTS:osquery_additional_amalgamation>"
        "$<TARGET_OBJECTS:osquery_foreign_amalgamation>"
        "$<TARGET_OBJECTS:osquery_amalgamation>"
    )

    target_group_sources(libosquery_tables "${CMAKE_CURRENT_LIST_DIR}/tables")
  endif()
endif()

# Create the dynamic libosquery.
if(DEFINED ENV{OSQUERY_BUILD_SHARED})
  add_library(libosquery_shared SHARED main/lib.cpp)
  target_link_libraries(libosquery_shared PRIVATE libosquery)
  set_target_properties(libosquery_shared PROPERTIES OUTPUT_NAME osquery)
endif()

# A friendly echo printed after the library is built.
add_custom_target(osquery_library ALL
  COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan --bold
    "-- Built libosquery: $<TARGET_FILE:libosquery>"
  DEPENDS libosquery
)

# make devel (implies install)
add_custom_target(devel
  COMMAND ${CMAKE_COMMAND} -D COMPONENT=devel -P cmake_install.cmake
  DEPENDS libosquery_basic
)
add_dependencies(devel libosquery)

if(FUZZ)
  add_executable(fuzz
    main/fuzz.cpp
  )

  ADD_DEFAULT_LINKS(fuzz TRUE)
  SET_OSQUERY_COMPILE(fuzz)
  set_target_properties(fuzz PROPERTIES OUTPUT_NAME osqueryf)
endif()

if(NOT OSQUERY_BUILD_SDK_ONLY AND NOT FUZZ)
  set(DAEMON_SOURCE_FILES
    devtools/shell.cpp
    main/main.cpp
    main/${PROCESS_FAMILY}/main.cpp
  )
  # Add the versioning information for Windows binaries
  if(WINDOWS)
    # The windows version resource requires a version string, as well
    # as version components separated by a comma. First we replace the `-`
    # values that may exist for commit hash versions, then we grab the
    # major version components
    string(REPLACE "-" "." OSQUERY_VER_TEMP "${OSQUERY_BUILD_VERSION}")
    string(REPLACE "." ";" OSQUERY_VERSION_LIST "${OSQUERY_VER_TEMP}")
    list(GET OSQUERY_VERSION_LIST 0 OSQUERY_PRODUCT_NUMBER)
    list(GET OSQUERY_VERSION_LIST 1 OSQUERY_PRODUCT_VERSION)
    list(GET OSQUERY_VERSION_LIST 2 OSQUERY_BUILD_NUMBER)

    configure_file(
      ${CMAKE_SOURCE_DIR}/tools/windows_resources.rc.in
      ${CMAKE_BINARY_DIR}/osquery/windows_resources.rc
      @ONLY)
    list(APPEND DAEMON_SOURCE_FILES ${CMAKE_BINARY_DIR}/osquery/windows_resources.rc)
  endif()
  add_executable(daemon
    ${DAEMON_SOURCE_FILES}
  )

  ADD_DEFAULT_LINKS(daemon TRUE)
  TARGET_OSQUERY_LINK_WHOLE(daemon libosquery)
  TARGET_OSQUERY_LINK_WHOLE(daemon libosquery_tables)

  SET_OSQUERY_COMPILE(daemon)
  set_target_properties(daemon PROPERTIES OUTPUT_NAME osqueryd)

  # A friendly echo printed before building the daemon
  add_custom_command(TARGET daemon PRE_BUILD
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan --bold
      "-- Building osqueryd: $<TARGET_FILE:daemon>"
  )

  set(SHELL_EXECUTABLE "osqueryi")
  if(WINDOWS)
    set(SHELL_EXECUTABLE "${SHELL_EXECUTABLE}.exe")
  endif()

  add_custom_target(shell ALL
    COMMAND ${CMAKE_COMMAND} -E copy
      $<TARGET_FILE:daemon> "$<TARGET_FILE_DIR:daemon>/${SHELL_EXECUTABLE}")

  add_custom_command(
    TARGET shell POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E cmake_echo_color --cyan --bold
      "-- Creating osqueryi: $<TARGET_FILE_DIR:daemon>/${SHELL_EXECUTABLE}")

  # This is no longer supported.
  # Include the public API includes if make devel.
  # install(TARGETS libosquery ARCHIVE DESTINATION lib COMPONENT devel OPTIONAL)
  # install(DIRECTORY "${CMAKE_SOURCE_DIR}/include/osquery"
  #   DESTINATION include
  #   COMPONENT devel OPTIONAL
  #   PATTERN ".*" EXCLUDE
  # )

  # make install (executables)
  install(TARGETS daemon RUNTIME DESTINATION bin COMPONENT main)
  install(PROGRAMS ${CMAKE_BINARY_DIR}/osquery/osqueryi DESTINATION bin COMPONENT main)
  install(FILES "${CMAKE_SOURCE_DIR}/tools/deployment/osqueryctl"
    DESTINATION bin COMPONENT main)

  # make install (config files)
  install(FILES "${CMAKE_SOURCE_DIR}/tools/deployment/osquery.example.conf"
    DESTINATION "${CMAKE_INSTALL_PREFIX}/share/osquery/" COMPONENT main)
  install(DIRECTORY DESTINATION "${CMAKE_INSTALL_PREFIX}/var/osquery")

  install(DIRECTORY "${CMAKE_SOURCE_DIR}/packs/"
    DESTINATION "${CMAKE_INSTALL_PREFIX}/share/osquery/packs" COMPONENT main)
  if(APPLE)
    install(FILES "${CMAKE_SOURCE_DIR}/tools/deployment/com.facebook.osqueryd.plist"
      DESTINATION "${CMAKE_INSTALL_PREFIX}/share/osquery/" COMPONENT main)
  else()
    install(PROGRAMS "${CMAKE_SOURCE_DIR}/tools/deployment/osqueryd.initd"
      DESTINATION "${CMAKE_INSTALL_PREFIX}/etc/init.d/" RENAME "osqueryd" COMPONENT main)
  endif()
endif()

if(NOT SKIP_TESTS)
  # osquery testing library (testing helper methods/libs).
  add_library(libosquery_testing STATIC tests/test_util.cpp)
  add_dependencies(libosquery_testing libosquery)
  target_link_libraries(libosquery_testing libosquery_tables)
  SET_OSQUERY_COMPILE(libosquery_testing)
  set_target_properties(libosquery_testing PROPERTIES OUTPUT_NAME osquery_testing)

  # osquery core set of unit tests build with SDK.
  add_executable(osquery_tests main/tests.cpp ${OSQUERY_TESTS})
  ADD_DEFAULT_LINKS(osquery_tests FALSE)
  target_sources(osquery_tests
      PRIVATE
        "${CMAKE_CURRENT_LIST_DIR}/tests/test_additional_util.cpp"
        "${CMAKE_CURRENT_LIST_DIR}/tests/test_additional_util.h"
        "${CMAKE_CURRENT_LIST_DIR}/tests/test_util.cpp"
        "${CMAKE_CURRENT_LIST_DIR}/tests/test_util.h"
    )
  target_link_libraries(osquery_tests gtest gmock libosquery_testing)
  SET_OSQUERY_COMPILE(osquery_tests "${GTEST_FLAGS}")
  add_test(osquery_tests osquery_tests ${TEST_ARGS})

  # osquery benchmarks.
  if(NOT SKIP_BENCHMARKS AND NOT OSQUERY_BUILD_SDK_ONLY)
    add_executable(osquery_benchmarks main/benchmarks.cpp ${OSQUERY_BENCHMARKS})
    target_link_libraries(osquery_benchmarks benchmark libosquery_testing pthread)
    ADD_DEFAULT_LINKS(osquery_benchmarks TRUE)
    SET_OSQUERY_COMPILE(osquery_benchmarks "${GTEST_FLAGS}")
    set(BENCHMARK_TARGET "$<TARGET_FILE:osquery_benchmarks>")

    # make benchmark
    add_custom_target(
      run-benchmark
      COMMAND bash -c "${BENCHMARK_TARGET} $ENV{BENCHMARK_TO_FILE}"
      WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
      DEPENDS osquery_benchmarks
    )
  endif()

  if(NOT OSQUERY_BUILD_SDK_ONLY)
    # osquery tables set of unit tests (extracted for organization).
    add_executable(osquery_tables_tests tests/test_additional_util.cpp main/tests.cpp ${OSQUERY_TABLES_TESTS})
    ADD_DEFAULT_LINKS(osquery_tables_tests TRUE)
    target_link_libraries(osquery_tables_tests gtest gmock libosquery_testing)
    SET_OSQUERY_COMPILE(osquery_tables_tests "${GTEST_FLAGS}")
    add_test(osquery_tables_tests osquery_tables_tests ${TEST_ARGS})
  endif()

  # Build the example extension with the SDK.
  ADD_OSQUERY_EXTENSION(example_extension examples/example_extension.cpp)
endif()
