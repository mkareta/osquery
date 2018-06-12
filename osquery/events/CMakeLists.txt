#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

if(APPLE)
  target_link_libraries(libosquery 
    "-framework CoreServices"
    "-framework SystemConfiguration"
    "-framework IOKit"
    "-framework DiskArbitration"
    "-framework CoreGraphics"
  )
  osquery_find_and_link_library(libosquery "bsm")
  target_sources(libosquery 
    PRIVATE
      "${CMAKE_CURRENT_LIST_DIR}/darwin/diskarbitration.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/darwin/diskarbitration.h"
      "${CMAKE_CURRENT_LIST_DIR}/darwin/event_taps.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/darwin/event_taps.h"
      "${CMAKE_CURRENT_LIST_DIR}/darwin/fsevents.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/darwin/fsevents.h"
      "${CMAKE_CURRENT_LIST_DIR}/darwin/iokit.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/darwin/iokit.h"
      "${CMAKE_CURRENT_LIST_DIR}/darwin/kernel_util.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/darwin/openbsm.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/darwin/openbsm.h"
      "${CMAKE_CURRENT_LIST_DIR}/darwin/scnetwork.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/darwin/scnetwork.h"
  )
elseif(FREEBSD)
  target_sources(libosquery 
    PRIVATE
      "${CMAKE_CURRENT_LIST_DIR}/freebsd/fsevents.h"
      "${CMAKE_CURRENT_LIST_DIR}/freebsd/kernel_util.cpp"
  )
elseif(WINDOWS)
  osquery_find_and_link_library(libosquery "wevtapi.lib")
  target_sources(libosquery 
    PRIVATE
      "${CMAKE_CURRENT_LIST_DIR}/windows/windows_event_log.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/windows/windows_event_log.h"
  )
else() #LINUX
  osquery_find_and_link_library(libosquery "udev")
  osquery_find_and_link_library(libosquery "audit")

  target_sources(libosquery
    PRIVATE
      "${CMAKE_CURRENT_LIST_DIR}/linux/auditdnetlink.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/linux/auditdnetlink.h"
      "${CMAKE_CURRENT_LIST_DIR}/linux/auditeventpublisher.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/linux/auditeventpublisher.h"
      "${CMAKE_CURRENT_LIST_DIR}/linux/inotify.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/linux/inotify.h"
      "${CMAKE_CURRENT_LIST_DIR}/linux/kernel_util.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/linux/syslog.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/linux/syslog.h"
      "${CMAKE_CURRENT_LIST_DIR}/linux/tests"
      "${CMAKE_CURRENT_LIST_DIR}/linux/udev.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/linux/udev.h"
  )
endif()

target_sources(libosquery
  PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/events.cpp"
)

ADD_OSQUERY_TEST(
  "${CMAKE_CURRENT_LIST_DIR}/tests/events_database_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/tests/events_tests.cpp"
)

if(NOT WINDOWS)
  file(GLOB OSQUERY_EVENTS_BENCHMARKS "benchmarks/*.cpp")
  if (LINUX)
    file(GLOB OSQUERY_EVENTS_PLATFORM_BENCHMARKS "linux/benchmarks/*.cpp")
  elseif (DARWIN)
    file(GLOB OSQUERY_EVENTS_PLATFORM_BENCHMARKS "darwin/benchmarks/*.cpp")
  endif()
  ADD_OSQUERY_BENCHMARK(
    ${OSQUERY_EVENTS_BENCHMARKS}
    ${OSQUERY_EVENTS_PLATFORM_BENCHMARKS}
  )

  # Kernel-related userland code.
  if(NOT SKIP_KERNEL)
    message("Not skip kernel ? ${SKIP_KERNAL}")
    file(GLOB OSQUERY_EVENTS_KERNEL "kernel/*.cpp")
    target_sources(libosquery
      PRIVATE
        "${CMAKE_CURRENT_LIST_DIR}/kernel.cpp"
        "${OSQUERY_EVENTS_KERNEL}"
    )

    # Special kernel test define when building non-SDK and non-Release.
    if(NOT OSQUERY_BUILD_RELEASE AND NOT OSQUERY_BUILD_SDK_ONLY)
      set_target_properties(osquery_events_kernel
        PROPERTIES COMPILE_DEFINITIONS "KERNEL_TEST=1")
    endif()

    file(GLOB OSQUERY_EVENTS_KERNEL_TESTS "kernel/tests/*.cpp")
    ADD_OSQUERY_KERNEL_TEST(${OSQUERY_EVENTS_KERNEL_TESTS})

    file(GLOB OSQUERY_EVENTS_KERNEL_BENCHMARKS "kernel/benchmarks/*.cpp")
    ADD_OSQUERY_KERNEL_BENCHMARK(${OSQUERY_EVENTS_KERNEL_BENCHMARKS})
  endif()
endif()

if(APPLE)
  ADD_OSQUERY_TEST(
    "${CMAKE_CURRENT_LIST_DIR}/darwin/tests/fsevents_tests.cpp"
  )
elseif(LINUX)
  ADD_OSQUERY_TEST(
    "${CMAKE_CURRENT_LIST_DIR}/linux/tests/audit_tests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/linux/tests/inotify_tests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/linux/tests/process_file_events_tests.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/linux/tests/syslog_tests.cpp"
  )
elseif(WINDOWS)
  ADD_OSQUERY_TEST(
    "${CMAKE_CURRENT_LIST_DIR}/windows/tests/windows_event_log_tests.cpp"
  )
endif()
