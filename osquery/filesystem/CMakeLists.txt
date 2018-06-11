#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

if(NOT WINDOWS)
  osquery_find_and_link_library(libosquery "iconv")
  osquery_find_and_link_library(libosquery "archive")
  osquery_find_and_link_library(libosquery "zstd")
else()
  osquery_find_and_link_library(libosquery "archive_static")
  osquery_find_and_link_library(libosquery "zstd_static")
endif()

if(APPLE)
  target_sources(libosquery
    PRIVATE
      "${CMAKE_CURRENT_LIST_DIR}/darwin/plist.mm"
  )
  target_link_libraries(libosquery "-framework Foundation")
elseif(FREEBSD)
elseif(LINUX)
  target_sources(libosquery
    PRIVATE
      "${CMAKE_CURRENT_LIST_DIR}/linux/mem.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/linux/proc.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/linux/proc.h"
  )
endif()

target_sources(libosquery 
  PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/${PROCESS_FAMILY}/fileops.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/file_compression.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/fileops.h"
    "${CMAKE_CURRENT_LIST_DIR}/filesystem.cpp"
)

ADD_OSQUERY_TEST(
  "${CMAKE_CURRENT_LIST_DIR}/tests/fileops_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/tests/filesystem_tests.cpp"
)

if(APPLE)
  ADD_OSQUERY_TEST(
    "${CMAKE_CURRENT_LIST_DIR}/darwin/tests/plist_tests.cpp"
  )
  ADD_OSQUERY_BENCHMARK(
    "${CMAKE_CURRENT_LIST_DIR}/darwin/benchmarks/plist_benchmarks.cpp"
  )
endif()
