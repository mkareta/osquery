#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

target_sources(libosquery
  PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/dispatcher.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/distributed_runner.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/distributed_runner.h"
    "${CMAKE_CURRENT_LIST_DIR}/io_service.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/io_service.h"
    "${CMAKE_CURRENT_LIST_DIR}/scheduler.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/scheduler.h"
)

# FIXME: move to osquery test
ADD_OSQUERY_TABLE_TEST(
  "${CMAKE_CURRENT_LIST_DIR}/tests/scheduler_tests.cpp"
)

ADD_OSQUERY_TEST(
  "${CMAKE_CURRENT_LIST_DIR}/tests/dispatcher_tests.cpp"
)
