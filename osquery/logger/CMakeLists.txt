#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

target_sources(libosquery
  PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/logger.cpp"
)

target_sources(libosquery
  PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/plugins/buffered.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/plugins/buffered.h"
    "${CMAKE_CURRENT_LIST_DIR}/plugins/filesystem_logger.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/plugins/tls_logger.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/plugins/tls_logger.h"
    "${CMAKE_CURRENT_LIST_DIR}/plugins/stdout.cpp"
)

if(LINUX)
  target_sources(libosquery
    PRIVATE
      "${CMAKE_CURRENT_LIST_DIR}/plugins/syslog_logger.cpp"
  )
  ADD_OSQUERY_TEST(
    "${CMAKE_CURRENT_LIST_DIR}/plugins/tests/syslog_logger_tests.cpp"
  )
elseif(WINDOWS)
  target_sources(libosquery
    PRIVATE
      "${CMAKE_CURRENT_LIST_DIR}/plugins/windows_event_log.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/plugins/windows_event_log.h"
  )
endif()

# FIXME 
# Use ADD_OSQUERY_TEST after test fix
# There is a significant difference between the Glog-backed filesystem plugin
# and others, which use a Glog sink. They must be tested in tandem.
ADD_OSQUERY_TABLE_TEST(
  "${CMAKE_CURRENT_LIST_DIR}/plugins/tests/filesystem_logger_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/plugins/tests/buffered_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/plugins/tests/tls_logger_tests.cpp"
  "${CMAKE_CURRENT_LIST_DIR}/tests/logger_tests.cpp"
)

ADD_OSQUERY_BENCHMARK(
  "${CMAKE_CURRENT_LIST_DIR}/benchmarks/logger_benchmarks.cpp"
)

if(NOT SKIP_KAFKA AND NOT WINDOWS AND NOT FREEBSD)
  target_sources(libosquery
    PRIVATE
      "${CMAKE_CURRENT_LIST_DIR}/plugins/kafka_producer.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/plugins/kafka_producer.h"
  )

  osquery_find_and_link_library(libosquery "rdkafka")

  ADD_OSQUERY_TEST(
    "${CMAKE_CURRENT_LIST_DIR}/plugins/tests/kafka_producer_tests.cpp"
  )
endif()

if(NOT SKIP_AWS)
  target_sources(libosquery
    PRIVATE
      "${CMAKE_CURRENT_LIST_DIR}/plugins/aws_firehose.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/plugins/aws_firehose.h"
      "${CMAKE_CURRENT_LIST_DIR}/plugins/aws_kinesis.cpp"
      "${CMAKE_CURRENT_LIST_DIR}/plugins/aws_kinesis.h"
      "${CMAKE_CURRENT_LIST_DIR}/plugins/aws_log_forwarder.h"
  )

  ADD_OSQUERY_TEST(
    "${CMAKE_CURRENT_LIST_DIR}/plugins/tests/aws_logger_tests.cpp"
  )

  if(WINDOWS)
    osquery_find_and_link_library(libosquery "UserEnv.lib")
    osquery_find_and_link_library(libosquery "bcrypt.lib")
    osquery_find_and_link_library(libosquery "wevtapi.lib")
  endif()

  osquery_find_and_link_library(libosquery "aws-cpp-sdk-kinesis")
  osquery_find_and_link_library(libosquery "aws-cpp-sdk-firehose")
endif()
