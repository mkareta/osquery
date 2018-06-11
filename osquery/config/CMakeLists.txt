#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

target_sources(libosquery
  PRIVATE
    "${CMAKE_CURRENT_LIST_DIR}/additional_parsers/auto_constructed_tables.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/additional_parsers/auto_constructed_tables.h"
    "${CMAKE_CURRENT_LIST_DIR}/config.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/packs.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/parsers/decorators.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/parsers/decorators.h"
    "${CMAKE_CURRENT_LIST_DIR}/parsers/events_parser.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/parsers/feature_vectors.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/parsers/feature_vectors.h"
    "${CMAKE_CURRENT_LIST_DIR}/parsers/file_paths.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/parsers/kafka_topics.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/parsers/kafka_topics.h"
    "${CMAKE_CURRENT_LIST_DIR}/parsers/logger.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/parsers/logger.h"
    "${CMAKE_CURRENT_LIST_DIR}/parsers/options.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/parsers/prometheus_targets.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/parsers/prometheus_targets.h"
    "${CMAKE_CURRENT_LIST_DIR}/parsers/tests"
    "${CMAKE_CURRENT_LIST_DIR}/parsers/views.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/plugins/filesystem_config.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/plugins/tls_config.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/plugins/tls_config.h"
    "${CMAKE_CURRENT_LIST_DIR}/update.cpp"
)

file(GLOB OSQUERY_CONFIG_TESTS "tests/config_tests.cpp")
ADD_OSQUERY_TEST(${OSQUERY_CONFIG_TESTS})

# The packs tests will attempt to execute SQL, they must be additional
file(GLOB OSQUERY_PACKS_TESTS "tests/packs_tests.cpp")
ADD_OSQUERY_TEST(${OSQUERY_PACKS_TESTS})

file(GLOB OSQUERY_CONFIG_PLUGIN_TESTS "*/tests/*.cpp")
ADD_OSQUERY_TEST(${OSQUERY_CONFIG_PLUGIN_TESTS})
