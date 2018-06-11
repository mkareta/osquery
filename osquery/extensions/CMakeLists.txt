#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

# Generate the thrift intermediate/interface code.
set(THRIFT_IMPL_FILE impl_thrift.cpp)

if(LINUX OR DARWIN)
  if(DEFINED ENV{FBTHRIFT})
    add_custom_command(
      COMMAND
        LD_LIBRARY_PATH=${BUILD_DEPS}/lib:$ENV{LD_LIBRARY_PATH}
        ${THRIFT_COMPILER} --gen mstch_cpp2:stack_arguments,include_prefix=generated --gen py
        --templates "${BUILD_DEPS}/include/thrift/templates"
        -o "${CMAKE_BINARY_DIR}/generated"
        "${CMAKE_SOURCE_DIR}/osquery.thrift"
      DEPENDS "${CMAKE_SOURCE_DIR}/osquery.thrift"
      WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/generated"
      OUTPUT ${THRIFT_GENERATED_FILES}
    )
    add_definitions(-DFBTHRIFT -Wno-c++17-extensions)

    osquery_find_and_link_library(libosquery "libfolly")
    osquery_find_and_link_library(libosquery "libsnappy")
    osquery_find_and_link_library(libosquery "wangle")
    osquery_find_and_link_library(libosquery "mstch")
    osquery_find_and_link_library(libosquery "gssapi_krb5")
    osquery_find_and_link_library(libosquery "event")
    osquery_find_and_link_library(libosquery "double-conversion")

    # FBThrift static libraries.
    osquery_find_and_link_library(libosquery "thriftcpp2")
    osquery_find_and_link_library(libosquery "thrift-core")
    osquery_find_and_link_library(libosquery "thriftprotocol")
    osquery_find_and_link_library(libosquery "thriftfrozen2")
    osquery_find_and_link_library(libosquery "transport")
    osquery_find_and_link_library(libosquery "server")
    osquery_find_and_link_library(libosquery "concurrency")
    osquery_find_and_link_library(libosquery "security")
    osquery_find_and_link_library(libosquery "protocol")
    osquery_find_and_link_library(libosquery "async")
    osquery_find_and_link_library(libosquery "crypto")
    osquery_find_and_link_library(libosquery "ssl")

    set(THRIFT_IMPL_FILE impl_fbthrift.cpp)
  else()
    add_custom_command(
      COMMAND
        LD_LIBRARY_PATH=${BUILD_DEPS}/lib:$ENV{LD_LIBRARY_PATH}
        ${THRIFT_COMPILER} --gen cpp --gen py
        "${CMAKE_SOURCE_DIR}/osquery.thrift"
      DEPENDS "${CMAKE_SOURCE_DIR}/osquery.thrift"
      WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/generated"
      OUTPUT ${THRIFT_GENERATED_FILES}
    )
  endif()
else()
  add_custom_command(
    COMMAND
      ${THRIFT_COMPILER} --gen cpp --gen py
        "${CMAKE_SOURCE_DIR}/osquery.thrift"
    DEPENDS "${CMAKE_SOURCE_DIR}/osquery.thrift"
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}/generated"
    OUTPUT ${THRIFT_GENERATED_FILES}
  )
endif()

if(NOT WINDOWS)
  add_compile_options(
    -Wno-macro-redefined
  )
endif()

target_sources(libosquery
  PRIVATE
    "${THRIFT_GENERATED_FILES}"
    "${CMAKE_CURRENT_LIST_DIR}/${THRIFT_IMPL_FILE}"
    "${CMAKE_CURRENT_LIST_DIR}/extensions.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/interface.cpp"
    "${CMAKE_CURRENT_LIST_DIR}/interface.h"
)

ADD_OSQUERY_TEST(
  "${CMAKE_CURRENT_LIST_DIR}/tests/extensions_tests.cpp"
)
