#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

# List of table categories
set(TABLE_CATEGORIES
  "applications"
  "events"
  "networking"
  "system"
)

if(NOT SKIP_CARVER)
  list(APPEND TABLE_CATEGORIES "forensic")
endif()

# Apple/Darwin specific and applicable tables.
if(APPLE)
  set(TABLE_PLATFORM "darwin")

  target_link_libraries(libosquery_tables "-framework CoreFoundation")
  target_link_libraries(libosquery_tables "-framework CoreWLAN")
  target_link_libraries(libosquery_tables "-framework CoreGraphics")
  target_link_libraries(libosquery_tables "-framework Security")
  target_link_libraries(libosquery_tables "-framework OpenDirectory")
  target_link_libraries(libosquery_tables "-framework DiskArbitration")
  target_link_libraries(libosquery_tables "-framework ServiceManagement")


  osquery_find_and_link_library(libosquery_tables "libresolv.dylib")
  osquery_find_and_link_library(libosquery_tables "libxar.dylib")
  osquery_find_and_link_library(libosquery_tables "cups")
  osquery_find_and_link_library(libosquery_tables "iconv")
  osquery_find_and_link_library(libosquery_tables "bsm")
endif()

# FreeBSD specific and applicable tables.
if(FREEBSD)
  set(TABLE_PLATFORM "freebsd")

  include_directories("/usr/local/include/libxml2")

  osquery_find_and_link_library(libosquery_tables "procstat")
  osquery_find_and_link_library(libosquery_tables "util")
  osquery_find_and_link_library(libosquery_tables "kvm")
  osquery_find_and_link_library(libosquery_tables "elf")
endif()

# Windows specific and applicable tables.
if(WINDOWS)
  set(TABLE_PLATFORM "windows")

  # Additional Windows libraries
  osquery_find_and_link_library(libosquery_tables "crypt32.lib")
  osquery_find_and_link_library(libosquery_tables "Wintrust.lib")
  osquery_find_and_link_library(libosquery_tables "Advapi32.lib")
  osquery_find_and_link_library(libosquery_tables "Iphlpapi.lib")
  osquery_find_and_link_library(libosquery_tables "SetupAPI.lib")
  osquery_find_and_link_library(libosquery_tables "Ws2_32.lib")
  osquery_find_and_link_library(libosquery_tables "version.lib")
endif()

# Linux specific and applicable tables.
if(LINUX)
  set(TABLE_PLATFORM "linux")

  osquery_find_and_link_library(libosquery_tables "libresolv.so")
  osquery_find_and_link_library(libosquery_tables "cryptsetup")
  osquery_find_and_link_library(libosquery_tables "devmapper") 
  osquery_find_and_link_library(libosquery_tables "lvm2app") 
  osquery_find_and_link_library(libosquery_tables "lvm-internal")
  osquery_find_and_link_library(libosquery_tables "daemonclient")
  osquery_find_and_link_library(libosquery_tables "gcrypt")
  osquery_find_and_link_library(libosquery_tables "gpg-error")
  osquery_find_and_link_library(libosquery_tables "blkid")
  osquery_find_and_link_library(libosquery_tables "ip4tc")
  osquery_find_and_link_library(libosquery_tables "dpkg")
  osquery_find_and_link_library(libosquery_tables "lzma")
  osquery_find_and_link_library(libosquery_tables "bz2")
  osquery_find_and_link_library(libosquery_tables "rpm")
  osquery_find_and_link_library(libosquery_tables "rpmio")
  osquery_find_and_link_library(libosquery_tables "popt")
  osquery_find_and_link_library(libosquery_tables "db")
endif()

if(POSIX)
  osquery_find_and_link_library(libosquery_tables "augeas")
  osquery_find_and_link_library(libosquery_tables "fa")
  osquery_find_and_link_library(libosquery_tables "xml2")
endif()

# For each general category, add the C++ files in the base.
foreach(CATEGORY ${TABLE_CATEGORIES})
  file(GLOB OSQUERY_${CATEGORY}_TABLES
    "${CMAKE_CURRENT_LIST_DIR}/${CATEGORY}/*.[cpm]*"
    "${CMAKE_CURRENT_LIST_DIR}/${CATEGORY}/${TABLE_PLATFORM}/*.[cpm]*"
  )
  if(OSQUERY_${CATEGORY}_TABLES)
    darwin_target_sources(libosquery_tables
      PRIVATE
        ${OSQUERY_${CATEGORY}_TABLES}
    )
  endif()

  # POSIX tables.
  if(POSIX)
    file(GLOB OSQUERY_${CATEGORY}_POSIX_TABLES 
      "${CMAKE_CURRENT_LIST_DIR}/${CATEGORY}/posix/*.[cpm]*"
    )
    if(OSQUERY_${CATEGORY}_POSIX_TABLES)
      target_sources(libosquery_tables
        PRIVATE
          ${OSQUERY_${CATEGORY}_POSIX_TABLES}
      )
    endif()

    # Add posix table tests.
    file(GLOB POSIX_OSQUERY_${CATEGORY}_TABLES_TESTS
      "${CMAKE_CURRENT_LIST_DIR}/${CATEGORY}/posix/tests/*.[cpm]*"
    )
    ADD_OSQUERY_TABLE_TEST(${POSIX_OSQUERY_${CATEGORY}_TABLES_TESTS})
  endif()

  # Table implementations shared by FreeBSD and Linux
  if(FREEBSD OR LINUX)
    file(GLOB OSQUERY_${CATEGORY}_FREENUX_TABLES 
      "${CMAKE_CURRENT_LIST_DIR}/${CATEGORY}/freenux/*.[cpm]*"
    )
    if(OSQUERY_${CATEGORY}_FREENUX_TABLES)
      target_sources(libosquery_tables
        PRIVATE
          ${OSQUERY_${CATEGORY}_FREENUX_TABLES}
      )
    endif()
  endif()

  # Add the table tests.
  file(GLOB OSQUERY_${CATEGORY}_TABLES_TESTS
    "${CMAKE_CURRENT_LIST_DIR}/${CATEGORY}/tests/*.[cpm]*"
    "${CMAKE_CURRENT_LIST_DIR}/${CATEGORY}/${TABLE_PLATFORM}/tests/*.[cpm]*"
  )
  ADD_OSQUERY_TABLE_TEST(${OSQUERY_${CATEGORY}_TABLES_TESTS})
endforeach()

file(GLOB OSQUERY_UTILITY_TABLES "${CMAKE_CURRENT_LIST_DIR}/utility/*.cpp")
target_sources(libosquery_tables
  PRIVATE
    ${OSQUERY_UTILITY_TABLES}
)

if(NOT SKIP_AWS AND LINUX)
  file(GLOB OSQUERY_CLOUD_TABLES "${CMAKE_CURRENT_LIST_DIR}/cloud/*.[cpm]*")
  target_sources(libosquery_tables
    PRIVATE
      ${OSQUERY_CLOUD_TABLES}
  )
  
  file(GLOB OSQUERY_CLOUD_TABLES_TESTS "${CMAKE_CURRENT_LIST_DIR}/cloud/tests/*.[cpm]*")
  if(OSQUERY_CLOUD_TABLES_TESTS)
    ADD_OSQUERY_TABLE_TEST(${OSQUERY_CLOUD_TABLES_TESTS})
  endif()

  osquery_find_and_link_library(libosquery_tables "aws-cpp-sdk-ec2")
endif()

if(NOT SKIP_TSK AND POSIX)
  file(GLOB OSQUERY_TSK_TABLES "${CMAKE_CURRENT_LIST_DIR}/sleuthkit/*.[cpm]*")
  target_sources(libosquery_tables
    PRIVATE
      ${OSQUERY_TSK_TABLES}
  )

  file(GLOB OSQUERY_TSK_TABLES_TESTS "${CMAKE_CURRENT_LIST_DIR}/sleuthkit/tests/*.[cpm]*")
  if(OSQUERY_TSK_TABLES_TESTS)
    ADD_OSQUERY_TABLE_TEST(${OSQUERY_TSK_TABLES_TESTS})
  endif()

  osquery_find_and_link_library(libosquery_tables "tsk")
endif()

if(NOT SKIP_YARA AND POSIX)
  file(GLOB OSQUERY_YARA_TABLES "${CMAKE_CURRENT_LIST_DIR}/yara/*.[cpm]*")
  target_sources(libosquery_tables
    PRIVATE
      ${OSQUERY_YARA_TABLES}
  )

  file(GLOB OSQUERY_YARA_TABLES_TESTS "${CMAKE_CURRENT_LIST_DIR}/yara/tests/*.[cpm]*")
  if(OSQUERY_YARA_TABLES_TESTS)
    ADD_OSQUERY_TABLE_TEST(${OSQUERY_YARA_TABLES_TESTS})
  endif()

  osquery_find_and_link_library(libosquery_tables "yara")
endif()

if(NOT SKIP_LLDPD AND POSIX)
  file(GLOB OSQUERY_LLDPD_TABLES "${CMAKE_CURRENT_LIST_DIR}/lldpd/*.[cpm]*")
  target_sources(libosquery_tables
    PRIVATE
      ${OSQUERY_LLDPD_TABLES}
  )

  file(GLOB OSQUERY_LLDPD_TABLES_TESTS "${CMAKE_CURRENT_LIST_DIR}/lldpd/tests/*.[cpm]*")
  if(OSQUERY_LLDPD_TABLES_TESTS)
    ADD_OSQUERY_TABLE_TEST(${OSQUERY_LLDPD_TABLES_TESTS})
  endif()

  osquery_find_and_link_library(libosquery_tables "lldpctl")
endif()
