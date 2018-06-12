#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

# Please do not add new libraries to this list
# New library *should* be added together with code that 
# require it

if(WINDOWS)
  if(DEFINED ENV{DEBUG})
    set(WB_KEY "sgd")
    set(WO_KEY "_dbg")
    set(WT_KEY "d_dbg")
  else()
    set(WB_KEY "s")
    set(WO_KEY "")
  endif()
  osquery_find_and_link_library(libosquery "ntdll.lib")
  osquery_find_and_link_library(libosquery "ws2_32.lib")
  osquery_find_and_link_library(libosquery "iphlpapi.lib")
  osquery_find_and_link_library(libosquery "netapi32.lib")
  osquery_find_and_link_library(libosquery "rpcrt4.lib")
  osquery_find_and_link_library(libosquery "shlwapi.lib")
  osquery_find_and_link_library(libosquery "version.lib")
  osquery_find_and_link_library(libosquery "Wtsapi32.lib")
  osquery_find_and_link_library(libosquery "wbemuuid.lib")
  osquery_find_and_link_library(libosquery "taskschd.lib")
  osquery_find_and_link_library(libosquery "dbghelp.lib")
  osquery_find_and_link_library(libosquery "dbgeng.lib")
  osquery_find_and_link_library(libosquery "libboost_system-mt-${WB_KEY}")
  osquery_find_and_link_library(libosquery "libboost_regex-mt-${WB_KEY}")
  osquery_find_and_link_library(libosquery "libboost_filesystem-mt-${WB_KEY}")
  osquery_find_and_link_library(libosquery "libboost_context-mt-${WB_KEY}")
  osquery_find_and_link_library(libosquery "rocksdb${WO_KEY}")
  osquery_find_and_link_library(libosquery "thriftmt${WT_KEY}")
  osquery_find_and_link_library(libosquery "gflags_static${WO_KEY}")
  osquery_find_and_link_library(libosquery "ssleay32")
  osquery_find_and_link_library(libosquery "eay32")
  osquery_find_and_link_library(libosquery "zlibstatic")

  # Enable control flow guard
  target_link_libraries(libosquery "-guard:cf")
else()
  osquery_find_and_link_library(libosquery "pthread")
  osquery_find_and_link_library(libosquery "z")
  osquery_find_and_link_library(libosquery "gflags")
  osquery_find_and_link_library(libosquery "thrift")
endif()

if(APPLE OR LINUX)
  osquery_find_and_link_library(libosquery "dl")
  osquery_find_and_link_library(libosquery "rocksdb_lite")
elseif(FREEBSD)
  osquery_find_and_link_library(libosquery "icuuc")
  osquery_find_and_link_library(libosquery "linenoise")
  osquery_find_and_link_library(libosquery "rocksdb-lite")
endif()

if(POSIX)
  osquery_find_and_link_library(libosquery "boost_system")
  osquery_find_and_link_library(libosquery "boost_filesystem")
  osquery_find_and_link_library(libosquery "boost_thread")
  osquery_find_and_link_library(libosquery "boost_context")
  osquery_find_and_link_library(libosquery "boost_regex")
endif()

if(LINUX OR FREEBSD)
  osquery_find_and_link_library(libosquery "librt")
  osquery_find_and_link_library(libosquery "libc")
endif()

# Remaining additional development libraries.
osquery_find_and_link_library(libosquery "glog${WO_KEY}")

if(POSIX)
  # Hashing methods in core use libcrypto.
  osquery_find_and_link_library(libosquery "crypto")

  osquery_find_and_link_library(libosquery "ssl")
  osquery_find_and_link_library(libosquery "pthread")
  osquery_find_and_link_library(libosquery "magic")
endif()

if(APPLE)
  osquery_find_and_link_library(libosquery "lzma")
else()
  if(POSIX)
    osquery_find_and_link_library(libosquery "lzma")
  endif()
endif()

osquery_find_and_link_library(libosquery "bz2")

# The platform-specific SDK + core linker flags.
if(POSIX)
  target_link_libraries(libosquery "-rdynamic")
endif()

if(APPLE)
  target_link_libraries(libosquery "-Wl,-dead_strip")
  target_link_libraries(libosquery "-mmacosx-version-min=${OSX_VERSION_MIN}")
  target_link_libraries(libosquery "-Wl,-cache_path_lto,${CMAKE_BINARY_DIR}/ltocache")
  target_link_libraries(libosquery "-Wl,-no_weak_imports")
elseif(LINUX OR FREEBSD)
  target_link_libraries(libosquery "-Wl,-zrelro -Wl,-znow")
  if(NOT DEFINED ENV{SANITIZE} AND NOT DEFINED ENV{DEBUG})
    target_link_libraries(libosquery "-pie")
  endif()
endif()

if(LINUX)
  osquery_find_and_link_library(libosquery "uuid")
  if(NOT DEFINED ENV{OSQUERY_BUILD_LINK_SHARED})
    target_link_libraries(libosquery "-static-libstdc++")
    target_link_libraries(libosquery "-static-libstdc++")
  endif()
  # For Ubuntu/CentOS packages add the build SHA1.
  target_link_libraries(libosquery "-Wl,--build-id")
  if (CLANG AND DEPS)
    # If using GCC, libgcc_s may be needed.
    target_link_libraries(libosquery "-fuse-ld=lld")
    osquery_find_and_link_library(libosquery "c++")
    osquery_find_and_link_library(libosquery "c++abi")
    osquery_find_and_link_library(libosquery "unwind")
    if(NOT CMAKE_CXX_COMPILER_VERSION VERSION_LESS 5.0.0)
      target_link_libraries(libosquery "-Wl,--thinlto-cache-dir=${CMAKE_BINARY_DIR}/cache")
      target_link_libraries(libosquery "-Wl,--thinlto-cache-policy,cache_size_bytes=2g")
    endif()
    osquery_find_and_link_library(libosquery "-B${BUILD_DEPS}/legacy/lib")
  endif()
endif()