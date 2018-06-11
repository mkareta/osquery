#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

# Add all and extra for osquery code.
if(CLANG AND POSIX)
  add_compile_options(
    -Wall
    -Wextra
    -pedantic
    -Wuseless-cast
    -Wno-c99-extensions
    -Wno-zero-length-array
    -Wno-unused-parameter
    -Wno-gnu-case-range
    -Weffc++
  )
  if(NOT FREEBSD)
    add_compile_options(
      -Wshadow-all
      -Wno-shadow-field
    )
  endif()
endif()
