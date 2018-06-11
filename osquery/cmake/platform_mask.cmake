#  Copyright (c) 2014-present, Facebook, Inc.
#  All rights reserved.
#
#  This source code is licensed under both the Apache 2.0 license (found in the
#  LICENSE file in the root directory of this source tree) and the GPLv2 (found
#  in the COPYING file in the root directory of this source tree).
#  You may select, at your option, one of the above-listed licenses.

# A final map from CMake build platform to a enum using for runtime detection.
# The goal is to provide a minimum set of compile code paths.
# See ./include/core.h for the enum class.
# POSIX   = 0x01
# WINDOWS = 0x02
# BSD     = 0x04
# LINUX   = 0x08 && POSIX
# OS X    = 0x10 && BSD && POSIX
# FREEBSD = 0x20 && BSD && POSIX
if(WINDOWS)
  math(EXPR PLATFORM_MASK "2")
elseif(LINUX)
  math(EXPR PLATFORM_MASK "1 + 8")
elseif(APPLE)
  math(EXPR PLATFORM_MASK "1 + 4 + 16")
elseif(FREEBSD)
  math(EXPR PLATFORM_MASK "1 + 4 + 32")
endif()