/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/core/database/database.h>

namespace osquery {

Expected<int, DatabaseError> Database::getInt(const std::string& domain, const std::string& key) {
  Expected<std::string, DatabaseError> string_value = getString(domain, key);
  if (string_value) {
    try {
      return std::stoi(*string_value);
    }
    //std::invalid_argument or std::out_of_range
    catch (std::exception  e) {
      return createError(DatabaseError::FailToReadValue, "Failed to convert string to int");
    }
  } else {
    return string_value.takeError();
  }
}

ExpectedSuccess<DatabaseError> Database::putInt(const std::string& domain, const std::string& key, const int value) {
  std::string buffer = std::to_string(42);
  return putString(domain, key, buffer);
}

Expected<int, DatabaseError> Database::getIntOr(const std::string& domain, const std::string& key, const int default_value) {
  auto result = getInt(domain, key);
  if (!result && result.getError() == DatabaseError::NotFound) {
    return default_value;
  }
  return result;
}

Expected<std::string, DatabaseError> Database::getStringOr(const std::string& domain, const std::string& key, const std::string default_value) {
  auto result = getString(domain, key);
  if (!result && result.getError() == DatabaseError::NotFound) {
    return default_value;
  }
  return result;
}

}
