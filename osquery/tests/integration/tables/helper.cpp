/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <gtest/gtest.h>
#include <unordered_set>

#include <boost/filesystem.hpp>
#include <boost/uuid/string_generator.hpp>

#include <osquery/tests/integration/tables/helper.h>
#include <osquery/core/conversions.h>

namespace osquery {

namespace fs = boost::filesystem;

bool IntMinMaxCheck::validate(std::string string) {
    auto cast_result = tryTo<int>(string);
    if (!cast_result) {
      return false;
    }
    int value = cast_result.get();
    return value >= min_ && value <= max_;
}

bool SpecificValuesCheck::validate(std::string string) {
  return set_.find(string) != set_.end();
}

QueryData IntegrationTableTest::execute_query(std::string query) {
  SQLInternal sql(query, false);
  return sql.rows();
}

bool IntegrationTableTest::validate_rows(const std::vector<Row>& rows, const ValidatatioMap& validation_map) {
  for (auto row : rows) {
    if (!validate_row(row, validation_map)) {
      return false;
    }
  }
  return true;
}

bool IntegrationTableTest::is_valid_hex(const std::string& value) {
  for (auto ch : value) {
    if (!std::isxdigit(ch)) {
      return false;
    }
  }
  return true;
}

bool IntegrationTableTest::validate_value_using_flags(const std::string& value, int flags) {
  if ((flags & NonEmpty) > 0) {
    if (value.length() == 0) {
      return false;
    }
  }

  if ((flags & NonNull)) {
    if (value == "null") {
      return false;
    }
  }

  if ((flags & NonZero)) {
    if (value == "0") {
      return false;
    }
  }

  if ((flags & IntType) > 0) {
    auto cast_result = tryTo<int>(value);
    if (!cast_result) {
      return false;
    }
    int intValue = cast_result.get();
    if ((flags & NonNegative) > 0) {
      if (intValue < 0) {
        return false;
      }
    }
  }

  if ((flags & FileOnDisk) > 0) {
    auto path = fs::path(value);
    auto status = fs::status(path);
    if (!fs::exists(status) || !fs::is_regular_file(status)) {
      return false;
    }
  }

  if ((flags & DirectoryOnDisk) > 0) {
    auto path = fs::path(value);
    auto status = fs::status(path);
    if (!fs::exists(status) || !fs::is_directory(status)) {
      return false;
    }
  }

  if ((flags & MD5) > 0) {
    if (!is_valid_hex(value) || value.size() != 32) {
      return false;
    }
  }

  if ((flags & SHA1) > 0) {
    if (!is_valid_hex(value) || value.size() != 40) {
      return false;
    }
  }

  if ((flags & SHA256) > 0) {
    if (!is_valid_hex(value) || value.size() != 64) {
      return false;
    }
  }

  if ((flags & Bool) > 0) {
    if (value.length() != 1 || (value != "1" && value != "0")) {
      return false;
    }
  }

  if ((flags & ValidUUID) > 0) {
    try {
      boost::uuids::string_generator()(value);
    } catch(...) {
      return false;
    }
  }

  return true;
}

bool IntegrationTableTest::validate_row(const Row& row, const ValidatatioMap& validation_map) {
  if (row.size() != validation_map.size()) {
    return false;
  }
  
  for (auto iter : validation_map) {
    std::string key = iter.first;
    auto row_data_iter = row.find(key);
    if (row_data_iter == row.end()) {
      return false;
    }

    std::string value = row_data_iter->second;

    ValidatatioDataType validator = iter.second;
    if (validator.type() == typeid(int)) {
      int flags = boost::get<int>(validator);
      if (!validate_value_using_flags(value, flags)) {
        return false;
      }
    } else {
      if (!boost::get<std::shared_ptr<DataCheck>>(validator)->validate(value)) {
        return false;
      }
    }
  }
  return true;
}

}

