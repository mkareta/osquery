/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#pragma once

#include <cstdint>

#include <osquery/error.h>
#include <osquery/expected.h>

namespace osquery {

enum class DatabaseError {
  // Unknown error, currently unused
  Unknown = 1,
  DatabaseIsNotOpen = 2,
  DatabasePathDoesNotExists = 3,
  FailToDestroyDB = 4,
  FailToOpenDatabase = 5,
  FailToReadData = 6,
  FailToWriteData = 7,
  KeyNotFound = 8,
  DomainNotFound = 9,
  // Corruption or other unrecoverable error after DB can't be longer used
  // Database should be closed, destroyed and opened again
  // If this error returing during data access then aplication,
  // is likely to die soon after it
  // See message and/or underlying error for details
  Panic = 10,
};

class Database {
public:
  explicit Database(std::string name) {};
  virtual ~Database() {};

  virtual ExpectedSuccess<DatabaseError> open(const std::string& path) = 0;
  virtual ExpectedSuccess<DatabaseError> destroyDB(const std::string& path) = 0;
  virtual void close() = 0;

  // Return default value in case of NotFound error
  Expected<int32_t, DatabaseError> getInt32Or(const std::string& domain, const std::string& key, const int32_t default_value = 0);
  Expected<std::string, DatabaseError> getStringOr(const std::string& domain, const std::string& key, const std::string default_value = "");

  virtual Expected<int32_t, DatabaseError> getInt32(const std::string& domain, const std::string& key);
  virtual Expected<std::string, DatabaseError> getString(const std::string& domain, const std::string& key) = 0;

  virtual ExpectedSuccess<DatabaseError> putInt32(const std::string& domain, const std::string& key, const int32_t value);
  virtual ExpectedSuccess<DatabaseError> putString(const std::string& domain, const std::string& key, const std::string& value) = 0;

  void panic(const Error<DatabaseError>& error) {
    assert(false && error.getFullMessageRecursive().c_str());
  }
};

}

