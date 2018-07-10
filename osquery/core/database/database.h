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

#include <osquery/error.h>
#include <osquery/expected.h>

namespace osquery {

enum class DatabaseError {
  Unknown = 1,
  FailToReadValue = 2,
  DatabasePathDoesNotExists = 3,
  DatabaseIsCorrupted = 4,
  FailToOpenDatabase = 5,
  FailToDestroyDB = 6,
  DatabaseIsNotOpen = 7,
  UnknownDomain = 8,
  FailToReadData = 9,
  FailToWriteData = 10,
  NotFound = 11,
};

class Database {
public:
  explicit Database(std::string name) {};
  virtual ~Database() {};

  virtual ExpectedSuccess<DatabaseError> open(const std::string& path) = 0;
  virtual ExpectedSuccess<DatabaseError> destroyDB(const std::string& path) = 0;
  virtual void close() = 0;

  // Return default value in case of NotFound error
  Expected<int, DatabaseError> getIntOr(const std::string& domain, const std::string& key, const int default_value = 0);
  Expected<std::string, DatabaseError> getStringOr(const std::string& domain, const std::string& key, const std::string default_value = "");

  virtual Expected<int, DatabaseError> getInt(const std::string& domain, const std::string& key);
  virtual Expected<std::string, DatabaseError> getString(const std::string& domain, const std::string& key) = 0;

  virtual ExpectedSuccess<DatabaseError> putInt(const std::string& domain, const std::string& key, const int value);
  virtual ExpectedSuccess<DatabaseError> putString(const std::string& domain, const std::string& key, const std::string& value) = 0;

};

}

