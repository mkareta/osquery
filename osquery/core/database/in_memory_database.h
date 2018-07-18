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

#include <unordered_map>

#include <osquery/core/database/database.h>

namespace osquery {

template <typename StorageType>
class InMemoryStorage final {
public:
  void put(const std::string &key, const StorageType value) {
    storage_[key] = value;
  }
  Expected<StorageType, DatabaseError> get(const std::string &key) const {
    auto iter = storage_.find(key);
    if (iter != storage_.end()) {
      return iter->second;
    }
    return createError(DatabaseError::KeyNotFound, "Can't find value for key ") << key;
  }
private:
  std::unordered_map<std::string, StorageType> storage_;
};

class InMemoryDatabase final : public Database {
public:
  explicit InMemoryDatabase(std::string name) : Database(std::move(name)) {};
  ~InMemoryDatabase() override {}

  ExpectedSuccess<DatabaseError> destroyDB(const std::string& path) override;
  ExpectedSuccess<DatabaseError> open(const std::string& path) override;

  void close() override;

  //Low level access
  Expected<int32_t, DatabaseError> getInt32(const std::string& domain, const std::string& key) override;
  Expected<std::string, DatabaseError> getString(const std::string& domain, const std::string& key) override;

  ExpectedSuccess<DatabaseError> putInt32(const std::string& domain, const std::string& key, const int32_t value) override;
  ExpectedSuccess<DatabaseError> putString(const std::string& domain, const std::string& key, const std::string& value) override;

private:
  template<typename T>
  Expected<T, DatabaseError> getValueFromStorage(const std::unordered_map<std::string, std::unique_ptr<InMemoryStorage<T>>> &storage, const std::string& domain, const std::string& key);
  template<typename T>
  ExpectedSuccess<DatabaseError> putValueToStorage(const std::unordered_map<std::string, std::unique_ptr<InMemoryStorage<T>>> &storage, const std::string& domain, const std::string& key, const T& value);
private:
  bool is_open_;
  std::unordered_map<std::string, std::unique_ptr<InMemoryStorage<std::string>>> string_storage_;
  std::unordered_map<std::string, std::unique_ptr<InMemoryStorage<int32_t>>> int_storage_;
};

}
