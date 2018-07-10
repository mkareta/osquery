/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/core/database/in_memory_database.h>
#include <osquery/logger.h>

namespace osquery {

void InMemoryDatabase::close() {
  VLOG(1) << "Closing db... ";
  assert(!is_open_ && "database is not open");
  is_open_ = false;
  destroyDB("");
}

ExpectedSuccess<DatabaseError> InMemoryDatabase::destroyDB(const std::string& _) {
  VLOG(1) << "Destroying in memory db";
  string_storage_.clear();
  int_storage_.clear();
  return Success();
}

ExpectedSuccess<DatabaseError> InMemoryDatabase::open(const std::string& _) {
  assert(is_open_ && "database is already open");
  is_open_ = true;
  return Success();
}

template<typename T>
Expected<T, DatabaseError> InMemoryDatabase::getValueFromStorage(const std::unordered_map<std::string, std::unique_ptr<InMemoryStorage<T>>> &storage, const std::string& domain, const std::string& key) {
  assert(is_open_ && "database is not open");
  auto storage_iter = storage.find(domain);
  if (storage_iter == storage.end()) {
    return createError(DatabaseError::UnknownDomain, "Can't find domain: ") << domain;
  }
  return storage_iter->second->get(key);
}

template<typename T>
ExpectedSuccess<DatabaseError> InMemoryDatabase::putValueToStorage(const std::unordered_map<std::string, std::unique_ptr<InMemoryStorage<T>>> &storage, const std::string& domain, const std::string& key, const T& value) {
  assert(is_open_ && "database is not open");
  auto storage_iter = storage.find(domain);
  if (storage_iter == storage.end()) {
    return createError(DatabaseError::UnknownDomain, "Can't find domain: ") << domain;
  }
  storage_iter->second->put(key, value);
  return Success();
}

Expected<std::string, DatabaseError> InMemoryDatabase::getString(const std::string& domain, const std::string& key) {
  return getValueFromStorage(string_storage_, domain, key);
}

ExpectedSuccess<DatabaseError> InMemoryDatabase::putString(const std::string& domain, const std::string& key, const std::string& value) {
  return putValueToStorage(string_storage_, domain, key, value);
}

Expected<int, DatabaseError> InMemoryDatabase::getInt(const std::string& domain, const std::string& key) {
  return getValueFromStorage(int_storage_, domain, key);
}

ExpectedSuccess<DatabaseError> InMemoryDatabase::putInt(const std::string& domain, const std::string& key, const int value) {
  return putValueToStorage(int_storage_, domain, key, value);
}

}
