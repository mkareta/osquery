/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/database.h>
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
  storage_.clear();
  return Success();
}

ExpectedSuccess<DatabaseError> InMemoryDatabase::open(const std::string& _) {
  assert(is_open_ && "database is already open");
  for (const auto &domain : kDomains) {
    storage_[domain] = std::make_unique<InMemoryStorage<boost::variant<std::string, int32_t>>>();
  }
  is_open_ = true;
  return Success();
}

Error<DatabaseError> InMemoryDatabase::domainNotFoundError(const std::string& domain) {
  return createError(DatabaseError::DomainNotFound, "Can't find domain: ") << domain;
}

template<typename T>
Expected<T, DatabaseError> InMemoryDatabase::getValue(const std::string& domain, const std::string& key) {
  assert(is_open_ && "database is not open");
  auto storage_iter = storage_.find(domain);
  if (storage_iter == storage_.end()) {
    return domainNotFoundError(domain);
  }
  std::lock_guard<std::mutex> lock(storage_iter->second->getMutex());
  auto result = storage_iter->second->get(key);
  if (result) {
    boost::variant<std::string, int32_t> value = result.take();
    if (value.type() == typeid(T)) {
      return boost::get<T>(value);
    } else {
      auto error = createError(DatabaseError::KeyNotFound, "Requested wrong type for: ") << domain << ":" << key << " stored type: " << value.type().name() << " requested type " << typeid(T).name();
      LOG(ERROR) << error.getFullMessageRecursive();
#ifdef DEBUG
      assert(false && error.getFullMessageRecursive().c_str());
#endif
      return std::move(error);
    }
  }
  return result.takeError();
}

template<typename T>
ExpectedSuccess<DatabaseError> InMemoryDatabase::putValue(const std::string& domain, const std::string& key, const T& value) {
  assert(is_open_ && "database is not open");
  auto storage_iter = storage_.find(domain);
  if (storage_iter == storage_.end()) {
    return domainNotFoundError(domain);
  }
  std::lock_guard<std::mutex> lock(storage_iter->second->getMutex());
#ifdef DEBUG
  {
    auto result = storage_iter->second->get(key);
    assert(result && result.get().type() == typeid(T) && "changing type is not allowed");
  }
#endif
  storage_iter->second->put(key, value);
  return Success();
}

Expected<std::string, DatabaseError> InMemoryDatabase::getString(const std::string& domain, const std::string& key) {
  return getValue<std::string>(domain, key);
}

ExpectedSuccess<DatabaseError> InMemoryDatabase::putString(const std::string& domain, const std::string& key, const std::string& value) {
  return putValue(domain, key, value);
}

Expected<int, DatabaseError> InMemoryDatabase::getInt32(const std::string& domain, const std::string& key) {
  return getValue<int32_t>(domain, key);
}

ExpectedSuccess<DatabaseError> InMemoryDatabase::putInt32(const std::string& domain, const std::string& key, const int32_t value) {
  return putValue(domain, key, value);
}

Expected<std::vector<std::string>, DatabaseError> InMemoryDatabase::getKeys(const std::string& domain, const std::string& prefix) {
  assert(is_open_ && "database is not open");
  auto storage_iter = storage_.find(domain);
  if (storage_iter == storage_.end()) {
    return domainNotFoundError(domain);
  }
  return storage_iter->second->getKeys(prefix);
}

ExpectedSuccess<DatabaseError> InMemoryDatabase::putStringsUnsafe(const std::string& domain, std::vector<std::pair<std::string, std::string>>& data) {
  assert(is_open_ && "database is not open");
  auto storage_iter = storage_.find(domain);
  if (storage_iter == storage_.end()) {
    return domainNotFoundError(domain);
  }
  std::lock_guard<std::mutex> lock(storage_iter->second->getMutex());
  for (const auto& pair : data) {
    storage_iter->second->put(pair.first, pair.second);
  }
}

}

