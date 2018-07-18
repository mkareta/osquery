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

#include <boost/filesystem.hpp>
#include <rocksdb/db.h>

#include <osquery/core/database/database.h>
#include <osquery/database/plugins/rocksdb.h>

namespace osquery {

enum class RocksdbError {
  UnexpectedValueType = 1,
  DatabaseIsCorrupted = 2,
};

class RocksdbDatabase final : public Database {
public:
  explicit RocksdbDatabase(std::string name) : Database(std::move(name)) {};
  ~RocksdbDatabase() override {}

  ExpectedSuccess<DatabaseError> destroyDB(const std::string& path) override;
  ExpectedSuccess<DatabaseError> open(const std::string& path) override;

  void close() override;

  //Low level access
  Expected<int32_t, DatabaseError> getInt32(const std::string& domain, const std::string& key) override;
  Expected<std::string, DatabaseError> getString(const std::string& domain, const std::string& key) override;

  ExpectedSuccess<DatabaseError> putInt32(const std::string& domain, const std::string& key, const int32_t value) override;
  ExpectedSuccess<DatabaseError> putString(const std::string& domain, const std::string& key, const std::string& value) override;

public: // Migration support
  // Raw bytes API, intented for usage during DB migration
  Expected<std::string, DatabaseError> getRawBytes(const std::string& domain, const std::string& key);
  ExpectedSuccess<DatabaseError> putRawBytes(const std::string& domain, const std::string& key, const std::string &value);

  // Function will be called with key/value pair, where value is raw bytes
  // caller should know how parse value
  // Func: void(const std::string& key, const char *data);
  template <typename Func>
  ExpectedSuccess<DatabaseError> enumarateDomain(const std::string& domain, Func function);

private:
  rocksdb::Options getOptions();
  std::vector<rocksdb::ColumnFamilyDescriptor> createDefaultColumnFamilies(const rocksdb::Options& options);
  ExpectedSuccess<DatabaseError> openInternal(const rocksdb::Options &options, const boost::filesystem::path &path);
  Expected<std::string, DatabaseError> getRawBytesInternal(rocksdb::ColumnFamilyHandle *handle, const std::string& key);
  ExpectedSuccess<DatabaseError> putRawBytesInternal(rocksdb::ColumnFamilyHandle *handle, const std::string& key, const std::string& value);
  ExpectedSuccess<DatabaseError> checkDbConnection();
  Expected<std::shared_ptr<rocksdb::ColumnFamilyHandle>, DatabaseError> getHandle(const std::string &domain);
private:

  bool in_panic_ = false;
  rocksdb::ReadOptions default_read_options_;
  rocksdb::WriteOptions default_write_options_;
  std::unique_ptr<rocksdb::DB> db_ = nullptr;
  std::unordered_map<std::string, std::shared_ptr<rocksdb::ColumnFamilyHandle>> handles_map_;
};

}
