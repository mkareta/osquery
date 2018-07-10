/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/core/database/rocksdb_database.h>
#include <osquery/logger.h>

namespace osquery {

DECLARE_int32(rocksdb_write_buffer);
DECLARE_int32(rocksdb_merge_number);
DECLARE_int32(rocksdb_background_flushes);
DECLARE_uint64(rocksdb_buffer_blocks);

static const int kLogMessageBufferSize = 512;
static const int kMaxLogMessageBufferSize = 65536;

class RocksDBLogger : public rocksdb::Logger {
 public:
  using rocksdb::Logger::Logv;

  /// Capture only error logs from RocksDB and forward them.
  void Logv(const char* format, va_list ap) override {
    char buffer[kLogMessageBufferSize] = {0};
    // Try to use local buffer for log message
    // and fallback to heap buffer in case of failure
    int size = vsnprintf(buffer, kMaxLogMessageBufferSize, format, ap);
    if (size > kLogMessageBufferSize - 1) {
      // Message longer than kMaxLogMessageBufferSize will be truncated
      int heap_buffer_size = std::min(kMaxLogMessageBufferSize, size);
      char* heap_buffer = static_cast<char*>(malloc(heap_buffer_size));
      vsnprintf(heap_buffer, heap_buffer_size, format, ap);
      LOG(ERROR) << "RocksDB Error: " << heap_buffer;
      free(heap_buffer);
    } else {
      LOG(ERROR) << "RocksDB Error: " << buffer;
    }
  };
};

rocksdb::Options RocksdbDatabase::getOptions() {
  rocksdb::Options options;
  options.OptimizeForSmallDb();

  // Set meta-data (mostly) handling options.
  options.create_if_missing = true;
  options.create_missing_column_families = true;
  options.error_if_exists = false;
  options.paranoid_checks = true;

  options.info_log = std::make_shared<RocksDBLogger>();

  // Please review RocksDBLogger if you want to modify this line!
  options.info_log_level = rocksdb::ERROR_LEVEL;

  options.max_open_files = 128;

  options.log_file_time_to_roll = 0;
  options.keep_log_file_num = 10;
  options.max_log_file_size = 1024 * 1024 * 1;

  options.stats_dump_period_sec = 0;
  options.max_manifest_file_size = 1024 * 500;

  // Performance and optimization settings.
  options.compression = rocksdb::kNoCompression;
  options.compaction_style = rocksdb::kCompactionStyleLevel;
  options.arena_block_size = (4 * 1024);
  options.write_buffer_size = (4 * 1024) * FLAGS_rocksdb_buffer_blocks;
  options.max_write_buffer_number =
      static_cast<int>(FLAGS_rocksdb_write_buffer);
  options.min_write_buffer_number_to_merge =
      static_cast<int>(FLAGS_rocksdb_merge_number);

  return options;
}

std::vector<rocksdb::ColumnFamilyDescriptor> RocksdbDatabase::createDefaultColumnFamilies(
    const rocksdb::Options& options) {
  std::vector<rocksdb::ColumnFamilyDescriptor> column_families;
  column_families.push_back(rocksdb::ColumnFamilyDescriptor(
      rocksdb::kDefaultColumnFamilyName, options));
  for (const auto& cf_name : kDomains) {
    column_families.push_back(
        rocksdb::ColumnFamilyDescriptor(cf_name, options));
  }
  return column_families;
}

void RocksdbDatabase::close() {
  VLOG(1) << "Closing db... ";
  assert(db_ == nullptr && "db connection is not open");
  if (db_ != nullptr) {
    handles_map_.clear();
    db_ = nullptr;
  }
}

ExpectedSuccess<DatabaseError> RocksdbDatabase::destroyDB(const std::string& path) {
  VLOG(1) << "Destroying db at path " << path;

  assert(db_ == nullptr && "can't destroy db while it in use");
  if (db_ != nullptr) {
    // Try to recover in case if db was open
    close();
  }

  rocksdb::Options options = getOptions();
  auto db_path = boost::filesystem::path(path).make_preferred();
  auto destroy_status = rocksdb::DestroyDB(db_path.string(), options);
  if (!destroy_status.ok()) {
    return createError(DatabaseError::FailToDestroyDB,
                       "Fail to destroy db: ") << destroy_status.ToString();
  }
  return Success();
}

ExpectedSuccess<DatabaseError> RocksdbDatabase::openInternal(const rocksdb::Options &options, const boost::filesystem::path &path) {
  VLOG(1) << "Will try to open db at path: " << path.string();
  auto column_families = createDefaultColumnFamilies(options);
  auto db_path = boost::filesystem::path(path).make_preferred();
  auto db_path_status = boost::filesystem::status(db_path);
  if (!boost::filesystem::exists(db_path_status)) {
    return createError(DatabaseError::DatabasePathDoesNotExists,
                       "database path doesn't exist");
  }
  std::vector<rocksdb::ColumnFamilyHandle*> raw_handles;
  rocksdb::DB* raw_db_handle = nullptr;
  auto open_status = rocksdb::DB::Open(options, db_path.string(), column_families, &raw_handles, &raw_db_handle);
  if (open_status.IsCorruption()) {
    return createError(DatabaseError::DatabaseIsCorrupted,
                       "database is corrrupted: ") << open_status.ToString();
  }
  if (!open_status.ok()) {
    return createError(DatabaseError::FailToOpenDatabase,
                       "Fail to open database: ") << open_status.ToString();
  }

  assert(column_families.size() == raw_handles.size() && "can't map column families to handles");
  if (column_families.size() != raw_handles.size()) {
    return createError(DatabaseError::FailToOpenDatabase,
                       "Fail to open database: can't map column families to handles");
  }

  db_ = std::unique_ptr<rocksdb::DB>(raw_db_handle);
  for (size_t i = 0; i < column_families.size(); i++) {
    handles_map_[column_families[0].name] = std::shared_ptr<rocksdb::ColumnFamilyHandle>(raw_handles[i]);
  }

  return Success();
}

ExpectedSuccess<DatabaseError> RocksdbDatabase::open(const std::string& path) {
  rocksdb::Options options = getOptions();
  auto db_path = boost::filesystem::path(path).make_preferred();
  default_read_options_ = rocksdb::ReadOptions();
  default_read_options_.verify_checksums = false;
  default_write_options_ = rocksdb::WriteOptions();
  return openInternal(options, db_path);
}

ExpectedSuccess<DatabaseError> RocksdbDatabase::checkDbConnection() {
  if (db_ == nullptr) {
    return createError(DatabaseError::DatabaseIsNotOpen,
                "Database is closed");
  }
  return Success();
}

Expected<std::string, DatabaseError> RocksdbDatabase::getStringInternal(rocksdb::ColumnFamilyHandle *handle, const std::string& key) {
  std::string value = "";
  auto status = db_->Get(default_read_options_, handle, key, &value);
  if (status.IsNotFound()) {
    return createError(DatabaseError::NotFound, "Value not found");
  }
  if (!status.ok()) {
    return createError(DatabaseError::FailToReadData, status.ToString());
  }
  return value;
}

ExpectedSuccess<DatabaseError> RocksdbDatabase::putStringInternal(rocksdb::ColumnFamilyHandle *handle, const std::string& key, const std::string& value) {
  auto status = db_->Put(default_write_options_, handle, key, value);
  if (!status.ok()) {
    createError(DatabaseError::FailToWriteData, status.ToString());
  }
  return Success();
}

Expected<std::shared_ptr<rocksdb::ColumnFamilyHandle>, DatabaseError> RocksdbDatabase::getHandle(const std::string &domain) {
  if (BOOST_UNLIKELY(db_ == nullptr)) {
    return createError(DatabaseError::DatabaseIsNotOpen, "Database is closed");
  }
  auto handle = handles_map_.find(domain);
  if (BOOST_UNLIKELY(handle == handles_map_.end())) {
    assert(false && "Unknown database domain");
    return createError(DatabaseError::UnknownDomain, "Unknown database domain");
  }

}

Expected<std::string, DatabaseError> RocksdbDatabase::getString(const std::string& domain, const std::string& key) {
  auto dbCheck = checkDbConnection();

  if (BOOST_UNLIKELY(!dbCheck)) {
    return dbCheck.takeError();
  }

  auto handle = handles_map_.find(domain);
  if (BOOST_UNLIKELY(handle == handles_map_.end())) {
    assert(false && "Unknown database domain");
    return createError(DatabaseError::UnknownDomain, "Unknown database domain");
  }
  return getStringInternal(handle->second.get(), key);
}

ExpectedSuccess<DatabaseError> RocksdbDatabase::putString(const std::string& domain, const std::string& key, const std::string& value) {
  auto dbCheck = checkDbConnection();

  if (BOOST_UNLIKELY(!dbCheck)) {
    return dbCheck.takeError();
  }
  auto handle = handles_map_.find(domain);
  if (BOOST_UNLIKELY(handle == handles_map_.end())) {
    assert(false && "Unknown database domain");
    return createError(DatabaseError::UnknownDomain, "Unknown database domain");
  }
  return putStringInternal(handle->second.get(), key, value);
}

Expected<int, DatabaseError> RocksdbDatabase::getInt(const std::string& domain, const std::string& key) {
  Expected<std::string, DatabaseError> buffer = getString(domain, key);
  if (buffer) {
    std::string value = buffer.take();
    int result = *(reinterpret_cast<const int *>(value.data()));
    return ntohl(result);
  }
  return buffer.takeError();
}

ExpectedSuccess<DatabaseError> RocksdbDatabase::putInt(const std::string& domain, const std::string& key, const int value) {
  int tmp_value = htonl(value);
  std::string buffer(reinterpret_cast<const char *>(&tmp_value), 4);
  return putString(domain, key, buffer);
}

template <typename Func>
ExpectedSuccess<DatabaseError> enumarateDomain(const std::string& domain, Func function) {

}

}
