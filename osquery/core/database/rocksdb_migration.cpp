/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <osquery/core/database/rocksdb_migration.h>
#include <osquery/core/conversions.h>

#include <boost/filesystem.hpp>

namespace osquery {

ExpectedSuccess<RocksdbMigrationError> RocksdbMigration::migrateDatabase(const std::string& path) {

//  auto column_families = createDefaultColumnFamilies(options);
//  auto db_path = boost::filesystem::path(path).make_preferred();
//  auto db_path_status = boost::filesystem::status(db_path);
//  if (!boost::filesystem::exists(db_path_status)) {
//    return createError(DatabaseError::DatabasePathDoesNotExists,
//                       "database path doesn't exist");
//  }
//  std::vector<rocksdb::ColumnFamilyHandle*> raw_handles;
//  rocksdb::DB* raw_db_handle = nullptr;
//  auto open_status = rocksdb::DB::Open(options, db_path.string(), column_families, &raw_handles, &raw_db_handle);
//  if (open_status.IsCorruption()) {
//    auto corruptionError = createError(RocksdbError::DatabaseIsCorrupted, open_status.ToString());
//    return createError(DatabaseError::Panic, "database is corrrupted", std::move(corruptionError));
//  }
//  if (!open_status.ok()) {
//    return createError(DatabaseError::FailToOpenDatabase,
//                       "Fail to open database: ") << open_status.ToString();
//  }

  return Success();
}

RocksdbMigration::RocksdbMigration(const std::string& path) {
  source_path_ = boost::filesystem::path(path).make_preferred().string();
}

ExpectedSuccess<RocksdbMigrationError> RocksdbMigration::migrateIfNeeded() {
  
  return Success();
}

Expected<RocksdbMigration::DatabaseHandle, RocksdbMigrationError> RocksdbMigration::openDatabase(const std::string& path, bool create_if_missing, bool error_if_exists) {
  DatabaseHandle handle;
  handle.options.OptimizeForSmallDb();
  handle.options.create_if_missing = create_if_missing;
  handle.options.error_if_exists = error_if_exists;
  handle.path = path;
  std::vector<std::string> column_families;
  rocksdb::DB::ListColumnFamilies(handle.options, path, &column_families);

  std::vector<rocksdb::ColumnFamilyDescriptor> descriptors;
  for (const auto& column : column_families) {
    descriptors.push_back(rocksdb::ColumnFamilyDescriptor(column, handle.options));
  }
  std::vector<rocksdb::ColumnFamilyHandle *> column_family_handles;
  rocksdb::DB *db = nullptr;
  auto status = rocksdb::DB::Open(handle.options, path, descriptors, &column_family_handles, &db);
  if (status.IsInvalidArgument()) {
    return createError(RocksdbMigrationError::InvalidArgument, status.ToString());
  }
  if (!status.ok()) {
    return createError(RocksdbMigrationError::FailToOpen, status.ToString());
  }
  handle.handle = std::unique_ptr<rocksdb::DB>(db);
  for (const auto& ptr : column_family_handles) {
    handle.handles.push_back(std::unique_ptr<rocksdb::ColumnFamilyHandle>(ptr));
  }
  return std::move(handle);
}

Expected<int, RocksdbMigrationError> RocksdbMigration::getVersion(const DatabaseHandle& db) {
  rocksdb::ReadOptions options;
  options.verify_checksums = true;
  for (const auto& handle : db.handles) {
    if (handle->GetName() == "configurations") {
      // Try to get new version first
      // Version stored as string value to help analyze db
      // by tools
      std::string version_str;
      auto status = db.handle->Get(options, handle.get(), std::string("database_schema_version"), &version_str);
      if (status.IsNotFound()) {
        // Fallback to old version storage
        status = db.handle->Get(options, handle.get(), std::string("results_version"), &version_str);
      }
      if (!status.ok()) {
        return createError(RocksdbMigrationError::FailToGetVersion, status.ToString());
      }
      auto result = tryTo<int>(version_str);
      if (result) {
        return *result;
      }
      return createError(RocksdbMigrationError::FailToGetVersion, "", result.takeError());
    }
  }
  return createError(RocksdbMigrationError::FailToGetVersion, "Verion data is not found");
}



}
