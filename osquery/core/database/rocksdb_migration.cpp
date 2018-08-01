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
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>


namespace osquery {

ExpectedSuccess<RocksdbMigrationError> RocksdbMigration::migrateDatabase(const std::string& path) {
  auto migration = std::make_unique<RocksdbMigration>(path);
  return migration->migrateIfNeeded();
}

RocksdbMigration::RocksdbMigration(const std::string& path) {
  source_path_ = boost::filesystem::path(path).make_preferred().string();
}

ExpectedSuccess<RocksdbMigrationError> RocksdbMigration::migrateIfNeeded() {
  auto open_result = openDatabase(source_path_, false, false);
  if (open_result) {
    auto db_handle = open_result.take();
    auto version_result = getVersion(db_handle);
    if (version_result) {
      int version = version_result.take();
      if (version != kDatabaseSchemaVersionCurrent) {
        migrateFromVersion(version);
      } else {
        return Success();
      }
    } else {
      return createError(RocksdbMigrationError::FailToMigrate, "", version_result.takeError());
    }
  } else {
    // InvalidArgument means that db does not exists
    if (open_result.getErrorCode() == RocksdbMigrationError::InvalidArgument) {
      return Success();
    } else {
      return createError(RocksdbMigrationError::FailToMigrate, "", open_result.takeError());
    }
  }
  return Success();
}

void RocksdbMigration::buildMigrationMap() {
  migration_map_[kDatabaseSchemaV2] = [](const std::string& src, const std::string& dst) -> Expected<int, RocksdbMigrationError> {
    return -1;
  };
}

ExpectedSuccess<RocksdbMigrationError> RocksdbMigration::migrateFromVersion(int original_version) {
  buildMigrationMap();
  std::string src_path = source_path_;
  std::string dst_path = randomOutputPath();
  bool drop_src_data = false;
  for (int version = original_version; version < kDatabaseSchemaVersionCurrent;) {
    auto iter = migration_map_.find(version);
    if (iter == migration_map_.end()) {
      auto error = createError(RocksdbMigrationError::NoMigrationFromCurrentVersion, "No migration logic from version: ") << version;
      return createError(RocksdbMigrationError::FailToMigrate, "Failed to migrate database", std::move(error));
    }
    VLOG(1) << "Migrating from version: " << version << ". Src path: " << src_path << ". Dst path: " << dst_path;
    auto migration_result = iter->second(src_path, dst_path);
    if (migration_result) {
      int new_version = migration_result.take();
      if (new_version <= version) {
        auto error = createError(RocksdbMigrationError::MigrationLogicError, "New version(") << version << ") is lower or same as old(" << new_version << ")";
        return createError(RocksdbMigrationError::FailToMigrate, "", std::move(error));
      }
      version = new_version;
    } else {
      return createError(RocksdbMigrationError::FailToMigrate, "Failed to migrate database", migration_result.takeError());
    }
    if (drop_src_data) {
      VLOG(1) << "Destroying db at path: " << src_path;
      rocksdb::DestroyDB(src_path, rocksdb::Options());
    }
    drop_src_data = true;
    src_path = dst_path;
    dst_path = randomOutputPath();
  }
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

std::string RocksdbMigration::randomOutputPath() {
  auto path = boost::filesystem::path(OSQUERY_HOME);
  boost::uuids::uuid uuid = boost::uuids::random_generator()();
  path.append("migration");
  path.append(boost::uuids::to_string(uuid));
  return path.string();
}

}
