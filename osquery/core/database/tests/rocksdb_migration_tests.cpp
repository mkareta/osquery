/**
 *  Copyright (c) 2018-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

#include <gtest/gtest.h>

#include <boost/filesystem.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>

#include <osquery/core/database/rocksdb_database.h>
#include <osquery/core/database/rocksdb_migration.h>
#include <osquery/database.h>

namespace osquery {

class RocksdbDatabaseTest : public ::testing::Test {
 protected:
  std::string path_;

  virtual void SetUp() {
    boost::uuids::uuid uuid = boost::uuids::random_generator()();
    auto random_name = boost::uuids::to_string(uuid);
    auto path = boost::filesystem::temp_directory_path().append(random_name);
    boost::filesystem::create_directory(path);
    path_ = path.string();
  }

  virtual void TearDown() {
    boost::filesystem::remove_all(path_);
  }
};

std::string randomDBPath() {
  boost::uuids::uuid uuid = boost::uuids::random_generator()();
  auto random_name = boost::uuids::to_string(uuid);
  auto path = boost::filesystem::temp_directory_path().append(random_name);
  boost::filesystem::create_directory(path);
  return path.string();
}

TEST_F(RocksdbDatabaseTest, test_v2_v3_migraion) {
  auto path = randomDBPath();
  auto db = std::make_unique<RocksdbDatabase>("test", path_);
  auto result = db->open();
  ASSERT_TRUE(result);
  ASSERT_TRUE(db->putString("default", "key1", "configurations1"));
  ASSERT_TRUE(db->putString("default", "key2", "configurations2"));
  ASSERT_TRUE(db->putString("queries", "key1", "logs1"));
  ASSERT_TRUE(db->putString("queries", "key2", "logs2"));
  ASSERT_TRUE(db->putString("queries", "key3", "logs3"));
  db->close();
  RocksdbMigration::migrateDatabase(path_);
}

} // namespace osquery
