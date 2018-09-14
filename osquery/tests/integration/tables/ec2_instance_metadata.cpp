
/**
 *  Copyright (c) 2014-present, Facebook, Inc.
 *  All rights reserved.
 *
 *  This source code is licensed under both the Apache 2.0 license (found in the
 *  LICENSE file in the root directory of this source tree) and the GPLv2 (found
 *  in the COPYING file in the root directory of this source tree).
 *  You may select, at your option, one of the above-listed licenses.
 */

// Sanity check integration test for ec2_instance_metadata
// Spec file: specs/linux/ec2_instance_metadata.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {

class ec2InstanceMetadata : public IntegrationTableTest {};

TEST_F(ec2InstanceMetadata, test_sanity) {
  // 1. Query data
  // QueryData data = execute_query("select * from ec2_instance_metadata");
  // 2. Check size before validation
  // ASSERT_GE(data.size(), 0ul);
  // ASSERT_EQ(data.size(), 1ul);
  // ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See IntegrationTableTest.cpp for avaialbe flags
  // Or use custom DataCheck object
  // ValidatatioMap row_map = {
  //      {"instance_id", NormalType}
  //      {"instance_type", NormalType}
  //      {"architecture", NormalType}
  //      {"region", NormalType}
  //      {"availability_zone", NormalType}
  //      {"local_hostname", NormalType}
  //      {"local_ipv4", NormalType}
  //      {"mac", NormalType}
  //      {"security_groups", NormalType}
  //      {"iam_arn", NormalType}
  //      {"ami_id", NormalType}
  //      {"reservation_id", NormalType}
  //      {"account_id", NormalType}
  //      {"ssh_public_key", NormalType}
  //}
  // 4. Perform validation
  // validate_rows(data, row_map);
}

} // namespace osquery
