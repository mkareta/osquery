
/**
*  Copyright (c) 2014-present, Facebook, Inc.
*  All rights reserved.
*
*  This source code is licensed under both the Apache 2.0 license (found in the
*  LICENSE file in the root directory of this source tree) and the GPLv2 (found
*  in the COPYING file in the root directory of this source tree).
*  You may select, at your option, one of the above-listed licenses.
*/

// Sanity check integration test for wifi_networks 
// Spec file: specs/darwin/wifi_networks.table

#include <osquery/tests/integration/tables/helper.h>

namespace osquery {

class wifiNetworks : public IntegrationTableTest {};

TEST_F(wifiNetworks, test_sanity) {
  // 1. Query data
  //QueryData data = execute_query("select * from wifi_networks");
  // 2. Check size before validation
  //ASSERT_GE(data.size(), 0ul);
  //ASSERT_EQ(data.size(), 1ul);
  //ASSERT_EQ(data.size(), 0ul);
  // 3. Build validation map
  // See IntegrationTableTest.cpp for avaialbe flags
  // Or use custom DataCheck object
  //ValidatatioMap row_map = {
  //      {"ssid", NormalType}
  //      {"network_name", NormalType}
  //      {"security_type", NormalType}
  //      {"last_connected", IntType}
  //      {"passpoint", IntType}
  //      {"possibly_hidden", IntType}
  //      {"roaming", IntType}
  //      {"roaming_profile", NormalType}
  //      {"captive_portal", IntType}
  //      {"auto_login", IntType}
  //      {"temporarily_disabled", IntType}
  //      {"disabled", IntType}
  //}
  // 4. Perform validation
  //EXPECT_TRUE(validate_rows(data, row_map));
}

}
