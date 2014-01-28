// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.all_server_tests;

import "./entropy/file_entropy_source_test.dart" as dev_random_entropy_source_test;
import "./entropy/url_entropy_source_test.dart" as random_org_entropy_source_test;

import "./all_tests.dart" as all_tests;
import "./src/registry_server_test.dart" as registry_server_test;

void main() {

  // registry
  registry_server_test.main();

  // base tests
  all_tests.main();

  // entropy sources
  dev_random_entropy_source_test.main();
  random_org_entropy_source_test.main();

}