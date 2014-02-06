// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.all_client_tests;

import "package:unittest/html_enhanced_config.dart";

import "./all_tests.dart" as all_tests;
import "./api/registry_client_test.dart" as registry_client_test;

void main() {

  useHtmlEnhancedConfiguration();

  // registry
  registry_client_test.main();

  // base tests
  all_tests.main();

}