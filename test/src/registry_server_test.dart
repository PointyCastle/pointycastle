// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.registry_server_test;

import "package:cipher/impl/server.dart";

import "package:unittest/unittest.dart";

import "../test/registry_tests.dart";

void main() {

  initCipher();

  group( "registry_server:", () {

    test( "EntropySource returns valid implementations", () {

      testEntropySource( "file:///dev/random" );
      testEntropySource( "http://www.random.org/cgi-bin/randbyte?nbytes={count}&format=f" );
      testEntropySource( "https://www.random.org/cgi-bin/randbyte?nbytes={count}&format=f" );

    });

  });

}
