// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.digests.ripemd256_test;

import "package:cipher/cipher.dart";
import "package:cipher/impl/base.dart";

import "../test/digest_tests.dart";

/// NOTE: the expected results for these tests are computed using the Java version of Bouncy Castle. */
void main() {

  initCipher();

  runDigestTests( new Digest("RIPEMD-256"), [

    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "5bca9a62d8c446acea2716a6634bed99ae9c240ebadf584b277397028bbe74de",

    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme...",
    "b12cc8c54ad8e14e9cbaa8bdd1d78139880fc824a2af19c67699d64fb4322cc2",

  ]);

}

