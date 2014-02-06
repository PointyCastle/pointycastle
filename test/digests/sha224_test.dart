// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.digests.sha224_test;

import "package:cipher/cipher.dart";
import "package:cipher/impl/base.dart";

import "../test/digest_tests.dart";

/// NOTE: the expected results for these tests are computed using the Java version of Bouncy Castle.
void main() {

  initCipher();

  runDigestTests( new Digest("SHA-224"), [

    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "10cffc69eddba6e8eafae57155284bd074778e0903e251ea9c8f9f62",

    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme...",
    "f62bf1175f02176cfb00c370aea1c7203ba45a91cf776535380ab1a5",

  ]);

}

