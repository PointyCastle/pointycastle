// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.digests.sha3_test;

import "package:cipher/cipher.dart";
import "package:cipher/impl/base.dart";

import "../test/digest_tests.dart";

/// NOTE: the expected results for these tests are computed using the Java version of Bouncy Castle.
void main() {

  initCipher();

  runDigestTests(new Digest("SHA-3/512"), [

    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "ac60af5cf659dcb3df7ad078a3ea92a0be21b49ab4ba82b4b7bed3734f6445019b860ffa4b25555b3666bb75716f699566967f7dff3b6b8aa89754c059035caf",

    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme...",
    "c31849ce2794f05ec01cbbd6760ab2b9dbfc5a7ce7482eee934fe6818d74d3c54f3234fc935dcd1cfe1bc17f68e14ed01d3035c90214650d3740accd5860cb18",

  ]);

}

