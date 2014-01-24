// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.digests.md5_test;

import "package:cipher/cipher.dart";
import "package:cipher/impl.dart";

import "../test/digest_tests.dart";


/// NOTE: the expected results for these tests are computed using the Java version of Bouncy Castle.
void main() {

  initCipher();

  runDigestTests( new Digest("MD5"), [

    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "b4dbd72756e62ad118c9759446956d15",

    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme...",
    "dc4381c2a676fdcd92fad9ba4b97116d",

  ]);

}

