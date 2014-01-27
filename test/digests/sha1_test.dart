// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.digests.sha1_test;

import "package:cipher/cipher.dart";
import "package:cipher/impl/base.dart";

import "../test/digest_tests.dart";


/// NOTE: the expected results for these tests are computed using the Java version of Bouncy Castle.
void main() {

  initCipher();

  runDigestTests( new Digest("SHA-1"), [

    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "04e7635f310b9fbfa496ace02fa3ff9e7737f58c",

    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme...",
    "cc8c8c2319221ae0b2a5dd5b26748a937c5855e4",

  ]);

}

