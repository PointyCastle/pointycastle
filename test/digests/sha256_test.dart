// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.digests.sha256_test;

import "package:cipher/cipher.dart";

import "../test/digest_tests.dart";


/// NOTE: the expected results for these tests are computed using the Java version of Bouncy Castle.
void main() {

  initCipher();

  runDigestTests( new Digest("SHA-256"), [

    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "5bd6045a7697c48316411ff00be02595cf3d8596d99ba12482d18c90d61633cb",

    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme...",
    "2ab2e44465bec2b6bcfc8d13bfe07aa7e25e064685c60c2715d1831172376073",

  ]);

}

