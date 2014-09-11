// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.digests.md4_test;

import "package:cipher/cipher.dart";

import "../test/digest_tests.dart";

void main() {

  initCipher();

  runDigestTests( new Digest("MD4"), [

    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "1d6839cb198b77f5d9a027a5ed1989d7",

    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme...",
    "95cdeefe499f74582d2894436cfbb989",

  ]);

}

