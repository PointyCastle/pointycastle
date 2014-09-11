// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.digests.md2_test;

import "package:cipher/cipher.dart";

import "../test/digest_tests.dart";

void main() {

  initCipher();

  runDigestTests( new Digest("MD2"), [

    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "70bdf19ce16c171706e9ef02219f35a8",

    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme...",
    "2b6aa7a2fe344c9bd4844c73c306a26a",

  ]);

}

