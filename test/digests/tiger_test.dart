// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.digests.tiger_test;

import "package:cipher/cipher.dart";
import "package:cipher/impl/base.dart";

import "../test/digest_tests.dart";


/// NOTE: the expected results for these tests are computed using the Java version of Bouncy Castle
void main() {

  initCipher();

  runDigestTests( new Digest("Tiger"), [

    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "c9a8c5f0ce21cd25d1158c7b9b9ef043437ef0e2bce65cca",

    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme...",
    "8edc9820300d6453f6784523bbf32d9e44ce20fbec7b07f8",

  ]);

}

