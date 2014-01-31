// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.digests.sha512t_test;

import "package:cipher/cipher.dart";
import "package:cipher/impl/base.dart";

import "../test/digest_tests.dart";


/// NOTE: the expected results for these tests are computed using the Java version of Bouncy Castle.
void main() {

  initCipher();

  runDigestTests( new Digest("SHA-512/488"), [

    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "77c5a401110133e531d1acf33ea6010d8d8149f9804310b6d32a69033aee079e88603166478069b1d4622030a508930a062199150f66462e26063266e5",

    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme...",
    "149a6a1e7f9741b56186b01c9195e1c5a003197ff559604653ea176c6d6e75c7cd117d3105cf10bc8d1f24e46c98c5a8b2fa2e53c16e95ada867b20ea1",

  ]);

}

