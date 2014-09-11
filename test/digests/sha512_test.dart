// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.digests.sha512_test;

import "package:cipher/cipher.dart";

import "../test/digest_tests.dart";

void main() {

  initCipher();

  runDigestTests( new Digest("SHA-512"), [

    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "7a61cb16b6c459d0894ba7ce01a50a43036da9f77e9a27c2e17d563c7eca877f"
    "a9e1d91968f5c61552a62f72deb07c5f6c00f8f43d0c3dccd46dfcc248b29b0e",

    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme...",
    "f221fdceac5a63b712f303b444cf8aeacdc5a58835c340469772075430ddc43d"
    "983891458e543b0abd8c4acb71d69a808e292a86eaef1c1b1ddc83a567d8a346",

  ]);

}

