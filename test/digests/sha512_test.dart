// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

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

