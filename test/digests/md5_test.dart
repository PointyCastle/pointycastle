// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.digests.md5_test;

import "package:cipher/cipher.dart";

import "../test/digest_tests.dart";

void main() {

  initCipher();

  runDigestTests( new Digest("MD5"), [

    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "b4dbd72756e62ad118c9759446956d15",

    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme...",
    "dc4381c2a676fdcd92fad9ba4b97116d",

  ]);

}

