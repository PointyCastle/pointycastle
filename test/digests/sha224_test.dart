// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.digests.sha224_test;

import "package:cipher/cipher.dart";

import "../test/digest_tests.dart";

void main() {

  initCipher();

  runDigestTests( new Digest("SHA-224"), [

    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "10cffc69eddba6e8eafae57155284bd074778e0903e251ea9c8f9f62",

    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme...",
    "f62bf1175f02176cfb00c370aea1c7203ba45a91cf776535380ab1a5",

  ]);

}

