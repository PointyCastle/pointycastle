// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.digests.sha256_test;

import "package:cipher/cipher.dart";

import "../test/digest_tests.dart";

void main() {

  initCipher();

  runDigestTests( new Digest("SHA-256"), [

    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "5bd6045a7697c48316411ff00be02595cf3d8596d99ba12482d18c90d61633cb",

    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme...",
    "2ab2e44465bec2b6bcfc8d13bfe07aa7e25e064685c60c2715d1831172376073",

  ]);

}

