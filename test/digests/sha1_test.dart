// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.digests.sha1_test;

import "package:cipher/cipher.dart";

import "../test/digest_tests.dart";

void main() {



  runDigestTests( new Digest("SHA-1"), [

    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "04e7635f310b9fbfa496ace02fa3ff9e7737f58c",

    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme...",
    "cc8c8c2319221ae0b2a5dd5b26748a937c5855e4",

  ]);

}

