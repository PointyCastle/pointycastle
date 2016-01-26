// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.digests.tiger_test;

import "package:cipher/cipher.dart";

import "../test/digest_tests.dart";

void main() {



  runDigestTests( new Digest("Tiger"), [

    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "c9a8c5f0ce21cd25d1158c7b9b9ef043437ef0e2bce65cca",

    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme...",
    "8edc9820300d6453f6784523bbf32d9e44ce20fbec7b07f8",

  ]);

}

