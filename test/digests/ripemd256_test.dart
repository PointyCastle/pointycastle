// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.digests.ripemd256_test;

import "package:cipher/cipher.dart";

import "../test/digest_tests.dart";

void main() {

  initCipher();

  runDigestTests( new Digest("RIPEMD-256"), [

    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "5bca9a62d8c446acea2716a6634bed99ae9c240ebadf584b277397028bbe74de",

    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme...",
    "b12cc8c54ad8e14e9cbaa8bdd1d78139880fc824a2af19c67699d64fb4322cc2",

  ]);

}

