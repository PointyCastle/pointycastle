// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.paddings.pkcs7_test;

import "package:cipher/cipher.dart";

import "../test/padding_tests.dart";

void main() {

  initCipher();

  runPaddingTest( new Padding("PKCS7"), null,
      "123456789", 16,
      "31323334353637383907070707070707"
  );
  runPaddingTest( new Padding("PKCS7"), null,
      "", 16,
      "10101010101010101010101010101010"
  );

}

