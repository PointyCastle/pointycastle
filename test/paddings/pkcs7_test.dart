// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.paddings.pkcs7_test;

import "package:cipher/cipher.dart";
import "package:cipher/impl.dart";

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

