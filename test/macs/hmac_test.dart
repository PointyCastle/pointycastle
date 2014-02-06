// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.hmacs.hmac_test;

import "dart:typed_data";

import "package:cipher/cipher.dart";
import "package:cipher/impl/base.dart";

import "../test/mac_tests.dart";

/// NOTE: the expected results for these tests are computed using the Java version of Bouncy Castle.
void main() {

  initCipher();

  final mac = new Mac("SHA-1/HMAC");
  final key = new Uint8List.fromList( [0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF] );
  final keyParam = new KeyParameter(key);

  mac.init( keyParam );

  runMacTests( mac, [

    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "a646990cca06cb7550a91bdd9ae481c6472f06bc",

    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme...",
    "1d710be3529ecee6ddd2f1ad4c3c12d6f467243f",

  ]);

}

