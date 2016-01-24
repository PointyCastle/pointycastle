// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library pointycastle.test.hmacs.hmac_test;

import "dart:typed_data";

import "package:pointycastle/pointycastle.dart";

import "../test/mac_tests.dart";

void main() {



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

