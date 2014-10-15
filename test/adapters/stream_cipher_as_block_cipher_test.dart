// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.adapters.stream_cipher_as_block_cipher_test;

import 'package:unittest/unittest.dart';
import "package:cipher/adapters/stream_cipher_as_block_cipher.dart";

import '../test/block_cipher_tests.dart';
import '../test/src/null_stream_cipher.dart';
import '../test/src/helpers.dart';

void main() {

  runBlockCipherTests( new StreamCipherAsBlockCipher(16,new NullStreamCipher()), null, [

    "Lorem ipsum dolor sit amet, consectetur adipiscing elit ........",
    formatBytesAsHexString( createUint8ListFromString (
      "Lorem ipsum dolor sit amet, consectetur adipiscing elit ........"
    )),

    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme ...",
    formatBytesAsHexString( createUint8ListFromString (
      "En un lugar de La Mancha, de cuyo nombre no quiero acordarme ..."
    )),

  ]);

  var cbc = new StreamCipherAsBlockCipher(16,new NullStreamCipher());
  group( "StreamCipherAsBlockCipher:", () {

    runBlockCipherTests( cbc, null, [

      "Lorem ipsum dolor sit amet, consectetur adipiscing elit ........",
      formatBytesAsHexString( createUint8ListFromString (
          "Lorem ipsum dolor sit amet, consectetur adipiscing elit ........"
      )),

      "En un lugar de La Mancha, de cuyo nombre no quiero acordarme ...",
      formatBytesAsHexString( createUint8ListFromString (
        "En un lugar de La Mancha, de cuyo nombre no quiero acordarme ..."
      )),

    ]);

  });

}

