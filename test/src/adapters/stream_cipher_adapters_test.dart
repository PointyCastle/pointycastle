// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.src.adapters.stream_cipher_adapters_test;

import 'package:unittest/unittest.dart';

import "package:cipher/src/adapters/stream_cipher_adapters.dart";

import "../../test/block_cipher_tests.dart";

import "../../test/src/null_stream_cipher.dart";
import "../../test/src/null_block_cipher.dart";
import "../../test/src/helpers.dart";


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

  var underlyingCipher = new NullBlockCipher();
  var cbc = new StreamCipherAsChainingBlockCipher(16,new NullStreamCipher(),underlyingCipher);
  group( "StreamCipherAsChainingBlockCipher:", () {

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

    test( "underlyingCipher return is correct", () {
      expect( cbc.underlyingCipher, same(underlyingCipher) );
    });

  });

}

