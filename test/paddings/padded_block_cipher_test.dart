// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.padded_block_cipher_test;

import "dart:typed_data";

import "package:unittest/unittest.dart";

import "package:cipher/cipher.dart";
import "package:cipher/impl.dart";

import "../test/src/null_block_cipher.dart";
import "../test/src/helpers.dart";

void main() {

  initCipher();
  BlockCipher.registry["Null"] = (_) => new NullBlockCipher();

  group( "PaddedBlockCipherTest works", () {

    test( "cipher", () {

      var params = new PaddedBlockCipherParameters( null, null );
      var pbc = new PaddedBlockCipher("Null/PKCS7");

      var inp = createUint8ListFromSequentialNumbers(3*pbc.blockSize~/2);
      var out = new Uint8List( 2*pbc.blockSize );
      pbc.init( true, params );
      pbc.processBlock( inp, 0, out, 0 );
      pbc.doFinal( inp, pbc.blockSize, out, pbc.blockSize );

      expect( formatBytesAsHexString(out), "000102030405060708090a0b0c0d0e0f10111213141516170808080808080808" );

    });

  });

}

