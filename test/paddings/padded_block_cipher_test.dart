// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com  
// Use of this source code is governed by a LGPL v3 license. 
// See the LICENSE file for more information.

library cipher.test.padded_block_cipher_test;

import "dart:typed_data";

import "package:unittest/unittest.dart";

import "package:cipher/paddings/padded_block_cipher.dart";
import "package:cipher/params/padded_block_cipher_parameters.dart";
import "package:cipher/paddings/pkcs7.dart";
import "package:cipher/engines/null_cipher.dart";

import "../test/helpers.dart";


void main() {
  
  group( "PaddedBlockCipherTest works", () {
    
    test( "cipher", () {
  
      var params = new PaddedBlockCipherParameters( null, null );
      var pbc = new PaddedBlockCipherImpl( 
          new PKCS7Padding(), 
          new NullBlockCipher() 
      );
      
      var inp = createUint8ListFromSequentialNumbers(3*pbc.blockSize~/2);
      var out = new Uint8List( 2*pbc.blockSize );
      pbc.init( true, params );
      pbc.processBlock( inp, 0, out, 0 );
      pbc.doFinal( inp, pbc.blockSize, out, pbc.blockSize );
      
      expect( formatBytesAsHexString(out), "000102030405060708090a0b0c0d0e0f10111213141516170808080808080808" );
      
    });

  });
  
}

