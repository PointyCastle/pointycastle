// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.test.asymmetric_block_cipher_tests;

import "dart:typed_data";

import "package:cipher/cipher.dart";
import "package:unittest/unittest.dart";

import "./src/helpers.dart";

void runAsymmetricBlockCipherTests(AsymmetricBlockCipher cipher, CipherParameters encParams(), CipherParameters decParams(),
                                   List<String> plainCipherTextPairs ) {

  group( "${cipher.algorithmName}:", () {

    group( "encrypt:", () {
      for( var i=0 ; i<plainCipherTextPairs.length ; i+=2 ) {
        var plainText = plainCipherTextPairs[i];
        var cipherText = plainCipherTextPairs[i+1];

        test( "${formatAsTruncated(plainText)}", () =>
          _runCipherTest( cipher, encParams, plainText, cipherText )
        );

      }
    });

    group( "decrypt:", () {
      for( var i=0 ; i<plainCipherTextPairs.length ; i+=2 ) {
        var plainText = plainCipherTextPairs[i];
        var cipherText = plainCipherTextPairs[i+1];

        test( "${formatAsTruncated(plainText)}", () =>
          _runDecipherTest( cipher, decParams, cipherText, plainText )
        );

      }
    });

  });

}

void _runCipherTest(AsymmetricBlockCipher cipher, CipherParameters params(), String plainTextString,
                    String expectedHexCipherText) {

  var plainText = createUint8ListFromString( plainTextString );

  cipher.reset();
  cipher.init(true, params());

  var out = new Uint8List(cipher.outputBlockSize);

  cipher.processBlock(plainText, 0, plainText.length, out, 0);

  var hexOut = formatBytesAsHexString(out);

  expect( hexOut, equals(expectedHexCipherText) );
}

void _runDecipherTest(AsymmetricBlockCipher cipher, CipherParameters params(), String hexCipherText,
                      String expectedPlainTextString ) {

  var cipherText = createUint8ListFromHexString(hexCipherText);

  cipher.reset();
  cipher.init(false, params());

  var out = new Uint8List(cipher.outputBlockSize);

  var len = cipher.processBlock(cipherText, 0, cipherText.length, out, 0);

  var plainText = new String.fromCharCodes(out.sublist(0, len));

  expect( plainText, equals(expectedPlainTextString) );
}
