// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.test.asymmetric_block_cipher_tests;

import "dart:typed_data";

import "package:cipher/cipher.dart";
import "package:unittest/unittest.dart";

import "./src/helpers.dart";

void runAsymmetricBlockCipherTests(AsymmetricBlockCipher cipher, CipherParameters pubParams(), CipherParameters privParams(),
                                   List<String> plainCipherTextTuples ) {

  group( "${cipher.algorithmName}:", () {

    group( "encrypt:", () {
      for( var i=0 ; i<plainCipherTextTuples.length ; i+=3 ) {
        var plainText = plainCipherTextTuples[i];
        var publicCipherText = plainCipherTextTuples[i+1];
        var privateCipherText = plainCipherTextTuples[i+2];

        test( "public: ${formatAsTruncated(plainText)}", () =>
          _runCipherTest( cipher, pubParams, plainText, publicCipherText )
        );
        test( "private: ${formatAsTruncated(plainText)}", () =>
          _runCipherTest( cipher, privParams, plainText, privateCipherText )
        );

      }
    });

    group( "decrypt:", () {
      for( var i=0 ; i<plainCipherTextTuples.length ; i+=3 ) {
        var plainText = plainCipherTextTuples[i];
        var publicCipherText = plainCipherTextTuples[i+1];
        var privateCipherText = plainCipherTextTuples[i+2];

        test( "public: ${formatAsTruncated(plainText)}", () =>
          _runDecipherTest( cipher, pubParams, privateCipherText, plainText )
        );
        test( "private: ${formatAsTruncated(plainText)}", () =>
          _runDecipherTest( cipher, privParams, publicCipherText, plainText )
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
