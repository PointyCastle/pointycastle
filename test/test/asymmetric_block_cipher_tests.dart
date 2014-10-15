// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.test.asymmetric_block_cipher_tests;

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

  cipher.reset();
  cipher.init(true, params());

  var plainText = createUint8ListFromString( plainTextString );
  var out = cipher.process(plainText);
  var hexOut = formatBytesAsHexString(out);

  expect( hexOut, equals(expectedHexCipherText) );
}

void _runDecipherTest(AsymmetricBlockCipher cipher, CipherParameters params(), String hexCipherText,
                      String expectedPlainTextString ) {
  cipher.reset();
  cipher.init(false, params());

  var cipherText = createUint8ListFromHexString(hexCipherText);
  var out = cipher.process(cipherText);
  var plainText = new String.fromCharCodes(out);

  expect( plainText, equals(expectedPlainTextString) );
}
