// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.test.test.asymmetric_block_cipher_tests;

import "package:test/test.dart";
import "package:pointycastle/pointycastle.dart";
import "dart:typed_data";

import "./src/helpers.dart";

void runAEADBlockCipherTests( BlockCipher cipher, CipherParameters params, List<String> plainCipherTextPairs ) {

  group( "cipher  :", () {

    for( var i=0 ; i<plainCipherTextPairs.length ; i+=2 ) {

      var plainText = plainCipherTextPairs[i];
      var cipherText = plainCipherTextPairs[i+1];

      test( "$plainText", () {
        var plainTextBytes = new Uint8List.fromList(plainText.codeUnits);
        cipher
          ..reset()
          ..init(true, params);

        var cipherTextBytes = cipher.process(plainTextBytes);
        var hexCipherText = formatBytesAsHexString(cipherTextBytes);

        expect(hexCipherText, equals(cipherText));
      });

    }
  });

  group( "decipher:", () {

    for( var i=0 ; i<plainCipherTextPairs.length ; i+=2 ) {

      var plainText = plainCipherTextPairs[i];
      var cipherText = plainCipherTextPairs[i+1];

      test( "$plainText", () {
        var cipherTextBytes = createUint8ListFromHexString(cipherText);
        cipher
          ..reset()
          ..init(false, params);

        var plainTextBytes = cipher.process( cipherTextBytes );
        expect( new String.fromCharCodes(plainTextBytes), equals(plainText) );

        cipher.reset();

        cipherTextBytes.last &= 0x01;

        expect(() {
          cipher.process( cipherTextBytes );
        }, throwsA(new TypeMatcher<InvalidCipherTextException>()));
      });

    }
  });


}
