library aes_fast_test;

import "dart:typed_data";

import "package:cipher/engines/aes_fast.dart";
import "package:cipher/params/key_parameter.dart";

import "package:unittest/unittest.dart";

import "../test_helpers/test_helpers.dart";

/**
 * NOTE: the expected results for these tests are computed using the Java
 * version of Bouncy Castle
 */
void main() {

  final key = createUint8ListFromListOfInts( [0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF] );
  final params = new KeyParameter(key);

  group( "AES:", () {

    group( "well known results cipher tests:", () {

      void runCipherTest( String plainTextString, String expectedHexCipherText ) {
        var plainText = createUint8ListFromString( plainTextString );
        var aes = new AESFastEngine()..init(true, params);
        var cipherText = processBlocks( aes, plainText );
        var hexCipherText = formatBytesAsHexString(cipherText);

        expect( hexCipherText, equals(expectedHexCipherText) );
      }

      test( "'Lorem ipsum' cipher test", () {
        var plainText = "Lorem ipsum dolor sit amet, consectetur adipiscing elit ........";
        var expectedHexCipherText = "75020e0812adb36f32b1503e0de7a59691e0db8fd1c9efb920695a626cb633d6db0112c007d19d5ea66fe7ab36c766232b3bcb98fd35f06d27d5a2d475d92728";
        runCipherTest( plainText, expectedHexCipherText );
      });

      test( "'Quijote' cipher test", () {
        var plainText = "En un lugar de La Mancha, de cuyo nombre no quiero acordarme ...";
        var expectedHexCipherText = "29523a5e73c0ffb7f9aaabc737a09e73219bad5e98768b71e2c985b2d8ce217730b0720e1a215f7843c8c7e07d44c91212fb1d5b90a791dd147f3746cbc0e28b";
        runCipherTest( plainText, expectedHexCipherText );
      });

    });

    group( "well known results decipher tests:", () {

      void runDecipherTest( String hexCipherText, String expectedPlainText ) {
        var cipherText = createUint8ListFromHexString(hexCipherText);
        var aes = new AESFastEngine()..init(false, params);
        var plainText = processBlocks( aes, cipherText );

        expect( new String.fromCharCodes(plainText), equals(expectedPlainText) );
      }

      test( "'Lorem ipsum' cipher test", () {
        var cipherText = "75020e0812adb36f32b1503e0de7a59691e0db8fd1c9efb920695a626cb633d6db0112c007d19d5ea66fe7ab36c766232b3bcb98fd35f06d27d5a2d475d92728";
        var expectedPlainText = "Lorem ipsum dolor sit amet, consectetur adipiscing elit ........";
        runDecipherTest( cipherText, expectedPlainText );
      });

      test( "'Quijote' cipher test", () {
        var cipherText = "29523a5e73c0ffb7f9aaabc737a09e73219bad5e98768b71e2c985b2d8ce217730b0720e1a215f7843c8c7e07d44c91212fb1d5b90a791dd147f3746cbc0e28b";
        var expectedPlainText = "En un lugar de La Mancha, de cuyo nombre no quiero acordarme ...";
        runDecipherTest( cipherText, expectedPlainText );
      });

    });

    group( "cipher+decipher tests:", () {

      void runCipherDecipherTest( Uint8List plainText ) {
        var aes = new AESFastEngine()..init(true, params);
        var cipherText = processBlocks( aes, plainText );

        aes..reset()
          ..init( false, params );
        var plainTextAgain = processBlocks( aes, cipherText );

        expect( plainTextAgain, equals(plainText) );
      }

      test( "'Quijote' well known text",  () {
        var plainText = createUint8ListFromString("En un lugar de La Mancha, de cuyo nombre no quiero acordarme ...");
        runCipherDecipherTest( plainText );
      });

      test( "1KB of sequential numbers test",  () {
        var plainText = createUint8ListFromSequentialNumbers(1024);
        runCipherDecipherTest( plainText );
      });

    });

  });

}

