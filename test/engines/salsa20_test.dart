library salsa20_test;

import "dart:typed_data";

import "package:cipher/engines/salsa20.dart";
import "package:cipher/params/key_parameter.dart";
import "package:cipher/params/parameters_with_iv.dart";

import "package:unittest/unittest.dart";

import "../helpers.dart";

/**
 * NOTE: the expected results for these tests are computed using the Java
 * version of Bouncy Castle
 */
void main() {

  final _key = asUint8List_ListOfInt( [0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF] );
  final key = new KeyParameter(_key);
  final iv = asUint8List_ListOfInt( [0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77] );
  final params = new ParametersWithIV(key,iv);

  group( "Salsa20:", () {

    group( "well known results cipher tests:", () {

      void runCipherTest( String plainTextString, String expectedHexCipherText ) {
        var plainText = asUint8List_String( plainTextString );
        var salsa20 = new Salsa20Engine()..init(true, params);
        var cipherText = processStream( salsa20, plainText );
        var hexCipherText = toHexString_Uint8List(cipherText);

        expect( hexCipherText, equals(expectedHexCipherText) );
      }

      test( "'Lorem ipsum' cipher test", () {
        var plainText = "Lorem ipsum dolor sit amet, consectetur adipiscing elit ........";
        var expectedHexCipherText = "9d8d611ee047b47fc5e2bd5db4284463008aa89c174093d3ce4b3e8cc2594acfe9a62a84388fe060f75247d425c2fe0cd283cfce887f5c6b5dfea86d927efb36";
        runCipherTest( plainText, expectedHexCipherText );
      });

      test( "'Quijote' cipher test", () {
        var plainText = "En un lugar de La Mancha, de cuyo nombre no quiero acordarme ...";
        var expectedHexCipherText = "948c330ee347b17ad1f6a25db4220840138a96940d039adf871f76c9815551c5e3e5308e2198e025b65841843dc4f400ce8bcfca87795a2f12a2eb269c7efb36";
        runCipherTest( plainText, expectedHexCipherText );
      });

    });

    group( "well known results decipher tests:", () {

      void runDecipherTest( String hexCipherText, String expectedPlainText ) {
        var cipherText = toUint8List_String(hexCipherText);
        var salsa20 = new Salsa20Engine()..init(false, params);
        var plainText = processStream( salsa20, cipherText );

        expect( new String.fromCharCodes(plainText), equals(expectedPlainText) );
      }

      test( "'Lorem ipsum' cipher test", () {
        var cipherText = "9d8d611ee047b47fc5e2bd5db4284463008aa89c174093d3ce4b3e8cc2594acfe9a62a84388fe060f75247d425c2fe0cd283cfce887f5c6b5dfea86d927efb36";
        var expectedPlainText = "Lorem ipsum dolor sit amet, consectetur adipiscing elit ........";
        runDecipherTest( cipherText, expectedPlainText );
      });

      test( "'Quijote' cipher test", () {
        var cipherText = "948c330ee347b17ad1f6a25db4220840138a96940d039adf871f76c9815551c5e3e5308e2198e025b65841843dc4f400ce8bcfca87795a2f12a2eb269c7efb36";
        var expectedPlainText = "En un lugar de La Mancha, de cuyo nombre no quiero acordarme ...";
        runDecipherTest( cipherText, expectedPlainText );
      });

    });

    group( "cipher+decipher tests:", () {

      void runCipherDecipherTest( Uint8List plainText ) {
        var salsa20 = new Salsa20Engine()..init(true, params);
        var cipherText = processStream( salsa20, plainText );

        salsa20..reset()
          ..init( false, params );
        var plainTextAgain = processStream( salsa20, cipherText );

        expect( plainTextAgain, equals(plainText) );
      }

      test( "'Quijote' well known text",  () {
        var plainText = asUint8List_String("En un lugar de La Mancha, de cuyo nombre no quiero acordarme ...");
        runCipherDecipherTest( plainText );
      });

      test( "1KB of sequential numbers test",  () {
        var plainText = createSequentialInput(1024);
        runCipherDecipherTest( plainText );
      });

    });

  });
}

