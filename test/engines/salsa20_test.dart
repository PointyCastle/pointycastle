library salsa20_test;

import "package:cipher/engines/salsa20.dart";
import "package:cipher/params/key_parameter.dart";
import "package:cipher/params/parameters_with_iv.dart";

import "package:unittest/unittest.dart";

import "../test_helpers/test_helpers.dart";

/**
 * NOTE: the expected results for these tests are computed using the Java
 * version of Bouncy Castle
 */
void main() {

  final keyBytes = createUint8ListFromListOfInts( [0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF] );
  final key = new KeyParameter(keyBytes);
  final iv = createUint8ListFromListOfInts( [0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77] );
  final params = new ParametersWithIV(key,iv);

  group( "Salsa20:", () {

    group( "well known results cipher tests:", () {

      test( "'Lorem ipsum' cipher test", () => runStreamCipherTest(
        new Salsa20Engine()..init(true, params),
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit ........",
        "9d8d611ee047b47fc5e2bd5db4284463008aa89c174093d3ce4b3e8cc2594acfe9a62a84388fe060f75247d425c2fe0cd283cfce887f5c6b5dfea86d927efb36"
      ));

      test( "'Quijote' cipher test", () => runStreamCipherTest(
        new Salsa20Engine()..init(true, params),
        "En un lugar de La Mancha, de cuyo nombre no quiero acordarme ...",
        "948c330ee347b17ad1f6a25db4220840138a96940d039adf871f76c9815551c5e3e5308e2198e025b65841843dc4f400ce8bcfca87795a2f12a2eb269c7efb36"          
      ));

    });

    group( "well known results decipher tests:", () {

      test( "'Lorem ipsum' cipher test", () => runStreamDecipherTest(
        new Salsa20Engine()..init(false, params),
        "9d8d611ee047b47fc5e2bd5db4284463008aa89c174093d3ce4b3e8cc2594acfe9a62a84388fe060f75247d425c2fe0cd283cfce887f5c6b5dfea86d927efb36",
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit ........"
      ));

      test( "'Quijote' cipher test", () => runStreamDecipherTest(
          new Salsa20Engine()..init(false, params),
          "948c330ee347b17ad1f6a25db4220840138a96940d039adf871f76c9815551c5e3e5308e2198e025b65841843dc4f400ce8bcfca87795a2f12a2eb269c7efb36",
          "En un lugar de La Mancha, de cuyo nombre no quiero acordarme ..."
      ));

    });

    group( "cipher+decipher tests:", () {

      test( "'Quijote' well known text", () => runStreamCipherDecipherTest(
          new Salsa20Engine(),
          params,
          createUint8ListFromString("En un lugar de La Mancha, de cuyo nombre no quiero acordarme ...")
      ));

      test( "1KB of sequential numbers test",  () => runStreamCipherDecipherTest(
          new Salsa20Engine(),
          params,
          createUint8ListFromSequentialNumbers(1024)
      ));

    });

  });
}

