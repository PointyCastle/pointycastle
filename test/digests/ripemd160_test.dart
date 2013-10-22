library ripemd160_test;

import "dart:typed_data";

import "package:cipher/digests/ripemd160.dart";

import "package:unittest/unittest.dart";

import "../test_helpers/test_helpers.dart";


/**
 * NOTE: the expected results for these tests are computed using the Java
 * version of Bouncy Castle (except for abc and empty string which were taken
 * from http://homes.esat.kuleuven.be/~bosselae/ripemd160.html).
 */
void main() {

  group( "RIPEMD160:", () {

    group( "well known results tests:", () {

      void runTest( String messageString, String expectedOut ) {
        var message = createUint8ListFromString( messageString );
        var ripemd = new RIPEMD160Digest();

        var out = new Uint8List(ripemd.digestSize);
        ripemd.update( message, 0, message.length );
        ripemd.doFinal( out, 0 );

        var hexOut = formatBytesAsHexString(out);

        expect( hexOut, equals(expectedOut) );
      }

      test( "'Lorem ipsum' digest test", () {
        var plainText = "Lorem ipsum dolor sit amet, consectetur adipiscing elit...";
        var expectedHexCipherText = "7cc186f1d641709ec2bd363b10d3d66f122b365e";
        runTest( plainText, expectedHexCipherText );
      });

      test( "'Quijote' digest test", () {
        var plainText = "En un lugar de La Mancha, de cuyo nombre no quiero acordarme ...";
        var expectedHexCipherText = "48573da6caf89431a195e70f305f0df3b4f7ace6";
        runTest( plainText, expectedHexCipherText );
      });

      test( "'abc' digest test", () {
        var plainText = "abc";
        var expectedHexCipherText = "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc";
        runTest( plainText, expectedHexCipherText );
      });

      test( "(empty string) digest test", () {
        var plainText = "";
        var expectedHexCipherText = "9c1185a5c5e9fc54612808977ee8f548b2258d31";
        runTest( plainText, expectedHexCipherText );
      });

    });

  });

}

