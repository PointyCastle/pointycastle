// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.test.padding_tests;

import "dart:typed_data";

import "package:cipher/cipher.dart";
import "package:unittest/unittest.dart";

import "./src/helpers.dart";

void runPaddingTest( Padding pad, CipherParameters params,
                     String unpadData, int padLength, String padData ) {

  group( "${pad.algorithmName}:", () {

    test( "addPadding: $unpadData", () {

      var expectedBytes = createUint8ListFromHexString( padData );
      var dataBytes = new Uint8List( padLength )
        ..setAll( 0, unpadData.codeUnits )
      ;

      pad.init( params );
      var ret = pad.addPadding( dataBytes, unpadData.length );

      expect( ret, equals( padLength-unpadData.length ) );
      expect( dataBytes, equals(expectedBytes) );

    });

    test( "padCount: $padData", () {

      var dataBytes = createUint8ListFromHexString( padData );

      pad.init( params );
      var ret = pad.padCount( dataBytes );

      expect( ret, equals( padLength-unpadData.length ) );

    });

  });

}

