// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.test.mac_tests;

import "dart:typed_data";

import "package:cipher/api.dart";

import "package:unittest/unittest.dart";

import "src/helpers.dart";

void runMacTests( Mac mac, List<String> plainDigestTextPairs ) {

  group( "${mac.algorithmName}:", () {

    group( "digest:", () {

      for( var i=0 ; i<plainDigestTextPairs.length ; i+=2 ) {

        var plainText = plainDigestTextPairs[i];
        var digestText = plainDigestTextPairs[i+1];

        test( "${formatAsTruncated(plainText)}", () =>
          _runMacTest( mac, plainText, digestText )
        );

      }
    });

  });

}

void _runMacTest( Mac mac, String plainTextString, String expectedHexDigestText ) {
  var plainText = createUint8ListFromString( plainTextString );

  var out = new Uint8List(mac.macSize);

  mac.reset();
  mac.update( plainText, 0, plainText.length );
  mac.doFinal( out, 0 );

  var hexOut = formatBytesAsHexString(out);

  expect( hexOut, equals(expectedHexDigestText) );
}

