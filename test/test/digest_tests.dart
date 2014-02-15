// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.test.digest_tests;

import "package:cipher/cipher.dart";
import "package:unittest/unittest.dart";

import "./src/helpers.dart";

void runDigestTests( Digest digest, List<String> plainDigestTextPairs ) {

  group( "${digest.algorithmName}:", () {

    group( "digest:", () {

      for( var i=0 ; i<plainDigestTextPairs.length ; i+=2 ) {

        var plainText = plainDigestTextPairs[i];
        var digestText = plainDigestTextPairs[i+1];

        test( "${formatAsTruncated(plainText)}", () =>
          _runDigestTest( digest, plainText, digestText )
        );

      }
    });

  });

}

void _runDigestTest( Digest digest, String plainTextString, String expectedHexDigestText ) {
  digest.reset();

  var plainText = createUint8ListFromString( plainTextString );
  var out = digest.process(plainText);
  var hexOut = formatBytesAsHexString(out);

  expect( hexOut, equals(expectedHexDigestText) );
}

