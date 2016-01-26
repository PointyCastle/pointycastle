// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.test.mac_tests;

import "package:cipher/cipher.dart";
import "package:test/test.dart";

import "./src/helpers.dart";

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
  mac.reset();

  var plainText = createUint8ListFromString( plainTextString );
  var out = mac.process(plainText);
  var hexOut = formatBytesAsHexString(out);

  expect( hexOut, equals(expectedHexDigestText) );
}

