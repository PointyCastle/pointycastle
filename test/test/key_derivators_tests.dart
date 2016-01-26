// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.test.key_derivators_tests;

import "package:cipher/cipher.dart";
import "package:test/test.dart";

import "./src/helpers.dart";

void runKeyDerivatorTests( KeyDerivator keyDerivator, List<dynamic> paramsPasswordKeyTuples ) {

  group( "${keyDerivator.algorithmName}:", () {

    group( "deriveKey:", () {

      for( var i=0 ; i<paramsPasswordKeyTuples.length ; i+=3 ) {

        var params = paramsPasswordKeyTuples[i];
        var password = paramsPasswordKeyTuples[i+1];
        var key = paramsPasswordKeyTuples[i+2];

        test( "${formatAsTruncated(password)}", () =>
          _runKeyDerivatorTest( keyDerivator, params, password, key )
        );

      }
    });

  });

}

void _runKeyDerivatorTest( KeyDerivator keyDerivator, CipherParameters params, String password, String expectedHexKey ) {
  keyDerivator.init(params);

  var passwordBytes = createUint8ListFromString( password );
  var out = keyDerivator.process(passwordBytes);
  var hexOut = formatBytesAsHexString(out);

  expect( hexOut, equals(expectedHexKey) );
}

