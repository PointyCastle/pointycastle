// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.test.key_factories_tests;

import "dart:typed_data";

import "package:cipher/api.dart";

import "package:unittest/unittest.dart";

import "./helpers.dart";

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

  var out = new Uint8List(keyDerivator.keySize);
  var passwordBytes = createUint8ListFromString( password );
  keyDerivator.deriveKey(passwordBytes, 0, out, 0);

  var hexOut = formatBytesAsHexString(out);
  expect( hexOut, equals(expectedHexKey) );

}

