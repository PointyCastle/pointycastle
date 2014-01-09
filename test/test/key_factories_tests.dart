// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.test.key_factories_tests;

import "dart:typed_data";

import "package:cipher/api.dart";

import "package:unittest/unittest.dart";

import "./helpers.dart";

void runKeyFactoryTests( KeyFactory keyFactory, List<dynamic> paramsPasswordKeyTuples ) {

  group( "${keyFactory.algorithmName}:", () {

    group( "deriveKey:", () {

      for( var i=0 ; i<paramsPasswordKeyTuples.length ; i+=3 ) {

        var params = paramsPasswordKeyTuples[i];
        var password = paramsPasswordKeyTuples[i+1];
        var key = paramsPasswordKeyTuples[i+2];

        test( "${formatAsTruncated(password)}", () =>
          _runKeyFactoryTest( keyFactory, params, password, key )
        );

      }
    });

  });

}

void _runKeyFactoryTest( KeyFactory keyFactory, CipherParameters params, String password, String expectedHexKey ) {

  keyFactory.init(params);

  var out = new Uint8List(keyFactory.keySize);
  var passwordBytes = createUint8ListFromString( password );
  keyFactory.deriveKey(passwordBytes, 0, out, 0);

  var hexOut = formatBytesAsHexString(out);
  expect( hexOut, equals(expectedHexKey) );

}

