// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.test.key_generators_tests;

import "package:cipher/api.dart";

import "package:unittest/unittest.dart";

void runKeyGeneratorTests( KeyGenerator keyGenerator, List<AsymmetricKeyPair> expectedKeyPairs ) {

  group( "${keyGenerator.algorithmName}:", () {

    group( "generateKeyPair:", () {

      for( var i=0 ; i<expectedKeyPairs.length ; i++ ) {

        test( "${i}", () =>
          _runKeyGeneratorTest( keyGenerator, expectedKeyPairs[i] )
        );

      }
    });

  });

}

void _runKeyGeneratorTest( KeyGenerator keyGenerator, AsymmetricKeyPair expectedKeyPair ) {
  var keyPair = keyGenerator.generateKeyPair();

  expect( keyPair.privateKey, equals(expectedKeyPair.privateKey) );
  expect( keyPair.publicKey, equals(expectedKeyPair.publicKey) );
}

