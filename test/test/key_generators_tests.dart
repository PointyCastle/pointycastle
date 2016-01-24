// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library pointycastle.test.test.key_generators_tests;

import "package:test/test.dart";
import "package:pointycastle/pointycastle.dart";

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

