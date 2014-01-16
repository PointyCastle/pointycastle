// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.test.signer_tests;

import "package:cipher/api.dart";
import "package:cipher/params/parameters_with_random.dart";

import "package:unittest/unittest.dart";

import "./src/null_secure_random.dart";
import "src/helpers.dart";

void runSignerTests( Signer signer, CipherParameters signParams, CipherParameters verifyParams, List<String> messageSignaturePairs ) {

  group( "${signer.algorithmName}:", () {

    group( "generateSignature:", () {

      for( var i=0 ; i<messageSignaturePairs.length ; i+=2 ) {

        var message = messageSignaturePairs[i];
        var signature = messageSignaturePairs[i+1];

        test( "${formatAsTruncated(message)}", () =>
          _runGenerateSignatureTest( signer, signParams, message, signature )
        );

      }

    });

    group( "verifySignature:", () {

      for( var i=0 ; i<messageSignaturePairs.length ; i+=2 ) {

        var message = messageSignaturePairs[i];
        var signature = messageSignaturePairs[i+1];

        test( "${formatAsTruncated(message)}", () =>
          _runVerifySignatureTest( signer, verifyParams, message, signature )
        );

      }

    });

  });

}

void _runGenerateSignatureTest(Signer signer, CipherParameters params, String message, Signature expectedSignature) {
  var paramsWithRandom = new ParametersWithRandom( params, new NullSecureRandom() );

  signer.reset();
  signer.init(true, paramsWithRandom);

  var signature = signer.generateSignature(createUint8ListFromString(message));

  expect( signature, expectedSignature );
}

void _runVerifySignatureTest(Signer signer, CipherParameters params, String message, Signature signature) {
  signer.reset();
  signer.init(false, params);

  var ok = signer.verifySignature(createUint8ListFromString(message), signature);

  expect( ok, true );
}


