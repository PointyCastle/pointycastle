// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.paddings.ecdsa_signer_test;

import "package:unittest/unittest.dart";

import "package:cipher/api.dart";
import "package:cipher/impl.dart";
import "package:cipher/signers/ecdsa_signer.dart";
import "package:cipher/params/ec_key_parameters.dart";
import "package:cipher/params/parameters_with_random.dart";
import "package:cipher/ecc/ecc.dart";
//import "package:cipher/ecc/ecc_fp.dart";

import "../test/helpers.dart";

void main() {

  initCipher();

  group( "ECDSASigner:", () {

    test( "generateSignature()", () {

      var plainText = "Lorem ipsum dolor sit amet, consectetur adipiscing elit ........";
      var expectedSignature = "(4165461920577864743570110591887661239883413257826890841803,3921818269646681551036727339486031144481055001966973146395)";

      var message = createUint8ListFromString( plainText );

      var signer = new ECDSASigner();

      ECDomainParameters dpar = new ECDomainParameters( "prime192v1" );

      BigInteger D = new BigInteger("3062713166230336928689662410859599564103408831862304472446");
      BigInteger q = new BigInteger("6277101735386680763835789423207666416083908700390324961279");
      BigInteger px = new BigInteger("1498602238651628509310686451034731914387602356706565103527");
      BigInteger py = new BigInteger("6264116558863692852155702059476882343593676720209154057133");
      ECPrivateKeyParameters privparams = new ECPrivateKeyParameters(D, dpar);
      SecureRandom secrnd = new NullSecureRandom();
      ParametersWithRandom params = new ParametersWithRandom( privparams, secrnd );
      signer.init(true, params);

      var signature = signer.generateSignature(message);
      expect( signature.toString(), expectedSignature );

    });

  });

}

class NullSecureRandom extends SecureRandomBase {

  var _nextValue=0;

  String get algorithmName => "Null";

  void init(CipherParameters params) {
  }

  Uint8 nextUint8() => new Uint8(_nextValue++);

}

