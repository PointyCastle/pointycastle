// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.paddings.ecdsa_signer_test;

import 'package:bignum/bignum.dart';
import "package:cipher/cipher.dart";
import "package:cipher/impl/base.dart";

import "../test/signer_tests.dart";

/**
 * NOTE: the expected results for these tests are computed using the Java
 * version of Bouncy Castle
 */
void main() {

  initCipher();

  var eccDomain = new ECDomainParameters( "prime192v1" );

  var Qx = new BigInteger("1498602238651628509310686451034731914387602356706565103527");
  var Qy = new BigInteger("6264116558863692852155702059476882343593676720209154057133");
  var Q = eccDomain.curve.createPoint( Qx, Qy );
  var pubParams = new PublicKeyParameter( new ECPublicKey(Q, eccDomain));

  var d = new BigInteger("3062713166230336928689662410859599564103408831862304472446");
  var privParams = new PrivateKeyParameter( new ECPrivateKey(d, eccDomain) );

  runSignerTests( new Signer("ECDSA"), privParams, pubParams, [

    "Lorem ipsum dolor sit amet, consectetur adipiscing elit ........",
    _newSignature(
        "4165461920577864743570110591887661239883413257826890841803",
        "3921818269646681551036727339486031144481055001966973146395"
    ),

    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme ...",
    _newSignature(
        "4165461920577864743570110591887661239883413257826890841803",
        "4966480092874390501758979364830358346132047144845401039538"
    ),

  ]);
}

ECSignature _newSignature(String r, String s)
  => new ECSignature( new BigInteger(r), new BigInteger(s) );
