// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.key_generators.ec_key_generator_test;

import 'package:bignum/bignum.dart';

import 'package:cipher/api.dart';
import 'package:cipher/impl.dart';

import 'package:cipher/key_generators/ec_key_generator.dart';
import "package:cipher/params/parameters_with_random.dart";
import "package:cipher/params/key_generators/ec_key_generator_parameters.dart";

import "../test/src/null_secure_random.dart";
import '../test/key_generators_tests.dart';


/// NOTE: the expected results for these tests are taken from the Bouncy Castle Java implementation
void main() {

  initCipher();

  var rnd = new NullSecureRandom();

  var domainParams = new ECDomainParameters("prime192v1");
  var ecParams = new ECKeyGeneratorParameters(domainParams);
  var params = new ParametersWithRandom<ECKeyGeneratorParameters>(ecParams, rnd);

  var keyGenerator = new ECKeyGenerator();
  keyGenerator.init(params);

  runKeyGeneratorTests( keyGenerator, [

    _keyPair( domainParams,
        "4165461920577864743570110591887661239883413257826890841803",
        "433060747015770533144900903117711353276551186421527917903",
        "96533667595335344311200144916688449305687896108635671"
    ),

    _keyPair( domainParams,
        "952128485350936803657958938747669190775028076767588715981",
        "2074616205026821401743282701487442392635099812302414322181",
        "590882579351047642528856087035049998200115612080958942767"
    ),

    _keyPair( domainParams,
        "24186169899158470982826728287136856913767539338281496876",
        "2847521372076459404463997303980674024509607281070145578802",
        "1181668625034499949713400973925183307950925536265809249863"
    ),

  ]);

}

AsymmetricKeyPair _keyPair( ECDomainParameters domainParams, String Qx, String Qy, String d )
  => new AsymmetricKeyPair(
      new ECPublicKey( domainParams.curve.createPoint(
          new BigInteger(Qx),
          new BigInteger(Qy)
      ), domainParams ),
      new ECPrivateKey(
          new BigInteger(d),
      domainParams)
  );
