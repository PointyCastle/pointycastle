// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.key_generators.ec_key_generator;

import "package:cipher/api.dart";
import "package:cipher/params/parameters_with_random.dart";
import "package:cipher/params/key_generators/ec_key_generator_parameters.dart";

class ECKeyGenerator implements KeyGenerator {

  ECDomainParameters _params;
  SecureRandom _random;

  String get algorithmName => "EC";

  void init(CipherParameters params) {
    ECKeyGeneratorParameters ecparams;

    if( params is ParametersWithRandom ) {
      _random = params.random;
      ecparams = params.parameters;
    } else {
      _random = new SecureRandom();
      ecparams = params;
    }

    _params = ecparams.domainParameters;
  }

  AsymmetricKeyPair generateKeyPair() {
    var n = _params.n;
    var nBitLength = n.bitLength();
    var d;

    do {
      d = _random.nextBigInteger(nBitLength);//new BigInteger(nBitLength, _random);
    } while( d==BigInteger.ZERO || (d>=n) );

    var Q = _params.G*d;

    return new AsymmetricKeyPair(
      new ECPublicKey(Q, _params),
      new ECPrivateKey(d, _params)
    );
  }

}
