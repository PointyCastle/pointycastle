// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.key_generator.ec_key_generator;

import "package:pointycastle/api.dart";
import "package:pointycastle/ecc/api.dart";
import "package:pointycastle/key_generators/api.dart";

/// Abstract [CipherParameters] to init an ECC key generator.
class ECKeyGenerator implements KeyGenerator {
  ECDomainParameters _params;
  SecureRandom _random;

  String get algorithmName => "EC";

  void init(CipherParameters params) {
    ECKeyGeneratorParameters ecparams;

    if (params is ParametersWithRandom) {
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
    var nBitLength = n.bitLength;
    var d;

    do {
      d = _random.nextBigInteger(nBitLength);
    } while (d == BigInt.zero || (d >= n));

    var Q = _params.G * d;

    return new AsymmetricKeyPair(
        new ECPublicKey(Q, _params), new ECPrivateKey(d, _params));
  }
}
