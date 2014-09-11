// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.key_generators.api;

import "package:bignum/bignum.dart";

import "package:cipher/api.dart";
import "package:cipher/ecc/api.dart";

/// Abstract [CipherParameters] to init an ECC key generator.
class ECKeyGeneratorParameters extends KeyGeneratorParameters {

  ECDomainParameters _domainParameters;

  ECKeyGeneratorParameters(ECDomainParameters domainParameters)
      : super(domainParameters.n.bitLength()) {
    _domainParameters = domainParameters;
  }

  ECDomainParameters get domainParameters => _domainParameters;

}

/// Abstract [CipherParameters] to init an RSA key generator.
class RSAKeyGeneratorParameters extends KeyGeneratorParameters {

  final BigInteger publicExponent;
  final int certainty;

  RSAKeyGeneratorParameters(this.publicExponent, int bitStrength, this.certainty)
      : super(bitStrength);

}
