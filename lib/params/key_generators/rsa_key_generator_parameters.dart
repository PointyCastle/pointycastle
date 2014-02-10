// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.params.key_generators.rsa_key_generator_parameters;

import "package:bignum/bignum.dart";
import "package:cipher/api.dart";
import "package:cipher/params/key_generators/key_generator_parameters.dart";

/// Abstract [CipherParameters] to init an RSA key generator.
class RSAKeyGeneratorParameters extends KeyGeneratorParameters {

  final BigInteger publicExponent;
  final int certainty;

  RSAKeyGeneratorParameters(this.publicExponent, int bitStrength, this.certainty) : super(bitStrength);

}
