// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.params.key_generators.ec_key_generator_parameters;

import "package:cipher/api.dart";
import "package:cipher/params/key_generators/key_generator_parameters.dart";

/// Abstract [CipherParameters] to init an ECC key generator.
class ECKeyGeneratorParameters extends KeyGeneratorParameters {

  ECDomainParameters _domainParameters;

  ECKeyGeneratorParameters(ECDomainParameters domainParameters)
    : super(domainParameters.n.bitLength()) {
    _domainParameters = domainParameters;
  }

  ECDomainParameters get domainParameters => _domainParameters;

}
