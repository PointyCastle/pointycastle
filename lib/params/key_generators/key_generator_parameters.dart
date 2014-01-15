// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.params.key_generators.key_generator_parameters;

import "package:cipher/api.dart";

/// Abstract [CipherParameters] to init an asymmetric key generator.
abstract class KeyGeneratorParameters implements CipherParameters {

  final int bitStrength;

  KeyGeneratorParameters(this.bitStrength);

}
