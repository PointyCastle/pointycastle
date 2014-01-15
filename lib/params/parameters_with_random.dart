// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com  
// Use of this source code is governed by a LGPL v3 license. 
// See the LICENSE file for more information.

library cipher.params.parameters_with_random;

import "package:cipher/api.dart";

class ParametersWithRandom<UnderlyingParameters extends CipherParameters> implements CipherParameters {
  
  final UnderlyingParameters parameters;
  final SecureRandom random;

  ParametersWithRandom(this.parameters,this.random);

}
