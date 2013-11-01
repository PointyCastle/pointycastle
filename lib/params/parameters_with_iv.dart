// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com  
// Use of this source code is governed by a LGPL v3 license. 
// See the LICENSE file for more information.

library cipher.params.parameters_with_iv;

import "dart:typed_data";

import "package:cipher/api.dart";

class ParametersWithIV<UnderlyingParameters extends CipherParameters> implements CipherParameters {
  
    final Uint8List iv;
    final UnderlyingParameters parameters;

    ParametersWithIV( this.parameters, this.iv );

}
