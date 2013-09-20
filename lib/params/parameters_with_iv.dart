library cipher_params_parameters_with_iv;

import "dart:typed_data";

import "package:cipher/api.dart";

class ParametersWithIV implements CipherParameters {
  
    final Uint8List iv;
    final CipherParameters parameters;

    ParametersWithIV( this.parameters, this.iv );

}
