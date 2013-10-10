library cipher_params_parameters_with_iv;

import "dart:typed_data";

import "package:cipher/api.dart";

class ParametersWithIV<UnderlyingParameters extends CipherParameters> implements CipherParameters {
  
    final Uint8List iv;
    final UnderlyingParameters parameters;

    ParametersWithIV( this.parameters, this.iv );

}
