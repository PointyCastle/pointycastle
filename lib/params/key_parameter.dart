library cipher_params_key_parameter;

import "dart:typed_data";

import "package:cipher/api.dart";

class KeyParameter extends CipherParameters {
  
  final Uint8List key;
  
  KeyParameter(this.key);
  
}
