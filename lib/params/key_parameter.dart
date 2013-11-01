// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com  
// Use of this source code is governed by a LGPL v3 license. 
// See the LICENSE file for more information.

library cipher.params.key_parameter;

import "dart:typed_data";

import "package:cipher/api.dart";

class KeyParameter extends CipherParameters {
  
  final Uint8List key;
  
  KeyParameter(this.key);
  
}
