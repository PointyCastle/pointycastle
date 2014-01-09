// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.params.pbkdf2_parameters;

import "dart:typed_data";

import "package:cipher/api.dart";

/// [CipherParameters] used by PBKDF2.
class Pbkdf2Parameters extends CipherParameters {

  final Uint8List salt;
  final int iterationCount;
  final int desiredKeyLength;

  Pbkdf2Parameters(this.salt, this.iterationCount, this.desiredKeyLength);

}
