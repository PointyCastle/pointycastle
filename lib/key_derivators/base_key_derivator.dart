// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.key_derivators.base_key_derivator;

import "dart:typed_data";

import "package:cipher/api.dart";

/// Base implementation of [KeyDerivator] which provides shared methods.
abstract class BaseKeyDerivator implements KeyDerivator {

  Uint8List process(Uint8List data) {
    var out = new Uint8List(keySize);
    var len = deriveKey(data, 0, out, 0);
    return out.sublist(0, len);
  }

}