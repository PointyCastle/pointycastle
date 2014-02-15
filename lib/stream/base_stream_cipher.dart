// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.stream.base_stream_cipher;

import "dart:typed_data";

import "package:cipher/api.dart";

/// Base implementation of [StreamCipher] which provides shared methods.
abstract class BaseStreamCipher implements StreamCipher {

  Uint8List process(Uint8List data) {
    var out = new Uint8List(data.length);
    processBytes(data, 0, data.length, out, 0);
    return out;
  }

}