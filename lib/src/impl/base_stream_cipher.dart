// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.src.impl.base_stream_cipher;

import "dart:typed_data";

import "package:pointycastle/api.dart";

/// Base implementation of [StreamCipher] which provides shared methods.
abstract class BaseStreamCipher implements StreamCipher {

  Uint8List process(Uint8List data) {
    var out = new Uint8List(data.length);
    processBytes(data, 0, data.length, out, 0);
    return out;
  }

}