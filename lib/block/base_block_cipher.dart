// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.block.base_block_cipher;

import "dart:typed_data";

import "package:cipher/api.dart";

/// Base implementation of [BlockCipher] which provides shared methods.
abstract class BaseBlockCipher implements BlockCipher {

  Uint8List process(Uint8List data) {
    var out = new Uint8List(blockSize);
    var len = processBlock(data, 0, out, 0);
    return out.sublist(0, len);
  }

}