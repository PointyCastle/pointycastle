// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.asymmetric.base_asymmetric_block_cipher;

import "dart:typed_data";

import "package:cipher/api.dart";

/// Base implementation of [AsymmetricBlockCipher] which provides shared methods.
abstract class BaseAsymmetricBlockCipher implements AsymmetricBlockCipher {

  Uint8List process(Uint8List data) {
    var out = new Uint8List(outputBlockSize);
    var len = processBlock(data, 0, data.length, out, 0);
    return out.sublist(0, len);
  }

}