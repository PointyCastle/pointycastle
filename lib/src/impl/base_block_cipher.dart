// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.impl.base_block_cipher;

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