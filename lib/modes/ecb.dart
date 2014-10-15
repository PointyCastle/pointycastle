// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.modes.ecb;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/block/base_block_cipher.dart";

/// Implementation of Electronic Code Book (ECB) mode on top of a [BlockCipher].
class ECBBlockCipher extends BaseBlockCipher {

  final BlockCipher _underlyingCipher;

  ECBBlockCipher(this._underlyingCipher);

  String get algorithmName => "${_underlyingCipher.algorithmName}/ECB";

  int get blockSize => _underlyingCipher.blockSize;

  void reset() {
    _underlyingCipher.reset();
  }

  void init(bool forEncryption, CipherParameters params) {
    _underlyingCipher.init(forEncryption, params);
  }

  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff)
    => _underlyingCipher.processBlock(inp, inpOff, out, outOff);

}
