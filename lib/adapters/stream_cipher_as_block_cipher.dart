// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library pointycastle.impl.adapters.stream_cipher_as_block_cipher;

import "dart:typed_data";

import "package:pointycastle/api.dart";
import "package:pointycastle/src/impl/base_block_cipher.dart";

/// An adapter to convert an [StreamCipher] to a [BlockCipher]
class StreamCipherAsBlockCipher extends BaseBlockCipher {

  final StreamCipher streamCipher;
  final int blockSize;

  /// Create a [BlockCipher] from [streamCipher] simulating the given [blockSize]
  StreamCipherAsBlockCipher( this.blockSize, this.streamCipher );

  String get algorithmName => streamCipher.algorithmName;

  void reset() {
    streamCipher.reset();
  }

  void init(bool forEncryption, CipherParameters params) {
    streamCipher.init(forEncryption, params);
  }

  int processBlock( Uint8List inp, int inpOff, Uint8List out, int outOff ) {
    streamCipher.processBytes(inp, inpOff, blockSize, out, outOff);
    return blockSize;
  }

}
