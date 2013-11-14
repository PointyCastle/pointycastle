// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.adapters.stream_cipher_adapters;

import "dart:typed_data";

import "package:cipher/api.dart";

/// An adapter to convert an [StreamCipher] to a [BlockCipher]
class StreamCipherAsBlockCipher implements BlockCipher {

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

/// An adapter to convert an [StreamCipher] based in a [BlockCipher] to a [ChainingBlockCipher]
class StreamCipherAsChainingBlockCipher extends StreamCipherAsBlockCipher implements ChainingBlockCipher {

  final BlockCipher underlyingCipher;

  /**
   * Create a [ChainingBlockCipher] from [streamCipher] simulating the given [blockSize] and the [underlyingCipher].
   * WARNING: it is the responsibility of the caller to make sure that the three given values altogether make sense and are
   * semantically correct. The [underlyingCipher] is not used at all, just returned to implement the [ChainingBlockCipher]
   * interface, so make sure it is valid and makes sense.
   */
  StreamCipherAsChainingBlockCipher(int blockSize, StreamCipher streamCipher, this.underlyingCipher) :
    super(blockSize, streamCipher);

}
