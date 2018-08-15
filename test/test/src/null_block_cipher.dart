// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.block_cipher.test.src.null_block_cipher;

import "dart:typed_data";

import "package:pointycastle/api.dart";
import "package:pointycastle/src/impl/base_block_cipher.dart";

/**
 * An implementation of a null [BlockCipher], that is, a cipher that does not encrypt, neither decrypt. It can be used for
 * testing or benchmarking chaining algorithms.
 */
class NullBlockCipher extends BaseBlockCipher {
  final int blockSize;

  NullBlockCipher([this.blockSize = 16]);

  String get algorithmName => "Null";

  void reset() {}

  void init(bool forEncryption, CipherParameters params) {}

  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    out.setRange(outOff, outOff + blockSize, inp.sublist(inpOff));
    return blockSize;
  }
}
