// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.block_cipher.modes.sic;

import "package:pointycastle/api.dart";
import "package:pointycastle/adapters/stream_cipher_as_block_cipher.dart";
import "package:pointycastle/stream/sic.dart";
import "package:pointycastle/src/registry/registry.dart";

/**
 * See [SICStreamCipher].
 */
class SICBlockCipher extends StreamCipherAsBlockCipher {

  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG =
      new DynamicFactoryConfig.suffix("/SIC", (final String algorithmName, _) => () {
        int sep = algorithmName.lastIndexOf("/");
        BlockCipher underlying = new BlockCipher(algorithmName.substring(0, sep));
        return new SICBlockCipher(underlying.blockSize, new SICStreamCipher(underlying));
      });

  SICBlockCipher(int blockSize, StreamCipher underlyingCipher)
    : super(blockSize, underlyingCipher);

}