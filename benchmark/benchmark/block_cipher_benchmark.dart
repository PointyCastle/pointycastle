// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.benchmark.benchmark.block_cipher_benchmark;

import "dart:typed_data";

import "package:cipher/cipher.dart";

import "../benchmark/rate_benchmark.dart";

typedef CipherParameters CipherParametersFactory();

class BlockCipherBenchmark extends RateBenchmark {

  final String _blockCipherName;
  final bool _forEncryption;
  final CipherParametersFactory _cipherParametersFactory;
  Uint8List _data;

  BlockCipher _blockCipher;

  BlockCipherBenchmark(String blockCipherName, String blockCipherVariant, bool forEncryption,
      this._cipherParametersFactory) :
    super("BlockCipher | $blockCipherName - $blockCipherVariant - "
        "${forEncryption ? 'encrypt' : 'decrypt' }"),
    _blockCipherName = blockCipherName,
    _forEncryption = forEncryption;

  void setup() {
    initCipher();
    _blockCipher = new BlockCipher(_blockCipherName);
    _blockCipher.init(_forEncryption, _cipherParametersFactory());
    _data = new Uint8List(_blockCipher.blockSize);
  }

  void run() {
    _blockCipher.process(_data);
    addSample(_data.length);
  }

}
