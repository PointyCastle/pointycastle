// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

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
