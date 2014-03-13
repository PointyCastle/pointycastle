// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.benchmark.digests.aes_fast_benchmark;

import "dart:typed_data";

import "package:cipher/cipher.dart";

import "../benchmark/block_cipher_benchmark.dart";

void main() {
  new BlockCipherBenchmark("AES", "128", true,  () => new KeyParameter(new Uint8List(16))).report();
  new BlockCipherBenchmark("AES", "128", false, () => new KeyParameter(new Uint8List(16))).report();

  new BlockCipherBenchmark("AES", "192", true,  () => new KeyParameter(new Uint8List(24))).report();
  new BlockCipherBenchmark("AES", "192", false, () => new KeyParameter(new Uint8List(24))).report();

  new BlockCipherBenchmark("AES", "256", true,  () => new KeyParameter(new Uint8List(32))).report();
  new BlockCipherBenchmark("AES", "256", false, () => new KeyParameter(new Uint8List(32))).report();
}
