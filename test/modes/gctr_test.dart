// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.test.modes.gctr_test;

import "dart:typed_data";

import "package:pointycastle/pointycastle.dart";

import "../test/block_cipher_tests.dart";
import "../test/src/null_block_cipher.dart";

void main() {
  initCipher();
  BlockCipher.registry["Null-8"] = (_) => new NullBlockCipher(8);

  final iv = new Uint8List.fromList([
    0x00,
    0x11,
    0x22,
    0x33,
    0x44,
    0x55,
    0x66,
    0x77,
    0x88,
    0x99,
    0xAA,
    0xBB,
    0xCC,
    0xDD,
    0xEE,
    0xFF
  ]);
  final params = new ParametersWithIV(null, iv);

  runBlockCipherTests(new BlockCipher("Null-8/GCTR"), params, [
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit ........",
    "4d7d515125760e0871664915283804167134565f2478081761610a17373604086075535d2c2f195c6773414935280f14697f095f0c35195e263704154a734051",
    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme ...",
    "447c034126760b0d6572561528324835623468573e3b011b28354252743a1f026a36495735381919267947192d2e05187577095b03331f1a696b475e44734051",
  ]);
}
