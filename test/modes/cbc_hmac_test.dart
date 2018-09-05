// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.test.modes.cbc_test;

import "dart:typed_data";

import "package:pointycastle/pointycastle.dart";

import "package:pointycastle/block/aes_fast.dart";
import "package:pointycastle/block/modes/cbc_hmac.dart";
import "../test/src/helpers.dart";
import "../test/aead_cipher_tests.dart";
import 'package:test/test.dart';

void main() {
  final iv = new Uint8List.fromList([
    3, 22, 60, 12, 43, 67, 104, 105, 108, 108, 105, 99, 111, 116, 104,
    101
  ]);
  final tag = new Uint8List.fromList([
    83, 73, 191, 98, 104, 205, 211, 128, 201, 189, 199, 133, 32, 38,
  194, 85]);
  final aad = new Uint8List.fromList(
      [101, 121, 74, 104, 98, 71, 99, 105, 79, 105, 74, 66, 77, 84, 73, 52,
      83, 49, 99, 105, 76, 67, 74, 108, 98, 109, 77, 105, 79, 105, 74, 66,
      77, 84, 73, 52, 81, 48, 74, 68, 76, 85, 104, 84, 77, 106, 85, 50, 73,
      110, 48]);
  final params = new AEADParameters(
      new KeyParameter(new Uint8List.fromList(
          [4, 211, 31, 197, 84, 157, 252, 254, 11, 100, 157, 250, 63, 170, 106,
          206, 107, 124, 212, 45, 111, 107, 9, 219, 200, 177, 0, 240, 143, 156,
          44, 207])),
      128,
      iv,
      aad);


  var cipher = new CBCHMACAuthenticatedEncryptionCipher(new AESFastEngine());
  group( "${cipher.algorithmName}:", () {

    runAEADBlockCipherTests( cipher,
        params, [

          "Live long and prosper.",
          "283953b577218594c6b9f31898e6064b81df7f13d252b7e6a821d7688f703866"+formatBytesAsHexString(tag),

        ] );


  });

}

