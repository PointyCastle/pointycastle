// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.random.fortuna_random;

import "dart:typed_data";

import "package:bignum/bignum.dart";

import "package:cipher/api.dart";
import "package:cipher/block/aes_fast.dart";
import "package:cipher/random/auto_seed_block_ctr_random.dart";
import "package:cipher/params/parameters_with_iv.dart";
import "package:cipher/params/key_parameter.dart";

/// An implementation of [SecureRandom] as specified in the Fortuna algorithm.
class FortunaRandom implements SecureRandom {

  AESFastEngine _aes;
  AutoSeedBlockCtrRandom _prng;

  String get algorithmName => "Fortuna";

  FortunaRandom() {
    _aes = new AESFastEngine();
    _prng = new AutoSeedBlockCtrRandom(_aes, false);
  }

  void seed(KeyParameter param) {
    if (param.key.length != 32) {
      throw new ArgumentError("Fortuna PRNG can only be used with 256 bits keys");
    }

    final iv = new Uint8List(16);
    iv[15] = 1;
    _prng.seed(new ParametersWithIV(param, iv));
  }

  int nextUint8() => _prng.nextUint8();

  int nextUint16() => _prng.nextUint16();

  int nextUint32() => _prng.nextUint32();

  BigInteger nextBigInteger(int bitLength) => _prng.nextBigInteger(bitLength);

  Uint8List nextBytes(int count) {
    if (count > 1048576) {
      throw new ArgumentError(
          "Fortuna PRNG cannot generate more than 1MB of random data per invocation");
    }

    return _prng.nextBytes(count);
  }
}
