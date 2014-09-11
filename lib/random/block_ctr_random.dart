// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.random.block_ctr_random;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/src/ufixnum.dart";
import "package:cipher/random/secure_random_base.dart";

/**
 * An implementation of [SecureRandom] that uses a [BlockCipher] with CTR mode to generate random
 * values.
 */
class BlockCtrRandom extends SecureRandomBase implements SecureRandom {

  final BlockCipher cipher;

  Uint8List _input;
  Uint8List _output;
  var _used;

  BlockCtrRandom(this.cipher) {
    _input = new Uint8List(cipher.blockSize);
    _output = new Uint8List(cipher.blockSize);
    _used = _output.length;
  }

  String get algorithmName => "${cipher.algorithmName}/CTR/PRNG";

  void seed(CipherParameters params) {
    _used = _output.length;
    if (params is ParametersWithIV) {
      _input.setAll(0, params.iv);
      cipher.init(true, params.parameters);
    } else {
      cipher.init(true, params);
    }
  }

  int nextUint8() {
    if( _used==_output.length ) {
      cipher.processBlock(_input, 0, _output, 0);
      _used = 0;
      _incrementInput();
    }

    return clip8(_output[_used++]);
  }

  void _incrementInput() {
    int offset = _input.length;
    do {
      offset--;
      _input[offset] += 1;
    } while( _input[offset]==0 );
  }

}
