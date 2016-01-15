// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.random.block_ctr_random;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/src/ufixnum.dart";
import "package:cipher/src/impl/secure_random_base.dart";

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
