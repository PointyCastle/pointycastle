// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.src.null_asymmetric_block_cipher;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/asymmetric/base_asymmetric_block_cipher.dart";

/**
 * An implementation of a null [AsymmetricBlockCipher], that is, a cipher that does not encrypt, neither decrypt. It can be used
 * for testing or benchmarking chaining algorithms.
 */
class NullAsymmetricBlockCipher extends BaseAsymmetricBlockCipher {

  final int inputBlockSize;
  final int outputBlockSize;

  NullAsymmetricBlockCipher(this.inputBlockSize, this.outputBlockSize);

  String get algorithmName => "Null";

  void reset() {
  }

  void init(bool forEncryption, CipherParameters params) {
  }

  int processBlock(Uint8List inp, int inpOff, int len, Uint8List out, int outOff) {
    out.setRange(outOff, outOff+len, inp.sublist(inpOff));
    return len;
  }

}

class NullAsymmetricKey implements AsymmetricKey {}
class NullPublicKey extends NullAsymmetricKey implements PublicKey {}
class NullPrivateKey extends NullAsymmetricKey implements PrivateKey {}

