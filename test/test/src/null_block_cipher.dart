// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.engines.null_block_cipher;

import "dart:typed_data";

import "package:cipher/api.dart";

/**
 * An implementation of a null [BlockCipher], that is, a cipher that does not encrypt, neither decrypt. It can be used for
 * testing or benchmarking chaining algorithms.
 */
class NullBlockCipher implements BlockCipher {

  final int blockSize;

  NullBlockCipher([this.blockSize=16]);

  String get algorithmName => "Null";

  void reset() {
  }

  void init( bool forEncryption, CipherParameters params ) {
  }

  int processBlock( Uint8List inp, int inpOff, Uint8List out, int outOff ) {
      out.setRange( outOff, outOff+blockSize, inp.sublist(inpOff) );
      return blockSize;
  }

}

