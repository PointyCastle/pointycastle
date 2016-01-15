// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.src.null_stream_cipher;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/src/impl/base_stream_cipher.dart";

/**
 * An implementation of a null [StreamCipher], that is, a cipher that does not encrypt, neither decrypt. It can be used for
 * testing or benchmarking chaining algorithms.
 */
class NullStreamCipher extends BaseStreamCipher {

  String get algorithmName => "Null";

  void reset() {
  }

  void init(bool forEncryption, CipherParameters params) {
  }

  void processBytes(Uint8List inp, int inpOff, int len, Uint8List out, int outOff) {
    out.setRange( outOff, outOff+len, inp.sublist(inpOff) );
  }

  int returnByte(int inp) {
    return inp;
  }

}

