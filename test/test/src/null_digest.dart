// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.src.null_digest;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/digests/base_digest.dart";

/**
 * An implementation of a null [Digest], that is, a digest that returns an empty string. It can be
 * used for testing or benchmarking chaining algorithms.
 */
class NullDigest extends BaseDigest {

  final int digestSize;

  NullDigest([this.digestSize=32]);

  final String algorithmName = "Null";

  void reset() {
  }

  void updateByte(int inp) {
  }

  void update(Uint8List inp, int inpOff, int len) {
  }

  int doFinal(Uint8List out, int outOff) {
    out.fillRange(0, digestSize, 0);
    return digestSize;
  }

}

