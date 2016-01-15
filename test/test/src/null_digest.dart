// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.src.null_digest;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/src/impl/base_digest.dart";

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

