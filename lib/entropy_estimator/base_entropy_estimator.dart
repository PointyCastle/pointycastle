// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.entropy_estimator.base_entropy_estimator;

import "dart:typed_data";

import "package:cipher/api.dart";

/// Base implementation of [EntropyEstimator] which provides shared methods.
abstract class BaseEntropyEstimator implements EntropyEstimator {

  final _byteBuffer = new Uint8List(1);

  void updateByte(int inp) {
    _byteBuffer[0] = inp;
    update(_byteBuffer, 0, 1);
  }

  int process(Uint8List data) {
    reset();
    update(data, 0, data.length);
    return estimatedEntropy;
  }

}