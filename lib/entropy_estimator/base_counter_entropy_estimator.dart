// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.entropy_estimator.base_counter_entropy_estimator;

import "dart:typed_data";

import "package:cipher/api.dart";

import "./base_entropy_estimator.dart";

/**
 * This interface must be implemented by functions that estimate the entropy in sampled data. It
 * must return a number between 0 and [dataLength] being 0 the minimum entropy.
 */
typedef num EstimatedEntropyCalculator(int dataLength, List<int> counter);

abstract class BaseCounterEntropyEstimator extends BaseEntropyEstimator {

  final EstimatedEntropyCalculator _calculateEstimatedEntropy;

  final _counter = new List<int>.filled(256, 0);
  int _dataLength = 0;

  int _estimatedEntropy;

  BaseCounterEntropyEstimator(this._calculateEstimatedEntropy);

  void init(CipherParameters params) {
  }

  void reset() {
    _dataLength = 0;
    _estimatedEntropy = null;
    _counter.fillRange(0, _counter.length, 0);
  }

  @override
  void update(Uint8List inp, int inpOff, int len) {
    _estimatedEntropy = null;

    inp = inp.sublist(inpOff);
    for (int i = 0; i < len; i++) {
      _counter[inp[i]]++;
    }
    _dataLength += len;
  }

  int get dataLength => _dataLength;

  int get estimatedEntropy {
    if (_dataLength == 0) {
      throw new StateError("No data has been added to the entropy estimator");
    }

    if (_estimatedEntropy == null) {
      _estimatedEntropy = _calculateEstimatedEntropy(_dataLength, _counter).toInt();
    }
    return _estimatedEntropy;
  }

}
