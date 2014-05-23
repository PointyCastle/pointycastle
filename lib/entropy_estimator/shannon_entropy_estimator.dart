// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.entropy_estimator.shannon_entropy_estimator;

import "dart:math";

import "./base_counter_entropy_estimator.dart";

class ShannonEntropyEstimator extends BaseCounterEntropyEstimator {

  ShannonEntropyEstimator(): super(_shannonCalculateEstimatedEntropy);

  String get algorithmName => "Shannon";

}

num _shannonCalculateEstimatedEntropy(int dataLength, List<int> counter) {
  var prob = new List<double>(256);
  for (int i = 0; i < 256; i++) {
    prob[i] = counter[i] / dataLength;
  }

  var ent = 0;
  for (int i = 0; i < 256; i++) {
    if (prob[i] > 0) {
      ent -= prob[i] * _log2(prob[i]);
    }
  }

  return dataLength * ent / 8;
}

double _log2(num n) => LOG2E * log(n);
