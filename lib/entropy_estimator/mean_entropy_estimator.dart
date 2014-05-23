// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.entropy_estimator.mean_entropy_estimator;

import "./base_counter_entropy_estimator.dart";

class MeanEntropyEstimator extends BaseCounterEntropyEstimator {

  MeanEntropyEstimator() :
    super(_meanCalculateEstimatedEntropy);

  String get algorithmName => "Mean";

}

num _meanCalculateEstimatedEntropy(int dataLength, List<int> counter) {
  var mean = 0;
  for (int i = 0; i < 256; i++) {
    mean += i * counter[i] / dataLength;
  }

  var dev = (127.5 - mean).abs();
  var mult = 1 - (dev / 127.5);

  return dataLength * mult;
}


