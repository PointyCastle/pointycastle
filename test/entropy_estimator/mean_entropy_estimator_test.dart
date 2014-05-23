// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.entropy_estimator.mean_entropy_estimator_test;

import "dart:typed_data";

import "package:cipher/cipher.dart";
import "package:cipher/impl/base.dart";
import "package:unittest/unittest.dart";

void main() {

  initCipher();

  var estimator = new EntropyEstimator("Mean");

  group("${estimator.algorithmName}:", () {

    test("estimatedEntropy: no entropy", () {
      var expected = 0;

      expect(estimator.process(new Uint8List.fromList([  0,   0,   0,   0])), expected);
      expect(estimator.process(new Uint8List.fromList([255, 255, 255, 255])), expected);
    });

    test("estimatedEntropy: half entropy", () {
      final expected = 2;

      expect(estimator.process(new Uint8List.fromList([127, 255, 127, 255])), expected);
      expect(estimator.process(new Uint8List.fromList([128,   0, 128,   0])), expected);
    });

    test("estimatedEntropy: full entropy", () {
      final expected = 4;

      expect(estimator.process(new Uint8List.fromList([  0, 255,   0, 255])), expected);
      expect(estimator.process(new Uint8List.fromList([127, 128, 127, 128])), expected);
    });

  });
}
