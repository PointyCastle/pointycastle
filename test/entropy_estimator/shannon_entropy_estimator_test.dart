// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.entropy_estimator.shannon_entropy_estimator_test;

import "dart:typed_data";

import "package:cipher/cipher.dart";
import "package:cipher/impl/base.dart";
import "package:unittest/unittest.dart";

import "../test/src/helpers.dart";


void main() {

  initCipher();

  var estimator = new EntropyEstimator("Shannon");

  group("${estimator.algorithmName}:", () {

    test("estimatedEntropy: no entropy", () {
      var expected = 0;

      expect(estimator.process(new Uint8List.fromList([  0,   0,   0,   0])), expected);
      expect(estimator.process(new Uint8List.fromList([255, 255, 255, 255])), expected);
    });

    test("estimatedEntropy: full entropy", () {
      final entropy = createUint8ListFromSequentialNumbers(256);

      expect(estimator.process(entropy), entropy.length);
    });

  });

}
