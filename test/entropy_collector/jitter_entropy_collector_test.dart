// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.entropy_collector.jitter_entropy_collector_test;

import "dart:typed_data";

import "package:cipher/cipher.dart";
import "package:cipher/impl/base.dart";

import "package:unittest/unittest.dart";


void main() {
  initCipher();

  final collector = new EntropyCollector("Jitter");
  collector.init(new PollingEntropyCollectorParameters(100, 256));

  final estimator = new EntropyEstimator("Shannon");
  final watch = new Stopwatch()..start();

  group("${collector.algorithmName}:", () {
    test("entropy.listen()", () {
      int call = 1;
      collector.entropy.listen((Uint8List entropy) {
        expect(entropy.length, 256);

        /*
        estimator.update(entropy, 0, entropy.length);
        var ent = estimator.estimatedEntropy;
        var rate = 1000 * ent / watch.elapsedMilliseconds;
        print("Entropy rate:   ${rate.toStringAsFixed(2)} bytes/sec   [${watch.elapsedMilliseconds~/1000}\"]");
        */

        if (call == 5) {
          collector.stop();
        }

        call++;
      });

      collector.start();
    });
  });
}
