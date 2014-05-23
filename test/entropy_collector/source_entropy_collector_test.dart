// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.entropy_collector.source_entropy_collector_test;

import "dart:typed_data";

import "package:cipher/cipher.dart";
import "package:cipher/impl/base.dart";

import "package:unittest/unittest.dart";

import "../test/src/incremental_entropy_source.dart";


void main() {
  initCipher();
  EntropySource.registry["Incremental"] = (_) => new IncrementalEntropySource();

  final collector = new EntropyCollector("Incremental/EntropyCollector");
  collector.init(new PollingEntropyCollectorParameters(100, 256));

  group("${collector.algorithmName}:", () {
    test("entropy.listen()", () {
      int call = 1;
      collector.entropy.listen((Uint8List entropy) {
        for (int i = 0; i < 256; i++) {
          expect(entropy[i], i);
        }
        if (call == 5) {
          collector.stop();
        }
        call++;
      });

      collector.start();
    });
  });
}
