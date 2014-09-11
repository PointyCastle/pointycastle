// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.benchmark.benchmark.digest_benchmark;

import "dart:typed_data";

import "package:cipher/cipher.dart";

import "../benchmark/rate_benchmark.dart";


class DigestBenchmark extends RateBenchmark {

  final String _digestName;
  final Uint8List _data;

  Digest _digest;

  DigestBenchmark(String digestName,[int dataLength = 1024*1024]) :
    super("Digest | $digestName"),
    _digestName = digestName,
    _data = new Uint8List(dataLength);

  void setup() {
    initCipher();
    _digest = new Digest(_digestName);
  }

  void run() {
    _digest.process(_data);
    addSample(_data.length);
  }

}
