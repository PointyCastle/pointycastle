// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

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
