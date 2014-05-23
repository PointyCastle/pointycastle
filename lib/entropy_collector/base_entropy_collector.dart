// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.entropy_collector.base_entropy_collector;

import "dart:async";
import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/src/ufixnum.dart";

/// The watch for timestamping events (if necessary)
Stopwatch _watch = new Stopwatch()..start();

/// Base implementation of [EntropyCollector] which provides shared methods.
abstract class BaseEntropyCollector implements EntropyCollector {

  final _controller = new StreamController();

  bool _includeTimestampInEvents = false;

  BaseEntropyCollector({bool includeTimestampInEvents: false}) {
    _includeTimestampInEvents = includeTimestampInEvents;
  }

  Stream<Uint8List> get entropy => _controller.stream;

  void deliver(Uint8List entropy) {
    if (_includeTimestampInEvents) {
      var tmp = new Uint8List(entropy.length + 2);
      tmp.setRange(0, entropy.length, entropy);
      _packCurrentTime(tmp, entropy.length);
      entropy = tmp;
    }

    _controller.add(entropy);
  }

  void _packCurrentTime(Uint8List entropy, int offset) {
    var now = clip16(_watch.elapsedMicroseconds);
    pack16(now, entropy, offset, Endianness.BIG_ENDIAN);
  }

}
