// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.entropy_collector.jitter_entropy_collector;

import "dart:async";
import "dart:typed_data";

import "package:cipher/entropy_collector/base_polling_entropy_collector.dart";

class JitterEntropyCollector extends BasePollingEntropyCollector {

  static const _MIN_DURATION_BOUND = 100;
  static const _MAX_DURATION_BOUND = 200;
  static const _AVG_DURATION_BOUND = (_MIN_DURATION_BOUND + _MAX_DURATION_BOUND) ~/ 2;

  final _watch = new Stopwatch();
  int _loopCount = 1;

  JitterEntropyCollector();

  final String algorithmName = "Jitter";

  Future<Uint8List> pollEvent() {
    var entropy = new Uint8List(bytesPerRound);

    for (int i = 0; i < bytesPerRound; i++) {
      entropy[i] = _generateOneByteOfEntropy();
    }

    return new Future.value(entropy);
  }

  int _generateOneByteOfEntropy() {
    do {
      _watch
          ..reset()
          ..start();
      for (int i = 0; i < _loopCount; i++) {
        _doJitterOperation();
      }
      _watch.stop();

      if (_watch.elapsedTicks == 0) {
        _loopCount += 1;
      }
    } while (_watch.elapsedTicks < _MIN_DURATION_BOUND);

    if (_watch.elapsedTicks < _MIN_DURATION_BOUND) {
      _loopCount = _MIN_DURATION_BOUND * _loopCount ~/ _watch.elapsedTicks;
    } else if (_watch.elapsedMilliseconds > _MAX_DURATION_BOUND) {
      _loopCount = _AVG_DURATION_BOUND * _loopCount ~/ _watch.elapsedMilliseconds;
    }

    if (_loopCount == 0) {
      _loopCount = 1;
    }

    return _watch.elapsedTicks;
  }

  void _doJitterOperation() {
    var d = 2009.0423;
    for (int i = 0; i < 1000; i++) {
      d *= 2;
      d /= 2;
    }
  }

}
