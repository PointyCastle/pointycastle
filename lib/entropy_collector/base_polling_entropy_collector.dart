// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.entropy_collector.base_polling_entropy_collector;

import "dart:async";
import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/entropy_collector/base_entropy_collector.dart";
import "package:cipher/params/entropy_collector/polling_entropy_collector_params.dart";


/// Base implementation of an [EntropyCollector] that polls its source with a defined frequency.
abstract class BasePollingEntropyCollector extends BaseEntropyCollector {

  int _periodMillis = 100;
  int _bytesPerRound = 8;
  bool _running;

  int get periodMillis => _periodMillis;

  int get bytesPerRound => _bytesPerRound;

  void init(PollingEntropyCollectorParameters params) {
    _bytesPerRound = params.bytesPerRound;
    _periodMillis = params.periodMillis;
  }

  void start() {
    _running = true;
    _schedulePollEvent();
  }

  void stop() {
    _running = false;
  }

  Future<Uint8List> pollEvent();

  void _schedulePollEvent() {
    new Timer(new Duration(milliseconds: periodMillis), _generateEvent);
  }

  void _generateEvent() {
    pollEvent().then((Uint8List entropy) {
      deliver(entropy);

      if (_running) {
        _schedulePollEvent();
      }
    });
  }

}
