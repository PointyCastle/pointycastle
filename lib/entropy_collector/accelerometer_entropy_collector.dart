// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.entropy_collector.accelerometer_entropy_collector;

import "dart:html";
import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/src/ufixnum.dart";

import "./base_entropy_collector.dart";


/// Implementation of [EntropyCollector] which harvests entropy from user interactions.
class AccelerometerEntropyCollector extends BaseEntropyCollector {

  final String algorithmName = "Accelerometer";

  var _eventListener;

  AccelerometerEntropyCollector() : super(includeTimestampInEvents: true) {
    _eventListener = (event) => _collectEntropy(event);
  }

  void init(CipherParameters params) {
  }

  void start() {
    window.addEventListener("devicemotion", _eventListener, false);
  }

  void stop() {
    window.removeEventListener("devicemotion", _eventListener, false);
  }

  void _collectEntropy(DeviceMotionEvent event) {
    var entropy = new Uint8List(8);

    var x = clip16(event.accelerationIncludingGravity.x.toInt());
    pack16(x, entropy, 0, Endianness.BIG_ENDIAN);

    var y = clip16(event.accelerationIncludingGravity.x.toInt());
    pack16(y, entropy, 2, Endianness.BIG_ENDIAN);

    var z = clip16(event.accelerationIncludingGravity.x.toInt());
    pack16(z, entropy, 4, Endianness.BIG_ENDIAN);

    deliver(entropy);
  }

}
