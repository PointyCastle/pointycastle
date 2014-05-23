// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.entropy_collector.mouse_entropy_collector;

import "dart:html";
import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/src/ufixnum.dart";

import "./base_entropy_collector.dart";


/// Implementation of [EntropyCollector] which harvests entropy from user interactions.
class MouseEntropyCollector extends BaseEntropyCollector {

  final String algorithmName = "Mouse";

  var _eventListener;

  MouseEntropyCollector() : super(includeTimestampInEvents: true) {
    _eventListener = (event) => _collectEntropy(event);
  }

  void init(CipherParameters params) {
  }

  void start() {
    window.addEventListener("mousemove", _eventListener, false);
  }

  void stop() {
    window.removeEventListener("mousemove", _eventListener, false);
  }

  void _collectEntropy(MouseEvent event) {
    var entropy = new Uint8List(6);

    var x = clip16(event.screen.x);
    pack16(x, entropy, 0, Endianness.BIG_ENDIAN);

    var y = clip16(event.screen.y);
    pack16(y, entropy, 2, Endianness.BIG_ENDIAN);

    deliver(entropy);
  }

}
