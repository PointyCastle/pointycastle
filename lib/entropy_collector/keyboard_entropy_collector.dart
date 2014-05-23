// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.entropy_collector.keyboard_entropy_collector;

import "dart:html";
import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/src/ufixnum.dart";

import "./base_entropy_collector.dart";


/// Implementation of [EntropyCollector] which harvests entropy from user interactions.
class KeyboardEntropyCollector extends BaseEntropyCollector {

  final String algorithmName = "Keyboard";

  var _eventListener;

  KeyboardEntropyCollector() : super(includeTimestampInEvents: true) {
    _eventListener = (event) => _collectEntropy(event);
  }

  void init(CipherParameters params) {
  }

  void start() {
    window.addEventListener("keypress", _eventListener, false);
  }

  void stop() {
    window.removeEventListener("keypress", _eventListener, false);
  }

  void _collectEntropy(KeyboardEvent event) {
    var entropy = new Uint8List(5);

    pack16(event.keyCode, entropy, 0, Endianness.BIG_ENDIAN);

    var modsByte = 0;
    modsByte |= event.altGraphKey ? 1 : 0;
    modsByte |= event.altKey ? 2 : 0;
    modsByte |= event.ctrlKey ? 4 : 0;
    modsByte |= event.metaKey ? 8 : 0;
    modsByte |= event.shiftKey ? 16 : 0;

    entropy[2] = modsByte;

    deliver(entropy);
  }

}
