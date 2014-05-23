// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.entropy_collector.page_load_entropy_collector;

import "dart:html";
import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/src/ufixnum.dart";

import "./base_entropy_collector.dart";


/// Implementation of [EntropyCollector] which harvests entropy from page load time.
class PageLoadEntropyCollector extends BaseEntropyCollector {

  final String algorithmName = "PageLoad";

  var _eventListener;

  PageLoadEntropyCollector() : super(includeTimestampInEvents: true) {
    _eventListener = (event) => _collectEntropy(event);
  }

  void init(CipherParameters params) {
  }

  void start() {
    window.addEventListener("load", _eventListener, false);
  }

  void stop() {
    window.removeEventListener("load", _eventListener, false);
  }

  void _collectEntropy(Event event) {
    var entropy = new Uint8List(2);

    var now = clip16(window.performance.now().toInt());
    pack16(now, entropy, 0, Endianness.BIG_ENDIAN);

    deliver(entropy);
  }

}
