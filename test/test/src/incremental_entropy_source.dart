// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.src.incremental_entropy_source;

import "dart:async";
import "dart:typed_data";

import "package:cipher/api.dart";

/// An implementation of [SecureRandom] that return numbers in growing sequence.
class IncrementalEntropySource implements EntropySource {

  var _nextValue = 0;

  final String sourceName = "Incremental";

  Future<Uint8List> getBytes(int count) {
    var list = new Uint8List(count);
    for (int i = 0; i < count; i++) {
      list[i] = _nextValue++;
    }
    _nextValue &= 0xFF;
    return new Future.value(list);
  }

}


