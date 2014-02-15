// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.macs.base_mac;

import "dart:typed_data";

import "package:cipher/api.dart";

/// Base implementation of [Mac] which provides shared methods.
abstract class BaseMac implements Mac {

  Uint8List process(Uint8List data) {
    update(data, 0, data.length);
    var out = new Uint8List(macSize);
    var len = doFinal(out, 0);
    return out.sublist(0, len);
  }

}
