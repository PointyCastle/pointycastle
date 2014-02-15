// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.paddings.base_padding;

import "dart:typed_data";

import "package:cipher/api.dart";

/// Base implementation of [Padding] which provides shared methods.
abstract class BasePadding implements Padding {

  Uint8List process(bool pad, Uint8List data) {
    if (pad) {
      var out = new Uint8List.fromList(data);
      var len = addPadding(out, 0);
      return out;
    } else {
      var len = padCount(data);
      return new Uint8List.fromList(data.sublist(0, len));
    }
  }

}