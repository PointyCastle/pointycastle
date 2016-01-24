// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.src.impl.base_padding;

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