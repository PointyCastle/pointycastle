// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.impl.base_mac;

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
