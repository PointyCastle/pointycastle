// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.src.impl.base_stream_cipher;

import "dart:typed_data";

import "package:cipher/api.dart";

/// Base implementation of [StreamCipher] which provides shared methods.
abstract class BaseStreamCipher implements StreamCipher {

  Uint8List process(Uint8List data) {
    var out = new Uint8List(data.length);
    processBytes(data, 0, data.length, out, 0);
    return out;
  }

}