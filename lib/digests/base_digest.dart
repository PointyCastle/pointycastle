// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.digests.base_digest;

import "dart:typed_data";

import "package:cipher/api.dart";

/// Base implementation of [Digest] which provides shared methods.
abstract class BaseDigest implements Digest {

  Uint8List process(Uint8List data) {
    update(data, 0, data.length);
    var out = new Uint8List(digestSize);
    var len = doFinal(out, 0);
    return out.sublist(0, len);
  }

}