// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.src.null_secure_random;

import "package:cipher/api.dart";
import "package:cipher/api/ufixnum.dart";
import "package:cipher/random/secure_random_base.dart";

/// An implementation of [SecureRandom] that return numbers in growing sequence.
class NullSecureRandom extends SecureRandomBase {

  var _nextValue=0;

  String get algorithmName => "Null";

  void seed(CipherParameters params) {
  }

  int nextUint8() => clip8(_nextValue++);

}



