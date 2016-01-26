// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.impl.secure_random.test.src.null_secure_random;

import "package:cipher/api.dart";
import "package:cipher/src/ufixnum.dart";
import "package:cipher/src/impl/secure_random_base.dart";

/// An implementation of [SecureRandom] that return numbers in growing sequence.
class NullSecureRandom extends SecureRandomBase {

  var _nextValue=0;

  String get algorithmName => "Null";

  void seed(CipherParameters params) {
  }

  int nextUint8() => clip8(_nextValue++);

}



