// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.stream_cipher.ctr;

import "package:pointycastle/api.dart";
import "package:pointycastle/stream/sic.dart";

/// Just an alias to be able to create SIC as CTR
class CTRStreamCipher extends SICStreamCipher {
  CTRStreamCipher(BlockCipher underlyingCipher) : super(underlyingCipher);

  String get algorithmName => "${underlyingCipher.algorithmName}/CTR";
}
