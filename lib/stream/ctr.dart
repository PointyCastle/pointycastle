// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.stream_cipher.ctr;

import "package:pointycastle/api.dart";
import "package:pointycastle/stream/sic.dart";
import "package:pointycastle/src/registry/registry.dart";

/// Just an alias to be able to create SIC as CTR
class CTRStreamCipher extends SICStreamCipher {

  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG =
      new DynamicFactoryConfig.suffix("/CTR", (String algorithmName, _) => () {
        int sep = algorithmName.lastIndexOf("/");
        String digestName = algorithmName.substring(0, sep);
        return new CTRStreamCipher(new BlockCipher(digestName));
      });

  CTRStreamCipher(BlockCipher underlyingCipher) : super(underlyingCipher);
  String get algorithmName => "${underlyingCipher.algorithmName}/CTR";
}