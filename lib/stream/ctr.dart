// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.impl.stream_cipher.ctr;

import "package:cipher/api.dart";
import "package:cipher/stream/sic.dart";
import "package:cipher/src/registry/registry.dart";

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