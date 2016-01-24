// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library pointycastle.impl.padding.pkcs7;

import "dart:typed_data";

import "package:pointycastle/api.dart";
import "package:pointycastle/src/ufixnum.dart";
import "package:pointycastle/src/impl/base_padding.dart";
import "package:pointycastle/src/registry/registry.dart";

/// A [Padding] that adds PKCS7/PKCS5 padding to a block.
class PKCS7Padding extends BasePadding {

  static final FactoryConfig FACTORY_CONFIG = new StaticFactoryConfig("PKCS7");

  String get algorithmName => "PKCS7";

  void init( [CipherParameters params] ) {
      // nothing to do.
  }

  int addPadding( Uint8List data, int offset ) {
    var code = (data.length - offset);

    while( offset<data.length ) {
      data[offset] = code;
      offset++;
    }

    return code;
  }

  int padCount( Uint8List data ) {
    var count = clip8(data[data.length - 1]);

    if( count > data.length || count == 0 ) {
      throw new ArgumentError("Invalid or corrupted pad block");
    }

    for( var i=1 ; i<=count ; i++ ) {
      if( data[data.length - i] != count ) {
        throw new ArgumentError("Invalid or corrupted pad block");
      }
    }

    return count;
  }

}

