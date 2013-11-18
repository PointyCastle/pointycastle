// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com  
// Use of this source code is governed by a LGPL v3 license. 
// See the LICENSE file for more information.

library cipher.paddings.pkcs7;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/src/ufixnum.dart";

/// A [Padding] that adds PKCS7/PKCS5 padding to a block.
class PKCS7Padding implements Padding {
  
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
    var count = Uint8.clip( data[data.length - 1] );
    
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

