// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.random.secure_random_base;

import "dart:typed_data";

import "package:bignum/bignum.dart";

import "package:cipher/api.dart";

/// An utility base implementation of [SecureRandom] so that only [nextUint8] method needs to be implemented.
abstract class SecureRandomBase implements SecureRandom {

  Uint16 nextUint16() {
    var b0 = nextUint8();
    var b1 = nextUint8();
    return new Uint16( (b1<<8) | b0 );
  }

  Uint32 nextUint32() {
    var b0 = nextUint8();
    var b1 = nextUint8();
    var b2 = nextUint8();
    var b3 = nextUint8();
    return new Uint32( (b3<<24) | (b2<<16) | (b1<<8) | b0 );
  }

  BigInteger nextBigInteger( int bitLength ) {
    return new BigInteger.fromBytes(1, _randomBits(bitLength));
  }

  Uint8List nextBytes( int count ) {
    var bytes = new Uint8List(count);
    for( var i=0 ; i<count ; i++ ) {
      bytes[i] = nextUint8().toInt();
    }
    return bytes;
  }

  List<int> _randomBits(int numBits) {
    if (numBits < 0) {
      throw new ArgumentError("numBits must be non-negative");
    }

    var numBytes = (numBits+7)~/8; // avoid overflow
    var randomBits = new Uint8List(numBytes);

    // Generate random bytes and mask out any excess bits
    if (numBytes > 0) {
      for( var i=0 ; i<numBytes ; i++ ){
        randomBits[i] = nextUint8().toInt();
      }
      int excessBits = 8*numBytes - numBits;
      randomBits[0] &= (1 << (8-excessBits)) - 1;
    }
    return randomBits;
  }

}
