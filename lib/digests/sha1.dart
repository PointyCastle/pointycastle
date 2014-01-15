// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.digests.sha1;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/digests/md4_family_digest.dart";

/// Implementation of SHA-1 digest. For more info see links:
class SHA1Digest extends MD4FamilyDigest implements Digest {

  static const _DIGEST_LENGTH = 20;

  Uint32 _H1, _H2, _H3, _H4, _H5;

  var _X = new List<Uint32>(80);
  int _xOff;

  SHA1Digest() {
    reset();
  }

  String get algorithmName => "SHA-1";

  int get digestSize => _DIGEST_LENGTH;

  void reset() {
    super.reset();

    _H1 = new Uint32(0x67452301);
    _H2 = new Uint32(0xefcdab89);
    _H3 = new Uint32(0x98badcfe);
    _H4 = new Uint32(0x10325476);
    _H5 = new Uint32(0xc3d2e1f0);

    // Reset buffer
    _xOff = 0;
    _X.fillRange(0, _X.length, new Uint32(0) );
  }

  int doFinal(Uint8List out, int outOff) {
    finish();

    _H1.toBigEndian(out, outOff);
    _H2.toBigEndian(out, outOff+4);
    _H3.toBigEndian(out, outOff+8);
    _H4.toBigEndian(out, outOff+12);
    _H5.toBigEndian(out, outOff+16);

    reset();

    return _DIGEST_LENGTH;
  }

  void processWord( Uint8List inp, int inpOff ) {
    var n = new Uint32.fromBigEndian(inp, inpOff);
    _X[_xOff] = n;

    if( ++_xOff==16 ) {
      processBlock();
    }
  }

  void processLength(int bitLength) {
    if( _xOff>14 ) {
      processBlock();
    }

    var bd = new ByteData.view(new Uint8List(8).buffer);
    bd.setInt64( 0, bitLength, Endianness.BIG_ENDIAN );
    _X[14] = new Uint32( bd.getInt32(0) );
    _X[15] = new Uint32( bd.getInt32(4) );
  }

  void processBlock() {
    //
    // expand 16 word block into 80 word block.
    //
    for( var i=16 ; i<80 ; i++ ) {
      var t = _X[i - 3] ^ _X[i - 8] ^ _X[i - 14] ^ _X[i - 16];
      _X[i] = t << 1 | t >> 31;
    }

    //
    // set up working variables.
    //
    Uint32 A = _H1;
    Uint32 B = _H2;
    Uint32 C = _H3;
    Uint32 D = _H4;
    Uint32 E = _H5;

    //
    // round 1
    //
    var idx = 0;

    for( var j=0 ; j<4 ; j++ ) {

      // E = rotateLeft(A, 5) + f(B, C, D) + E + X[idx++] + Y1
      // B = rotateLeft(B, 30)
      E += (A << 5 | A >> 27) + _f(B, C, D) + _X[idx++] + Y1;
      B = B << 30 | B >> 2;

      D += (E << 5 | E >> 27) + _f(A, B, C) + _X[idx++] + Y1;
      A = A << 30 | A >> 2;

      C += (D << 5 | D >> 27) + _f(E, A, B) + _X[idx++] + Y1;
      E = E << 30 | E >> 2;

      B += (C << 5 | C >> 27) + _f(D, E, A) + _X[idx++] + Y1;
      D = D << 30 | D >> 2;

      A += (B << 5 | B >> 27) + _f(C, D, E) + _X[idx++] + Y1;
      C = C << 30 | C >> 2;
    }

    //
    // round 2
    //
    for (int j=0 ; j<4 ; j++ ) {
      // E = rotateLeft(A, 5) + h(B, C, D) + E + X[idx++] + Y2
      // B = rotateLeft(B, 30)
      E += (A << 5 | A >> 27) + _h(B, C, D) + _X[idx++] + Y2;
      B = B << 30 | B >> 2;

      D += (E << 5 | E >> 27) + _h(A, B, C) + _X[idx++] + Y2;
      A = A << 30 | A >> 2;

      C += (D << 5 | D >> 27) + _h(E, A, B) + _X[idx++] + Y2;
      E = E << 30 | E >> 2;

      B += (C << 5 | C >> 27) + _h(D, E, A) + _X[idx++] + Y2;
      D = D << 30 | D >> 2;

      A += (B << 5 | B >> 27) + _h(C, D, E) + _X[idx++] + Y2;
      C = C << 30 | C >> 2;
    }

    //
    // round 3
    //
    for( var j=0 ; j<4 ; j++ ) {
      // E = rotateLeft(A, 5) + g(B, C, D) + E + X[idx++] + Y3
      // B = rotateLeft(B, 30)
      E += (A << 5 | A >> 27) + _g(B, C, D) + _X[idx++] + Y3;
      B = B << 30 | B >> 2;

      D += (E << 5 | E >> 27) + _g(A, B, C) + _X[idx++] + Y3;
      A = A << 30 | A >> 2;

      C += (D << 5 | D >> 27) + _g(E, A, B) + _X[idx++] + Y3;
      E = E << 30 | E >> 2;

      B += (C << 5 | C >> 27) + _g(D, E, A) + _X[idx++] + Y3;
      D = D << 30 | D >> 2;

      A += (B << 5 | B >> 27) + _g(C, D, E) + _X[idx++] + Y3;
      C = C << 30 | C >> 2;
    }

    //
    // round 4
    //
    for( int j=0 ; j<=3 ; j++ ) {
      // E = rotateLeft(A, 5) + h(B, C, D) + E + X[idx++] + Y4
      // B = rotateLeft(B, 30)
      E += (A << 5 | A >> 27) + _h(B, C, D) + _X[idx++] + Y4;
      B = B << 30 | B >> 2;

      D += (E << 5 | E >> 27) + _h(A, B, C) + _X[idx++] + Y4;
      A = A << 30 | A >> 2;

      C += (D << 5 | D >> 27) + _h(E, A, B) + _X[idx++] + Y4;
      E = E << 30 | E >> 2;

      B += (C << 5 | C >> 27) + _h(D, E, A) + _X[idx++] + Y4;
      D = D << 30 | D >> 2;

      A += (B << 5 | B >> 27) + _h(C, D, E) + _X[idx++] + Y4;
      C = C << 30 | C >> 2;
    }


    _H1 += A;
    _H2 += B;
    _H3 += C;
    _H4 += D;
    _H5 += E;

    // reset start of the buffer.
    _xOff = 0;
    _X.fillRange(0, 16, new Uint32(0));
  }

  // Additive constants
  static final Y1 = 0x5a827999;
  static final Y2 = 0x6ed9eba1;
  static final Y3 = 0x8f1bbcdc;
  static final Y4 = 0xca62c1d6;

  Uint32 _f( Uint32 u, Uint32 v, Uint32 w ) => ((u & v) | ((~u) & w));

  Uint32 _h( Uint32 u, Uint32 v, Uint32 w ) => (u ^ v ^ w);

  Uint32 _g( Uint32 u, Uint32 v, Uint32 w ) => ((u & v) | (u & w) | (v & w));

}



