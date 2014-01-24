// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.digests.md4;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/digests/md4_family_digest.dart";

/// Implementation of MD5 digest
class MD5Digest extends MD4FamilyDigest implements Digest {

  static const _DIGEST_LENGTH = 16;

  Uint32 _H1, _H2, _H3, _H4;

  final _X = new List<Uint32>(16);
  int _xOff;

  MD5Digest() {
    reset();
  }

  String get algorithmName => "MD5";

  int get digestSize => _DIGEST_LENGTH;

  void reset() {
    super.reset();

    _H1 = new Uint32(0x67452301);
    _H2 = new Uint32(0xefcdab89);
    _H3 = new Uint32(0x98badcfe);
    _H4 = new Uint32(0x10325476);

    _xOff = 0;
    _X.fillRange( 0, _X.length, new Uint32(0) );
  }

  int doFinal( Uint8List out, int outOff ) {
    finish();

    _unpackWord(_H1, out, outOff);
    _unpackWord(_H2, out, outOff + 4);
    _unpackWord(_H3, out, outOff + 8);
    _unpackWord(_H4, out, outOff + 12);

    reset();

    return _DIGEST_LENGTH;
  }

  void processWord( Uint8List inp, int inpOff ) {
    _X[_xOff++] = new Uint32.fromLittleEndian(inp, inpOff);

    if( _xOff==16 ) {
      processBlock();
    }
  }

  void processLength( int bitLength ) {
    if( _xOff>14 ) {
      processBlock();
    }

    var bd = new ByteData.view(new Uint8List(8).buffer);
    bd.setInt64( 0, bitLength, Endianness.BIG_ENDIAN );
    _X[14] = new Uint32( bd.getInt32(4) );
    _X[15] = new Uint32( bd.getInt32(0) );
  }

  void processBlock() {
    var a = _H1;
    var b = _H2;
    var c = _H3;
    var d = _H4;

    // Round 1 - F cycle, 16 times.
    a = _rotateLeft(a + _F(b, c, d) + _X[ 0] + 0xd76aa478, _S11) + b;
    d = _rotateLeft(d + _F(a, b, c) + _X[ 1] + 0xe8c7b756, _S12) + a;
    c = _rotateLeft(c + _F(d, a, b) + _X[ 2] + 0x242070db, _S13) + d;
    b = _rotateLeft(b + _F(c, d, a) + _X[ 3] + 0xc1bdceee, _S14) + c;
    a = _rotateLeft(a + _F(b, c, d) + _X[ 4] + 0xf57c0faf, _S11) + b;
    d = _rotateLeft(d + _F(a, b, c) + _X[ 5] + 0x4787c62a, _S12) + a;
    c = _rotateLeft(c + _F(d, a, b) + _X[ 6] + 0xa8304613, _S13) + d;
    b = _rotateLeft(b + _F(c, d, a) + _X[ 7] + 0xfd469501, _S14) + c;
    a = _rotateLeft(a + _F(b, c, d) + _X[ 8] + 0x698098d8, _S11) + b;
    d = _rotateLeft(d + _F(a, b, c) + _X[ 9] + 0x8b44f7af, _S12) + a;
    c = _rotateLeft(c + _F(d, a, b) + _X[10] + 0xffff5bb1, _S13) + d;
    b = _rotateLeft(b + _F(c, d, a) + _X[11] + 0x895cd7be, _S14) + c;
    a = _rotateLeft(a + _F(b, c, d) + _X[12] + 0x6b901122, _S11) + b;
    d = _rotateLeft(d + _F(a, b, c) + _X[13] + 0xfd987193, _S12) + a;
    c = _rotateLeft(c + _F(d, a, b) + _X[14] + 0xa679438e, _S13) + d;
    b = _rotateLeft(b + _F(c, d, a) + _X[15] + 0x49b40821, _S14) + c;

    // Round 2 - G cycle, 16 time_S.
    a = _rotateLeft(a + _G(b, c, d) + _X[ 1] + 0xf61e2562, _S21) + b;
    d = _rotateLeft(d + _G(a, b, c) + _X[ 6] + 0xc040b340, _S22) + a;
    c = _rotateLeft(c + _G(d, a, b) + _X[11] + 0x265e5a51, _S23) + d;
    b = _rotateLeft(b + _G(c, d, a) + _X[ 0] + 0xe9b6c7aa, _S24) + c;
    a = _rotateLeft(a + _G(b, c, d) + _X[ 5] + 0xd62f105d, _S21) + b;
    d = _rotateLeft(d + _G(a, b, c) + _X[10] + 0x02441453, _S22) + a;
    c = _rotateLeft(c + _G(d, a, b) + _X[15] + 0xd8a1e681, _S23) + d;
    b = _rotateLeft(b + _G(c, d, a) + _X[ 4] + 0xe7d3fbc8, _S24) + c;
    a = _rotateLeft(a + _G(b, c, d) + _X[ 9] + 0x21e1cde6, _S21) + b;
    d = _rotateLeft(d + _G(a, b, c) + _X[14] + 0xc33707d6, _S22) + a;
    c = _rotateLeft(c + _G(d, a, b) + _X[ 3] + 0xf4d50d87, _S23) + d;
    b = _rotateLeft(b + _G(c, d, a) + _X[ 8] + 0x455a14ed, _S24) + c;
    a = _rotateLeft(a + _G(b, c, d) + _X[13] + 0xa9e3e905, _S21) + b;
    d = _rotateLeft(d + _G(a, b, c) + _X[ 2] + 0xfcefa3f8, _S22) + a;
    c = _rotateLeft(c + _G(d, a, b) + _X[ 7] + 0x676f02d9, _S23) + d;
    b = _rotateLeft(b + _G(c, d, a) + _X[12] + 0x8d2a4c8a, _S24) + c;

    // Round 3 - H cycle, 16 time_S.
    a = _rotateLeft(a + _H(b, c, d) + _X[ 5] + 0xfffa3942, _S31) + b;
    d = _rotateLeft(d + _H(a, b, c) + _X[ 8] + 0x8771f681, _S32) + a;
    c = _rotateLeft(c + _H(d, a, b) + _X[11] + 0x6d9d6122, _S33) + d;
    b = _rotateLeft(b + _H(c, d, a) + _X[14] + 0xfde5380c, _S34) + c;
    a = _rotateLeft(a + _H(b, c, d) + _X[ 1] + 0xa4beea44, _S31) + b;
    d = _rotateLeft(d + _H(a, b, c) + _X[ 4] + 0x4bdecfa9, _S32) + a;
    c = _rotateLeft(c + _H(d, a, b) + _X[ 7] + 0xf6bb4b60, _S33) + d;
    b = _rotateLeft(b + _H(c, d, a) + _X[10] + 0xbebfbc70, _S34) + c;
    a = _rotateLeft(a + _H(b, c, d) + _X[13] + 0x289b7ec6, _S31) + b;
    d = _rotateLeft(d + _H(a, b, c) + _X[ 0] + 0xeaa127fa, _S32) + a;
    c = _rotateLeft(c + _H(d, a, b) + _X[ 3] + 0xd4ef3085, _S33) + d;
    b = _rotateLeft(b + _H(c, d, a) + _X[ 6] + 0x04881d05, _S34) + c;
    a = _rotateLeft(a + _H(b, c, d) + _X[ 9] + 0xd9d4d039, _S31) + b;
    d = _rotateLeft(d + _H(a, b, c) + _X[12] + 0xe6db99e5, _S32) + a;
    c = _rotateLeft(c + _H(d, a, b) + _X[15] + 0x1fa27cf8, _S33) + d;
    b = _rotateLeft(b + _H(c, d, a) + _X[ 2] + 0xc4ac5665, _S34) + c;

    // Round 4 - K cycle, 16 time_S.
    a = _rotateLeft(a + _K(b, c, d) + _X[ 0] + 0xf4292244, _S41) + b;
    d = _rotateLeft(d + _K(a, b, c) + _X[ 7] + 0x432aff97, _S42) + a;
    c = _rotateLeft(c + _K(d, a, b) + _X[14] + 0xab9423a7, _S43) + d;
    b = _rotateLeft(b + _K(c, d, a) + _X[ 5] + 0xfc93a039, _S44) + c;
    a = _rotateLeft(a + _K(b, c, d) + _X[12] + 0x655b59c3, _S41) + b;
    d = _rotateLeft(d + _K(a, b, c) + _X[ 3] + 0x8f0ccc92, _S42) + a;
    c = _rotateLeft(c + _K(d, a, b) + _X[10] + 0xffeff47d, _S43) + d;
    b = _rotateLeft(b + _K(c, d, a) + _X[ 1] + 0x85845dd1, _S44) + c;
    a = _rotateLeft(a + _K(b, c, d) + _X[ 8] + 0x6fa87e4f, _S41) + b;
    d = _rotateLeft(d + _K(a, b, c) + _X[15] + 0xfe2ce6e0, _S42) + a;
    c = _rotateLeft(c + _K(d, a, b) + _X[ 6] + 0xa3014314, _S43) + d;
    b = _rotateLeft(b + _K(c, d, a) + _X[13] + 0x4e0811a1, _S44) + c;
    a = _rotateLeft(a + _K(b, c, d) + _X[ 4] + 0xf7537e82, _S41) + b;
    d = _rotateLeft(d + _K(a, b, c) + _X[11] + 0xbd3af235, _S42) + a;
    c = _rotateLeft(c + _K(d, a, b) + _X[ 2] + 0x2ad7d2bb, _S43) + d;
    b = _rotateLeft(b + _K(c, d, a) + _X[ 9] + 0xeb86d391, _S44) + c;

    _H1 += a;
    _H2 += b;
    _H3 += c;
    _H4 += d;

    // reset the offset and clean out the word buffer.
    _xOff = 0;
    _X.fillRange(0, _X.length, new Uint32(0));
  }

  // round 1 left rotates
  static const _S11 = 7;
  static const _S12 = 12;
  static const _S13 = 17;
  static const _S14 = 22;

  // round 2 left rotates
  static const _S21 = 5;
  static const _S22 = 9;
  static const _S23 = 14;
  static const _S24 = 20;

  // round 3 left rotates
  static const _S31 = 4;
  static const _S32 = 11;
  static const _S33 = 16;
  static const _S34 = 23;

  // round 4 left rotates
  static const _S41 = 6;
  static const _S42 = 10;
  static const _S43 = 15;
  static const _S44 = 21;

  // Helper functions
  Uint32 _rotateLeft( Uint32 x, int n ) => x.rotl(n);
  void _unpackWord( Uint32 word, Uint8List out, int outOff ) => word.toLittleEndian(out, outOff);

  // F, G, H and K are the basic MD5 functions.
  Uint32 _F( Uint32 u, Uint32 v, Uint32 w ) => (u & v) | (~u & w);
  Uint32 _G( Uint32 u, Uint32 v, Uint32 w ) => (u & w) | (v & ~w);
  Uint32 _H( Uint32 u, Uint32 v, Uint32 w ) => u ^ v ^ w;
  Uint32 _K( Uint32 u, Uint32 v, Uint32 w ) => v ^ (u | ~w);

}
