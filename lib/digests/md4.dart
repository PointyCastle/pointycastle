// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.digests.md4;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/digests/md4_family_digest.dart";

/// Implementation of MD4 digest
class MD4Digest extends MD4FamilyDigest implements Digest {

  static const _DIGEST_LENGTH = 16;

  Uint32 _H1, _H2, _H3, _H4;

  List<Uint32> _X = new List<Uint32>(16);
  var _xOff = 0;

  String get algorithmName => "MD4";

  int get digestSize => _DIGEST_LENGTH;

  MD4Digest() {
    reset();
  }

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
    if( _xOff > 14 ) {
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
    a = _rotateLeft(a + _F(b, c, d) + _X[ 0], _S11);
    d = _rotateLeft(d + _F(a, b, c) + _X[ 1], _S12);
    c = _rotateLeft(c + _F(d, a, b) + _X[ 2], _S13);
    b = _rotateLeft(b + _F(c, d, a) + _X[ 3], _S14);
    a = _rotateLeft(a + _F(b, c, d) + _X[ 4], _S11);
    d = _rotateLeft(d + _F(a, b, c) + _X[ 5], _S12);
    c = _rotateLeft(c + _F(d, a, b) + _X[ 6], _S13);
    b = _rotateLeft(b + _F(c, d, a) + _X[ 7], _S14);
    a = _rotateLeft(a + _F(b, c, d) + _X[ 8], _S11);
    d = _rotateLeft(d + _F(a, b, c) + _X[ 9], _S12);
    c = _rotateLeft(c + _F(d, a, b) + _X[10], _S13);
    b = _rotateLeft(b + _F(c, d, a) + _X[11], _S14);
    a = _rotateLeft(a + _F(b, c, d) + _X[12], _S11);
    d = _rotateLeft(d + _F(a, b, c) + _X[13], _S12);
    c = _rotateLeft(c + _F(d, a, b) + _X[14], _S13);
    b = _rotateLeft(b + _F(c, d, a) + _X[15], _S14);

    // Round 2 - G cycle, 16 times.
    a = _rotateLeft(a + _G(b, c, d) + _X[ 0] + 0x5a827999, _S21);
    d = _rotateLeft(d + _G(a, b, c) + _X[ 4] + 0x5a827999, _S22);
    c = _rotateLeft(c + _G(d, a, b) + _X[ 8] + 0x5a827999, _S23);
    b = _rotateLeft(b + _G(c, d, a) + _X[12] + 0x5a827999, _S24);
    a = _rotateLeft(a + _G(b, c, d) + _X[ 1] + 0x5a827999, _S21);
    d = _rotateLeft(d + _G(a, b, c) + _X[ 5] + 0x5a827999, _S22);
    c = _rotateLeft(c + _G(d, a, b) + _X[ 9] + 0x5a827999, _S23);
    b = _rotateLeft(b + _G(c, d, a) + _X[13] + 0x5a827999, _S24);
    a = _rotateLeft(a + _G(b, c, d) + _X[ 2] + 0x5a827999, _S21);
    d = _rotateLeft(d + _G(a, b, c) + _X[ 6] + 0x5a827999, _S22);
    c = _rotateLeft(c + _G(d, a, b) + _X[10] + 0x5a827999, _S23);
    b = _rotateLeft(b + _G(c, d, a) + _X[14] + 0x5a827999, _S24);
    a = _rotateLeft(a + _G(b, c, d) + _X[ 3] + 0x5a827999, _S21);
    d = _rotateLeft(d + _G(a, b, c) + _X[ 7] + 0x5a827999, _S22);
    c = _rotateLeft(c + _G(d, a, b) + _X[11] + 0x5a827999, _S23);
    b = _rotateLeft(b + _G(c, d, a) + _X[15] + 0x5a827999, _S24);

    // Round 3 - H cycle, 16 times.
    a = _rotateLeft(a + _H(b, c, d) + _X[ 0] + 0x6ed9eba1, _S31);
    d = _rotateLeft(d + _H(a, b, c) + _X[ 8] + 0x6ed9eba1, _S32);
    c = _rotateLeft(c + _H(d, a, b) + _X[ 4] + 0x6ed9eba1, _S33);
    b = _rotateLeft(b + _H(c, d, a) + _X[12] + 0x6ed9eba1, _S34);
    a = _rotateLeft(a + _H(b, c, d) + _X[ 2] + 0x6ed9eba1, _S31);
    d = _rotateLeft(d + _H(a, b, c) + _X[10] + 0x6ed9eba1, _S32);
    c = _rotateLeft(c + _H(d, a, b) + _X[ 6] + 0x6ed9eba1, _S33);
    b = _rotateLeft(b + _H(c, d, a) + _X[14] + 0x6ed9eba1, _S34);
    a = _rotateLeft(a + _H(b, c, d) + _X[ 1] + 0x6ed9eba1, _S31);
    d = _rotateLeft(d + _H(a, b, c) + _X[ 9] + 0x6ed9eba1, _S32);
    c = _rotateLeft(c + _H(d, a, b) + _X[ 5] + 0x6ed9eba1, _S33);
    b = _rotateLeft(b + _H(c, d, a) + _X[13] + 0x6ed9eba1, _S34);
    a = _rotateLeft(a + _H(b, c, d) + _X[ 3] + 0x6ed9eba1, _S31);
    d = _rotateLeft(d + _H(a, b, c) + _X[11] + 0x6ed9eba1, _S32);
    c = _rotateLeft(c + _H(d, a, b) + _X[ 7] + 0x6ed9eba1, _S33);
    b = _rotateLeft(b + _H(c, d, a) + _X[15] + 0x6ed9eba1, _S34);

    _H1 += a;
    _H2 += b;
    _H3 += c;
    _H4 += d;

    // reset the offset and clean out the word buffer.
    _xOff = 0;
    _X.fillRange( 0, _X.length, new Uint32(0) );
  }

  void _unpackWord( Uint32 word, Uint8List out, int outOff )
    => word.toLittleEndian(out, outOff);

  // round 1 left rotates
  static const _S11 = 3;
  static const _S12 = 7;
  static const _S13 = 11;
  static const _S14 = 19;

  // round 2 left rotates
  static const _S21 = 3;
  static const _S22 = 5;
  static const _S23 = 9;
  static const _S24 = 13;

  // round 3 left rotates
  static const _S31 = 3;
  static const _S32 = 9;
  static const _S33 = 11;
  static const _S34 = 15;

  /// rotate int x left n bits.
  Uint32 _rotateLeft( Uint32 x, int n ) => x.rotl(n);//((x << n) | (x >> (32 - n))).toInt();

  // F, G, H and I are the basic MD4 functions.
  Uint32 _F( Uint32 u, Uint32 v, Uint32 w ) => (u & v) | (~u & w);
  Uint32 _G( Uint32 u, Uint32 v, Uint32 w ) => (u & v) | (u & w) | (v & w);
  Uint32 _H( Uint32 u, Uint32 v, Uint32 w ) => u ^ v ^ w;


}



