// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.digests.ripemd256;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/api/ufixnum.dart";
import "package:cipher/digests/md4_family_digest.dart";

/// Implementation of RIPEMD-256 digest.
class RIPEMD256Digest extends MD4FamilyDigest implements Digest {

  static const _DIGEST_LENGTH = 32;

  Uint32 _H0, _H1, _H2, _H3, _H4, _H5, _H6, _H7;

  var _X = new List<Uint32>(16);
  int _xOff;

  RIPEMD256Digest() {
      reset();
  }

  String get algorithmName => "RIPEMD-256";

  int get digestSize => _DIGEST_LENGTH;

  void reset(){
    super.reset();

    _H0 = new Uint32(0x67452301);
    _H1 = new Uint32(0xefcdab89);
    _H2 = new Uint32(0x98badcfe);
    _H3 = new Uint32(0x10325476);
    _H4 = new Uint32(0x76543210);
    _H5 = new Uint32(0xFEDCBA98);
    _H6 = new Uint32(0x89ABCDEF);
    _H7 = new Uint32(0x01234567);

    _xOff = 0;
    _X.fillRange(0, _X.length, new Uint32(0));
  }

  int doFinal(Uint8List out, int outOff) {
    finish();

    _unpackWord(_H0, out, outOff);
    _unpackWord(_H1, out, outOff + 4);
    _unpackWord(_H2, out, outOff + 8);
    _unpackWord(_H3, out, outOff + 12);
    _unpackWord(_H4, out, outOff + 16);
    _unpackWord(_H5, out, outOff + 20);
    _unpackWord(_H6, out, outOff + 24);
    _unpackWord(_H7, out, outOff + 28);

    reset();

    return _DIGEST_LENGTH;
  }

  void processWord(Uint8List inp, int inpOff) {
    _X[_xOff++] = new Uint32.fromLittleEndian(inp, inpOff);

    if (_xOff == 16) {
        processBlock();
    }
  }

  void processLength(int bitLength) {
    if (_xOff > 14) {
        processBlock();
    }
    packBigEndianLength(bitLength, _X, 14);
  }

  void processBlock() {
    var a, aa;
    var b, bb;
    var c, cc;
    var d, dd;
    var t;

    a = _H0;
    b = _H1;
    c = _H2;
    d = _H3;
    aa = _H4;
    bb = _H5;
    cc = _H6;
    dd = _H7;

    // Round 1
    a = _F1(a, b, c, d, _X[ 0], 11);
    d = _F1(d, a, b, c, _X[ 1], 14);
    c = _F1(c, d, a, b, _X[ 2], 15);
    b = _F1(b, c, d, a, _X[ 3], 12);
    a = _F1(a, b, c, d, _X[ 4],  5);
    d = _F1(d, a, b, c, _X[ 5],  8);
    c = _F1(c, d, a, b, _X[ 6],  7);
    b = _F1(b, c, d, a, _X[ 7],  9);
    a = _F1(a, b, c, d, _X[ 8], 11);
    d = _F1(d, a, b, c, _X[ 9], 13);
    c = _F1(c, d, a, b, _X[10], 14);
    b = _F1(b, c, d, a, _X[11], 15);
    a = _F1(a, b, c, d, _X[12],  6);
    d = _F1(d, a, b, c, _X[13],  7);
    c = _F1(c, d, a, b, _X[14],  9);
    b = _F1(b, c, d, a, _X[15],  8);

    aa = _FF4(aa, bb, cc, dd, _X[ 5],  8);
    dd = _FF4(dd, aa, bb, cc, _X[14],  9);
    cc = _FF4(cc, dd, aa, bb, _X[ 7],  9);
    bb = _FF4(bb, cc, dd, aa, _X[ 0], 11);
    aa = _FF4(aa, bb, cc, dd, _X[ 9], 13);
    dd = _FF4(dd, aa, bb, cc, _X[ 2], 15);
    cc = _FF4(cc, dd, aa, bb, _X[11], 15);
    bb = _FF4(bb, cc, dd, aa, _X[ 4],  5);
    aa = _FF4(aa, bb, cc, dd, _X[13],  7);
    dd = _FF4(dd, aa, bb, cc, _X[ 6],  7);
    cc = _FF4(cc, dd, aa, bb, _X[15],  8);
    bb = _FF4(bb, cc, dd, aa, _X[ 8], 11);
    aa = _FF4(aa, bb, cc, dd, _X[ 1], 14);
    dd = _FF4(dd, aa, bb, cc, _X[10], 14);
    cc = _FF4(cc, dd, aa, bb, _X[ 3], 12);
    bb = _FF4(bb, cc, dd, aa, _X[12],  6);

    t = a; a = aa; aa = t;

    // Round 2
    a = _F2(a, b, c, d, _X[ 7],  7);
    d = _F2(d, a, b, c, _X[ 4],  6);
    c = _F2(c, d, a, b, _X[13],  8);
    b = _F2(b, c, d, a, _X[ 1], 13);
    a = _F2(a, b, c, d, _X[10], 11);
    d = _F2(d, a, b, c, _X[ 6],  9);
    c = _F2(c, d, a, b, _X[15],  7);
    b = _F2(b, c, d, a, _X[ 3], 15);
    a = _F2(a, b, c, d, _X[12],  7);
    d = _F2(d, a, b, c, _X[ 0], 12);
    c = _F2(c, d, a, b, _X[ 9], 15);
    b = _F2(b, c, d, a, _X[ 5],  9);
    a = _F2(a, b, c, d, _X[ 2], 11);
    d = _F2(d, a, b, c, _X[14],  7);
    c = _F2(c, d, a, b, _X[11], 13);
    b = _F2(b, c, d, a, _X[ 8], 12);

    aa = _FF3(aa, bb, cc, dd, _X[ 6],  9);
    dd = _FF3(dd, aa, bb, cc, _X[ 11], 13);
    cc = _FF3(cc, dd, aa, bb, _X[3], 15);
    bb = _FF3(bb, cc, dd, aa, _X[ 7],  7);
    aa = _FF3(aa, bb, cc, dd, _X[0], 12);
    dd = _FF3(dd, aa, bb, cc, _X[13],  8);
    cc = _FF3(cc, dd, aa, bb, _X[5],  9);
    bb = _FF3(bb, cc, dd, aa, _X[10], 11);
    aa = _FF3(aa, bb, cc, dd, _X[14],  7);
    dd = _FF3(dd, aa, bb, cc, _X[15],  7);
    cc = _FF3(cc, dd, aa, bb, _X[ 8], 12);
    bb = _FF3(bb, cc, dd, aa, _X[12],  7);
    aa = _FF3(aa, bb, cc, dd, _X[ 4],  6);
    dd = _FF3(dd, aa, bb, cc, _X[ 9], 15);
    cc = _FF3(cc, dd, aa, bb, _X[ 1], 13);
    bb = _FF3(bb, cc, dd, aa, _X[ 2], 11);

    t = b; b = bb; bb = t;

    // Round 3
    a = _F3(a, b, c, d, _X[ 3], 11);
    d = _F3(d, a, b, c, _X[10], 13);
    c = _F3(c, d, a, b, _X[14],  6);
    b = _F3(b, c, d, a, _X[ 4],  7);
    a = _F3(a, b, c, d, _X[ 9], 14);
    d = _F3(d, a, b, c, _X[15],  9);
    c = _F3(c, d, a, b, _X[ 8], 13);
    b = _F3(b, c, d, a, _X[ 1], 15);
    a = _F3(a, b, c, d, _X[ 2], 14);
    d = _F3(d, a, b, c, _X[ 7],  8);
    c = _F3(c, d, a, b, _X[ 0], 13);
    b = _F3(b, c, d, a, _X[ 6],  6);
    a = _F3(a, b, c, d, _X[13],  5);
    d = _F3(d, a, b, c, _X[11], 12);
    c = _F3(c, d, a, b, _X[ 5],  7);
    b = _F3(b, c, d, a, _X[12],  5);

    aa = _FF2(aa, bb, cc, dd, _X[ 15], 9);
    dd = _FF2(dd, aa, bb, cc, _X[5], 7);
    cc = _FF2(cc, dd, aa, bb, _X[1], 15);
    bb = _FF2(bb, cc, dd, aa, _X[ 3],  11);
    aa = _FF2(aa, bb, cc, dd, _X[ 7], 8);
    dd = _FF2(dd, aa, bb, cc, _X[14],  6);
    cc = _FF2(cc, dd, aa, bb, _X[ 6], 6);
    bb = _FF2(bb, cc, dd, aa, _X[ 9], 14);
    aa = _FF2(aa, bb, cc, dd, _X[11], 12);
    dd = _FF2(dd, aa, bb, cc, _X[ 8], 13);
    cc = _FF2(cc, dd, aa, bb, _X[12],  5);
    bb = _FF2(bb, cc, dd, aa, _X[ 2], 14);
    aa = _FF2(aa, bb, cc, dd, _X[10], 13);
    dd = _FF2(dd, aa, bb, cc, _X[ 0], 13);
    cc = _FF2(cc, dd, aa, bb, _X[ 4],  7);
    bb = _FF2(bb, cc, dd, aa, _X[13],  5);

    t = c; c = cc; cc = t;

    // Round 4
    a = _F4(a, b, c, d, _X[ 1], 11);
    d = _F4(d, a, b, c, _X[ 9], 12);
    c = _F4(c, d, a, b, _X[11], 14);
    b = _F4(b, c, d, a, _X[10], 15);
    a = _F4(a, b, c, d, _X[ 0], 14);
    d = _F4(d, a, b, c, _X[ 8], 15);
    c = _F4(c, d, a, b, _X[12],  9);
    b = _F4(b, c, d, a, _X[ 4],  8);
    a = _F4(a, b, c, d, _X[13],  9);
    d = _F4(d, a, b, c, _X[ 3], 14);
    c = _F4(c, d, a, b, _X[ 7],  5);
    b = _F4(b, c, d, a, _X[15],  6);
    a = _F4(a, b, c, d, _X[14],  8);
    d = _F4(d, a, b, c, _X[ 5],  6);
    c = _F4(c, d, a, b, _X[ 6],  5);
    b = _F4(b, c, d, a, _X[ 2], 12);

    aa = _FF1(aa, bb, cc, dd, _X[ 8], 15);
    dd = _FF1(dd, aa, bb, cc, _X[ 6],  5);
    cc = _FF1(cc, dd, aa, bb, _X[ 4],  8);
    bb = _FF1(bb, cc, dd, aa, _X[ 1], 11);
    aa = _FF1(aa, bb, cc, dd, _X[ 3], 14);
    dd = _FF1(dd, aa, bb, cc, _X[11], 14);
    cc = _FF1(cc, dd, aa, bb, _X[15],  6);
    bb = _FF1(bb, cc, dd, aa, _X[ 0], 14);
    aa = _FF1(aa, bb, cc, dd, _X[ 5],  6);
    dd = _FF1(dd, aa, bb, cc, _X[12],  9);
    cc = _FF1(cc, dd, aa, bb, _X[ 2],  12);
    bb = _FF1(bb, cc, dd, aa, _X[13],  9);
    aa = _FF1(aa, bb, cc, dd, _X[ 9],  12);
    dd = _FF1(dd, aa, bb, cc, _X[ 7],  5);
    cc = _FF1(cc, dd, aa, bb, _X[10],  15);
    bb = _FF1(bb, cc, dd, aa, _X[14], 8);

    t = d; d = dd; dd = t;

    _H0 += a;
    _H1 += b;
    _H2 += c;
    _H3 += d;
    _H4 += aa;
    _H5 += bb;
    _H6 += cc;
    _H7 += dd;

    // reset the offset and clean out the word buffer.
    _xOff = 0;
    _X.fillRange(0, _X.length, new Uint32(0));
  }

  Uint32 _f1( Uint32 x, Uint32 y, Uint32 z ) => x ^ y ^ z;
  Uint32 _f2( Uint32 x, Uint32 y, Uint32 z ) => (x & y) | (~x & z);
  Uint32 _f3( Uint32 x, Uint32 y, Uint32 z ) => (x | ~y) ^ z;
  Uint32 _f4( Uint32 x, Uint32 y, Uint32 z ) => (x & z) | (y & ~z);
  Uint32 _F1(Uint32 a, Uint32 b, Uint32 c, Uint32 d, Uint32 x, int s) => _rotl(a + _f1(b, c, d) + x, s);
  Uint32 _F2(Uint32 a, Uint32 b, Uint32 c, Uint32 d, Uint32 x, int s) => _rotl(a + _f2(b, c, d) + x + 0x5a827999, s);
  Uint32 _F3(Uint32 a, Uint32 b, Uint32 c, Uint32 d, Uint32 x, int s) => _rotl(a + _f3(b, c, d) + x + 0x6ed9eba1, s);
  Uint32 _F4(Uint32 a, Uint32 b, Uint32 c, Uint32 d, Uint32 x, int s) => _rotl(a + _f4(b, c, d) + x + 0x8f1bbcdc, s);
  Uint32 _FF1(Uint32 a, Uint32 b, Uint32 c, Uint32 d, Uint32 x, int s) => _rotl(a + _f1(b, c, d) + x, s);
  Uint32 _FF2(Uint32 a, Uint32 b, Uint32 c, Uint32 d, Uint32 x, int s) => _rotl(a + _f2(b, c, d) + x + 0x6d703ef3, s);
  Uint32 _FF3(Uint32 a, Uint32 b, Uint32 c, Uint32 d, Uint32 x, int s) => _rotl(a + _f3(b, c, d) + x + 0x5c4dd124, s);
  Uint32 _FF4(Uint32 a, Uint32 b, Uint32 c, Uint32 d, Uint32 x, int s) => _rotl(a + _f4(b, c, d) + x + 0x50a28be6, s);

}

void _unpackWord(Uint32 word, Uint8List out, int outOff) => word.toLittleEndian(out, outOff);

/** Cyclic logical shift left for 32 bit signed integers */
Uint32 _rotl( Uint32 x, int n ) => x.rotl(n);

/** Logical shift right for 32 bit signed integers */
Uint32 _lsr( Uint32 n, int shift ) => n >> shift;



