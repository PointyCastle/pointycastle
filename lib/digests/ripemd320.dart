// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.digests.ripemd320;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/digests/md4_family_digest.dart";

/// Implementation of RIPEMD-320 digest.
class RIPEMD320Digest extends MD4FamilyDigest implements Digest {

  static const _DIGEST_LENGTH = 40;

  Uint32 _H0, _H1, _H2, _H3, _H4, _H5, _H6, _H7, _H8, _H9; // IV's

  var _X = new List<Uint32>(16);
  int _xOff;

  RIPEMD320Digest() {
    reset();
  }

  String get algorithmName => "RIPEMD-320";

  int get digestSize => _DIGEST_LENGTH;

  void reset() {
    super.reset();

    _H0 = new Uint32(0x67452301);
    _H1 = new Uint32(0xefcdab89);
    _H2 = new Uint32(0x98badcfe);
    _H3 = new Uint32(0x10325476);
    _H4 = new Uint32(0xc3d2e1f0);
    _H5 = new Uint32(0x76543210);
    _H6 = new Uint32(0xFEDCBA98);
    _H7 = new Uint32(0x89ABCDEF);
    _H8 = new Uint32(0x01234567);
    _H9 = new Uint32(0x3C2D1E0F);

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
    _unpackWord(_H8, out, outOff + 32);
    _unpackWord(_H9, out, outOff + 36);

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
    var e, ee;
    var t;

    a = _H0;
    b = _H1;
    c = _H2;
    d = _H3;
    e = _H4;
    aa = _H5;
    bb = _H6;
    cc = _H7;
    dd = _H8;
    ee = _H9;

    //
    // Rounds 1 - 16
    //
    // left
    a = _rotl(a + _f1(b,c,d) + _X[ 0], 11) + e; c = _rotl(c, 10);
    e = _rotl(e + _f1(a,b,c) + _X[ 1], 14) + d; b = _rotl(b, 10);
    d = _rotl(d + _f1(e,a,b) + _X[ 2], 15) + c; a = _rotl(a, 10);
    c = _rotl(c + _f1(d,e,a) + _X[ 3], 12) + b; e = _rotl(e, 10);
    b = _rotl(b + _f1(c,d,e) + _X[ 4],  5) + a; d = _rotl(d, 10);
    a = _rotl(a + _f1(b,c,d) + _X[ 5],  8) + e; c = _rotl(c, 10);
    e = _rotl(e + _f1(a,b,c) + _X[ 6],  7) + d; b = _rotl(b, 10);
    d = _rotl(d + _f1(e,a,b) + _X[ 7],  9) + c; a = _rotl(a, 10);
    c = _rotl(c + _f1(d,e,a) + _X[ 8], 11) + b; e = _rotl(e, 10);
    b = _rotl(b + _f1(c,d,e) + _X[ 9], 13) + a; d = _rotl(d, 10);
    a = _rotl(a + _f1(b,c,d) + _X[10], 14) + e; c = _rotl(c, 10);
    e = _rotl(e + _f1(a,b,c) + _X[11], 15) + d; b = _rotl(b, 10);
    d = _rotl(d + _f1(e,a,b) + _X[12],  6) + c; a = _rotl(a, 10);
    c = _rotl(c + _f1(d,e,a) + _X[13],  7) + b; e = _rotl(e, 10);
    b = _rotl(b + _f1(c,d,e) + _X[14],  9) + a; d = _rotl(d, 10);
    a = _rotl(a + _f1(b,c,d) + _X[15],  8) + e; c = _rotl(c, 10);

    // right
    aa = _rotl(aa + _f5(bb,cc,dd) + _X[ 5] + 0x50a28be6,  8) + ee; cc = _rotl(cc, 10);
    ee = _rotl(ee + _f5(aa,bb,cc) + _X[14] + 0x50a28be6,  9) + dd; bb = _rotl(bb, 10);
    dd = _rotl(dd + _f5(ee,aa,bb) + _X[ 7] + 0x50a28be6,  9) + cc; aa = _rotl(aa, 10);
    cc = _rotl(cc + _f5(dd,ee,aa) + _X[ 0] + 0x50a28be6, 11) + bb; ee = _rotl(ee, 10);
    bb = _rotl(bb + _f5(cc,dd,ee) + _X[ 9] + 0x50a28be6, 13) + aa; dd = _rotl(dd, 10);
    aa = _rotl(aa + _f5(bb,cc,dd) + _X[ 2] + 0x50a28be6, 15) + ee; cc = _rotl(cc, 10);
    ee = _rotl(ee + _f5(aa,bb,cc) + _X[11] + 0x50a28be6, 15) + dd; bb = _rotl(bb, 10);
    dd = _rotl(dd + _f5(ee,aa,bb) + _X[ 4] + 0x50a28be6,  5) + cc; aa = _rotl(aa, 10);
    cc = _rotl(cc + _f5(dd,ee,aa) + _X[13] + 0x50a28be6,  7) + bb; ee = _rotl(ee, 10);
    bb = _rotl(bb + _f5(cc,dd,ee) + _X[ 6] + 0x50a28be6,  7) + aa; dd = _rotl(dd, 10);
    aa = _rotl(aa + _f5(bb,cc,dd) + _X[15] + 0x50a28be6,  8) + ee; cc = _rotl(cc, 10);
    ee = _rotl(ee + _f5(aa,bb,cc) + _X[ 8] + 0x50a28be6, 11) + dd; bb = _rotl(bb, 10);
    dd = _rotl(dd + _f5(ee,aa,bb) + _X[ 1] + 0x50a28be6, 14) + cc; aa = _rotl(aa, 10);
    cc = _rotl(cc + _f5(dd,ee,aa) + _X[10] + 0x50a28be6, 14) + bb; ee = _rotl(ee, 10);
    bb = _rotl(bb + _f5(cc,dd,ee) + _X[ 3] + 0x50a28be6, 12) + aa; dd = _rotl(dd, 10);
    aa = _rotl(aa + _f5(bb,cc,dd) + _X[12] + 0x50a28be6,  6) + ee; cc = _rotl(cc, 10);

    t = a; a = aa; aa = t;

    //
    // Rounds 16-31
    //
    // left
    e = _rotl(e + _f2(a,b,c) + _X[ 7] + 0x5a827999,  7) + d; b = _rotl(b, 10);
    d = _rotl(d + _f2(e,a,b) + _X[ 4] + 0x5a827999,  6) + c; a = _rotl(a, 10);
    c = _rotl(c + _f2(d,e,a) + _X[13] + 0x5a827999,  8) + b; e = _rotl(e, 10);
    b = _rotl(b + _f2(c,d,e) + _X[ 1] + 0x5a827999, 13) + a; d = _rotl(d, 10);
    a = _rotl(a + _f2(b,c,d) + _X[10] + 0x5a827999, 11) + e; c = _rotl(c, 10);
    e = _rotl(e + _f2(a,b,c) + _X[ 6] + 0x5a827999,  9) + d; b = _rotl(b, 10);
    d = _rotl(d + _f2(e,a,b) + _X[15] + 0x5a827999,  7) + c; a = _rotl(a, 10);
    c = _rotl(c + _f2(d,e,a) + _X[ 3] + 0x5a827999, 15) + b; e = _rotl(e, 10);
    b = _rotl(b + _f2(c,d,e) + _X[12] + 0x5a827999,  7) + a; d = _rotl(d, 10);
    a = _rotl(a + _f2(b,c,d) + _X[ 0] + 0x5a827999, 12) + e; c = _rotl(c, 10);
    e = _rotl(e + _f2(a,b,c) + _X[ 9] + 0x5a827999, 15) + d; b = _rotl(b, 10);
    d = _rotl(d + _f2(e,a,b) + _X[ 5] + 0x5a827999,  9) + c; a = _rotl(a, 10);
    c = _rotl(c + _f2(d,e,a) + _X[ 2] + 0x5a827999, 11) + b; e = _rotl(e, 10);
    b = _rotl(b + _f2(c,d,e) + _X[14] + 0x5a827999,  7) + a; d = _rotl(d, 10);
    a = _rotl(a + _f2(b,c,d) + _X[11] + 0x5a827999, 13) + e; c = _rotl(c, 10);
    e = _rotl(e + _f2(a,b,c) + _X[ 8] + 0x5a827999, 12) + d; b = _rotl(b, 10);

    // right
    ee = _rotl(ee + _f4(aa,bb,cc) + _X[ 6] + 0x5c4dd124,  9) + dd; bb = _rotl(bb, 10);
    dd = _rotl(dd + _f4(ee,aa,bb) + _X[11] + 0x5c4dd124, 13) + cc; aa = _rotl(aa, 10);
    cc = _rotl(cc + _f4(dd,ee,aa) + _X[ 3] + 0x5c4dd124, 15) + bb; ee = _rotl(ee, 10);
    bb = _rotl(bb + _f4(cc,dd,ee) + _X[ 7] + 0x5c4dd124,  7) + aa; dd = _rotl(dd, 10);
    aa = _rotl(aa + _f4(bb,cc,dd) + _X[ 0] + 0x5c4dd124, 12) + ee; cc = _rotl(cc, 10);
    ee = _rotl(ee + _f4(aa,bb,cc) + _X[13] + 0x5c4dd124,  8) + dd; bb = _rotl(bb, 10);
    dd = _rotl(dd + _f4(ee,aa,bb) + _X[ 5] + 0x5c4dd124,  9) + cc; aa = _rotl(aa, 10);
    cc = _rotl(cc + _f4(dd,ee,aa) + _X[10] + 0x5c4dd124, 11) + bb; ee = _rotl(ee, 10);
    bb = _rotl(bb + _f4(cc,dd,ee) + _X[14] + 0x5c4dd124,  7) + aa; dd = _rotl(dd, 10);
    aa = _rotl(aa + _f4(bb,cc,dd) + _X[15] + 0x5c4dd124,  7) + ee; cc = _rotl(cc, 10);
    ee = _rotl(ee + _f4(aa,bb,cc) + _X[ 8] + 0x5c4dd124, 12) + dd; bb = _rotl(bb, 10);
    dd = _rotl(dd + _f4(ee,aa,bb) + _X[12] + 0x5c4dd124,  7) + cc; aa = _rotl(aa, 10);
    cc = _rotl(cc + _f4(dd,ee,aa) + _X[ 4] + 0x5c4dd124,  6) + bb; ee = _rotl(ee, 10);
    bb = _rotl(bb + _f4(cc,dd,ee) + _X[ 9] + 0x5c4dd124, 15) + aa; dd = _rotl(dd, 10);
    aa = _rotl(aa + _f4(bb,cc,dd) + _X[ 1] + 0x5c4dd124, 13) + ee; cc = _rotl(cc, 10);
    ee = _rotl(ee + _f4(aa,bb,cc) + _X[ 2] + 0x5c4dd124, 11) + dd; bb = _rotl(bb, 10);

    t = b; b = bb; bb = t;

    //
    // Rounds 32-47
    //
    // left
    d = _rotl(d + _f3(e,a,b) + _X[ 3] + 0x6ed9eba1, 11) + c; a = _rotl(a, 10);
    c = _rotl(c + _f3(d,e,a) + _X[10] + 0x6ed9eba1, 13) + b; e = _rotl(e, 10);
    b = _rotl(b + _f3(c,d,e) + _X[14] + 0x6ed9eba1,  6) + a; d = _rotl(d, 10);
    a = _rotl(a + _f3(b,c,d) + _X[ 4] + 0x6ed9eba1,  7) + e; c = _rotl(c, 10);
    e = _rotl(e + _f3(a,b,c) + _X[ 9] + 0x6ed9eba1, 14) + d; b = _rotl(b, 10);
    d = _rotl(d + _f3(e,a,b) + _X[15] + 0x6ed9eba1,  9) + c; a = _rotl(a, 10);
    c = _rotl(c + _f3(d,e,a) + _X[ 8] + 0x6ed9eba1, 13) + b; e = _rotl(e, 10);
    b = _rotl(b + _f3(c,d,e) + _X[ 1] + 0x6ed9eba1, 15) + a; d = _rotl(d, 10);
    a = _rotl(a + _f3(b,c,d) + _X[ 2] + 0x6ed9eba1, 14) + e; c = _rotl(c, 10);
    e = _rotl(e + _f3(a,b,c) + _X[ 7] + 0x6ed9eba1,  8) + d; b = _rotl(b, 10);
    d = _rotl(d + _f3(e,a,b) + _X[ 0] + 0x6ed9eba1, 13) + c; a = _rotl(a, 10);
    c = _rotl(c + _f3(d,e,a) + _X[ 6] + 0x6ed9eba1,  6) + b; e = _rotl(e, 10);
    b = _rotl(b + _f3(c,d,e) + _X[13] + 0x6ed9eba1,  5) + a; d = _rotl(d, 10);
    a = _rotl(a + _f3(b,c,d) + _X[11] + 0x6ed9eba1, 12) + e; c = _rotl(c, 10);
    e = _rotl(e + _f3(a,b,c) + _X[ 5] + 0x6ed9eba1,  7) + d; b = _rotl(b, 10);
    d = _rotl(d + _f3(e,a,b) + _X[12] + 0x6ed9eba1,  5) + c; a = _rotl(a, 10);

    // right
    dd = _rotl(dd + _f3(ee,aa,bb) + _X[15] + 0x6d703ef3,  9) + cc; aa = _rotl(aa, 10);
    cc = _rotl(cc + _f3(dd,ee,aa) + _X[ 5] + 0x6d703ef3,  7) + bb; ee = _rotl(ee, 10);
    bb = _rotl(bb + _f3(cc,dd,ee) + _X[ 1] + 0x6d703ef3, 15) + aa; dd = _rotl(dd, 10);
    aa = _rotl(aa + _f3(bb,cc,dd) + _X[ 3] + 0x6d703ef3, 11) + ee; cc = _rotl(cc, 10);
    ee = _rotl(ee + _f3(aa,bb,cc) + _X[ 7] + 0x6d703ef3,  8) + dd; bb = _rotl(bb, 10);
    dd = _rotl(dd + _f3(ee,aa,bb) + _X[14] + 0x6d703ef3,  6) + cc; aa = _rotl(aa, 10);
    cc = _rotl(cc + _f3(dd,ee,aa) + _X[ 6] + 0x6d703ef3,  6) + bb; ee = _rotl(ee, 10);
    bb = _rotl(bb + _f3(cc,dd,ee) + _X[ 9] + 0x6d703ef3, 14) + aa; dd = _rotl(dd, 10);
    aa = _rotl(aa + _f3(bb,cc,dd) + _X[11] + 0x6d703ef3, 12) + ee; cc = _rotl(cc, 10);
    ee = _rotl(ee + _f3(aa,bb,cc) + _X[ 8] + 0x6d703ef3, 13) + dd; bb = _rotl(bb, 10);
    dd = _rotl(dd + _f3(ee,aa,bb) + _X[12] + 0x6d703ef3,  5) + cc; aa = _rotl(aa, 10);
    cc = _rotl(cc + _f3(dd,ee,aa) + _X[ 2] + 0x6d703ef3, 14) + bb; ee = _rotl(ee, 10);
    bb = _rotl(bb + _f3(cc,dd,ee) + _X[10] + 0x6d703ef3, 13) + aa; dd = _rotl(dd, 10);
    aa = _rotl(aa + _f3(bb,cc,dd) + _X[ 0] + 0x6d703ef3, 13) + ee; cc = _rotl(cc, 10);
    ee = _rotl(ee + _f3(aa,bb,cc) + _X[ 4] + 0x6d703ef3,  7) + dd; bb = _rotl(bb, 10);
    dd = _rotl(dd + _f3(ee,aa,bb) + _X[13] + 0x6d703ef3,  5) + cc; aa = _rotl(aa, 10);

    t = c; c = cc; cc = t;

    //
    // Rounds 48-63
    //
    // left
    c = _rotl(c + _f4(d,e,a) + _X[ 1] + 0x8f1bbcdc, 11) + b; e = _rotl(e, 10);
    b = _rotl(b + _f4(c,d,e) + _X[ 9] + 0x8f1bbcdc, 12) + a; d = _rotl(d, 10);
    a = _rotl(a + _f4(b,c,d) + _X[11] + 0x8f1bbcdc, 14) + e; c = _rotl(c, 10);
    e = _rotl(e + _f4(a,b,c) + _X[10] + 0x8f1bbcdc, 15) + d; b = _rotl(b, 10);
    d = _rotl(d + _f4(e,a,b) + _X[ 0] + 0x8f1bbcdc, 14) + c; a = _rotl(a, 10);
    c = _rotl(c + _f4(d,e,a) + _X[ 8] + 0x8f1bbcdc, 15) + b; e = _rotl(e, 10);
    b = _rotl(b + _f4(c,d,e) + _X[12] + 0x8f1bbcdc,  9) + a; d = _rotl(d, 10);
    a = _rotl(a + _f4(b,c,d) + _X[ 4] + 0x8f1bbcdc,  8) + e; c = _rotl(c, 10);
    e = _rotl(e + _f4(a,b,c) + _X[13] + 0x8f1bbcdc,  9) + d; b = _rotl(b, 10);
    d = _rotl(d + _f4(e,a,b) + _X[ 3] + 0x8f1bbcdc, 14) + c; a = _rotl(a, 10);
    c = _rotl(c + _f4(d,e,a) + _X[ 7] + 0x8f1bbcdc,  5) + b; e = _rotl(e, 10);
    b = _rotl(b + _f4(c,d,e) + _X[15] + 0x8f1bbcdc,  6) + a; d = _rotl(d, 10);
    a = _rotl(a + _f4(b,c,d) + _X[14] + 0x8f1bbcdc,  8) + e; c = _rotl(c, 10);
    e = _rotl(e + _f4(a,b,c) + _X[ 5] + 0x8f1bbcdc,  6) + d; b = _rotl(b, 10);
    d = _rotl(d + _f4(e,a,b) + _X[ 6] + 0x8f1bbcdc,  5) + c; a = _rotl(a, 10);
    c = _rotl(c + _f4(d,e,a) + _X[ 2] + 0x8f1bbcdc, 12) + b; e = _rotl(e, 10);

    // right
    cc = _rotl(cc + _f2(dd,ee,aa) + _X[ 8] + 0x7a6d76e9, 15) + bb; ee = _rotl(ee, 10);
    bb = _rotl(bb + _f2(cc,dd,ee) + _X[ 6] + 0x7a6d76e9,  5) + aa; dd = _rotl(dd, 10);
    aa = _rotl(aa + _f2(bb,cc,dd) + _X[ 4] + 0x7a6d76e9,  8) + ee; cc = _rotl(cc, 10);
    ee = _rotl(ee + _f2(aa,bb,cc) + _X[ 1] + 0x7a6d76e9, 11) + dd; bb = _rotl(bb, 10);
    dd = _rotl(dd + _f2(ee,aa,bb) + _X[ 3] + 0x7a6d76e9, 14) + cc; aa = _rotl(aa, 10);
    cc = _rotl(cc + _f2(dd,ee,aa) + _X[11] + 0x7a6d76e9, 14) + bb; ee = _rotl(ee, 10);
    bb = _rotl(bb + _f2(cc,dd,ee) + _X[15] + 0x7a6d76e9,  6) + aa; dd = _rotl(dd, 10);
    aa = _rotl(aa + _f2(bb,cc,dd) + _X[ 0] + 0x7a6d76e9, 14) + ee; cc = _rotl(cc, 10);
    ee = _rotl(ee + _f2(aa,bb,cc) + _X[ 5] + 0x7a6d76e9,  6) + dd; bb = _rotl(bb, 10);
    dd = _rotl(dd + _f2(ee,aa,bb) + _X[12] + 0x7a6d76e9,  9) + cc; aa = _rotl(aa, 10);
    cc = _rotl(cc + _f2(dd,ee,aa) + _X[ 2] + 0x7a6d76e9, 12) + bb; ee = _rotl(ee, 10);
    bb = _rotl(bb + _f2(cc,dd,ee) + _X[13] + 0x7a6d76e9,  9) + aa; dd = _rotl(dd, 10);
    aa = _rotl(aa + _f2(bb,cc,dd) + _X[ 9] + 0x7a6d76e9, 12) + ee; cc = _rotl(cc, 10);
    ee = _rotl(ee + _f2(aa,bb,cc) + _X[ 7] + 0x7a6d76e9,  5) + dd; bb = _rotl(bb, 10);
    dd = _rotl(dd + _f2(ee,aa,bb) + _X[10] + 0x7a6d76e9, 15) + cc; aa = _rotl(aa, 10);
    cc = _rotl(cc + _f2(dd,ee,aa) + _X[14] + 0x7a6d76e9,  8) + bb; ee = _rotl(ee, 10);

   t = d; d = dd; dd = t;

    //
    // Rounds 64-79
    //
    // left
    b = _rotl(b + _f5(c,d,e) + _X[ 4] + 0xa953fd4e,  9) + a; d = _rotl(d, 10);
    a = _rotl(a + _f5(b,c,d) + _X[ 0] + 0xa953fd4e, 15) + e; c = _rotl(c, 10);
    e = _rotl(e + _f5(a,b,c) + _X[ 5] + 0xa953fd4e,  5) + d; b = _rotl(b, 10);
    d = _rotl(d + _f5(e,a,b) + _X[ 9] + 0xa953fd4e, 11) + c; a = _rotl(a, 10);
    c = _rotl(c + _f5(d,e,a) + _X[ 7] + 0xa953fd4e,  6) + b; e = _rotl(e, 10);
    b = _rotl(b + _f5(c,d,e) + _X[12] + 0xa953fd4e,  8) + a; d = _rotl(d, 10);
    a = _rotl(a + _f5(b,c,d) + _X[ 2] + 0xa953fd4e, 13) + e; c = _rotl(c, 10);
    e = _rotl(e + _f5(a,b,c) + _X[10] + 0xa953fd4e, 12) + d; b = _rotl(b, 10);
    d = _rotl(d + _f5(e,a,b) + _X[14] + 0xa953fd4e,  5) + c; a = _rotl(a, 10);
    c = _rotl(c + _f5(d,e,a) + _X[ 1] + 0xa953fd4e, 12) + b; e = _rotl(e, 10);
    b = _rotl(b + _f5(c,d,e) + _X[ 3] + 0xa953fd4e, 13) + a; d = _rotl(d, 10);
    a = _rotl(a + _f5(b,c,d) + _X[ 8] + 0xa953fd4e, 14) + e; c = _rotl(c, 10);
    e = _rotl(e + _f5(a,b,c) + _X[11] + 0xa953fd4e, 11) + d; b = _rotl(b, 10);
    d = _rotl(d + _f5(e,a,b) + _X[ 6] + 0xa953fd4e,  8) + c; a = _rotl(a, 10);
    c = _rotl(c + _f5(d,e,a) + _X[15] + 0xa953fd4e,  5) + b; e = _rotl(e, 10);
    b = _rotl(b + _f5(c,d,e) + _X[13] + 0xa953fd4e,  6) + a; d = _rotl(d, 10);

    // right
    bb = _rotl(bb + _f1(cc,dd,ee) + _X[12],  8) + aa; dd = _rotl(dd, 10);
    aa = _rotl(aa + _f1(bb,cc,dd) + _X[15],  5) + ee; cc = _rotl(cc, 10);
    ee = _rotl(ee + _f1(aa,bb,cc) + _X[10], 12) + dd; bb = _rotl(bb, 10);
    dd = _rotl(dd + _f1(ee,aa,bb) + _X[ 4],  9) + cc; aa = _rotl(aa, 10);
    cc = _rotl(cc + _f1(dd,ee,aa) + _X[ 1], 12) + bb; ee = _rotl(ee, 10);
    bb = _rotl(bb + _f1(cc,dd,ee) + _X[ 5],  5) + aa; dd = _rotl(dd, 10);
    aa = _rotl(aa + _f1(bb,cc,dd) + _X[ 8], 14) + ee; cc = _rotl(cc, 10);
    ee = _rotl(ee + _f1(aa,bb,cc) + _X[ 7],  6) + dd; bb = _rotl(bb, 10);
    dd = _rotl(dd + _f1(ee,aa,bb) + _X[ 6],  8) + cc; aa = _rotl(aa, 10);
    cc = _rotl(cc + _f1(dd,ee,aa) + _X[ 2], 13) + bb; ee = _rotl(ee, 10);
    bb = _rotl(bb + _f1(cc,dd,ee) + _X[13],  6) + aa; dd = _rotl(dd, 10);
    aa = _rotl(aa + _f1(bb,cc,dd) + _X[14],  5) + ee; cc = _rotl(cc, 10);
    ee = _rotl(ee + _f1(aa,bb,cc) + _X[ 0], 15) + dd; bb = _rotl(bb, 10);
    dd = _rotl(dd + _f1(ee,aa,bb) + _X[ 3], 13) + cc; aa = _rotl(aa, 10);
    cc = _rotl(cc + _f1(dd,ee,aa) + _X[ 9], 11) + bb; ee = _rotl(ee, 10);
    bb = _rotl(bb + _f1(cc,dd,ee) + _X[11], 11) + aa; dd = _rotl(dd, 10);

    // do (e, ee) swap as part of assignment.
    _H0 += a;
    _H1 += b;
    _H2 += c;
    _H3 += d;
    _H4 += ee;
    _H5 += aa;
    _H6 += bb;
    _H7 += cc;
    _H8 += dd;
    _H9 += e;

    // reset the offset and clean out the word buffer.
    _xOff = 0;
    _X.fillRange(0, _X.length, new Uint32(0));
  }

  Uint32 _f1( Uint32 x, Uint32 y, Uint32 z ) => x ^ y ^ z;
  Uint32 _f2( Uint32 x, Uint32 y, Uint32 z ) => (x & y) | (~x & z);
  Uint32 _f3( Uint32 x, Uint32 y, Uint32 z ) => (x | ~y) ^ z;
  Uint32 _f4( Uint32 x, Uint32 y, Uint32 z ) => (x & z) | (y & ~z);
  Uint32 _f5( Uint32 x, Uint32 y, Uint32 z ) => x ^ (y | ~z);

}

void _unpackWord(Uint32 word, Uint8List out, int outOff) => word.toLittleEndian(out, outOff);

/** Cyclic logical shift left for 32 bit signed integers */
Uint32 _rotl( Uint32 x, int n ) => x.rotl(n);

/** Logical shift right for 32 bit signed integers */
Uint32 _lsr( Uint32 n, int shift ) => n >> shift;



