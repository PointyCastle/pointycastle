// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.digests.ripemd320;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/api/ufixnum.dart";
import "package:cipher/digests/md4_family_digest.dart";

/// Implementation of RIPEMD-320 digest.
class RIPEMD320Digest extends MD4FamilyDigest implements Digest {

  static const _DIGEST_LENGTH = 40;

  int _H0, _H1, _H2, _H3, _H4, _H5, _H6, _H7, _H8, _H9;
  final _X = new List<int>(16);
  int _xOff;

  RIPEMD320Digest() {
    reset();
  }

  final algorithmName = "RIPEMD-320";
  final digestSize = _DIGEST_LENGTH;

  void reset() {
    super.reset();

    _H0 = 0x67452301;
    _H1 = 0xefcdab89;
    _H2 = 0x98badcfe;
    _H3 = 0x10325476;
    _H4 = 0xc3d2e1f0;
    _H5 = 0x76543210;
    _H6 = 0xFEDCBA98;
    _H7 = 0x89ABCDEF;
    _H8 = 0x01234567;
    _H9 = 0x3C2D1E0F;

    _xOff = 0;
    _X.fillRange(0, _X.length, 0);
  }

  int doFinal(Uint8List out, int outOff) {
    finish();

    pack32(_H0, out, (outOff     ), Endianness.LITTLE_ENDIAN);
    pack32(_H1, out, (outOff +  4), Endianness.LITTLE_ENDIAN);
    pack32(_H2, out, (outOff +  8), Endianness.LITTLE_ENDIAN);
    pack32(_H3, out, (outOff + 12), Endianness.LITTLE_ENDIAN);
    pack32(_H4, out, (outOff + 16), Endianness.LITTLE_ENDIAN);
    pack32(_H5, out, (outOff + 20), Endianness.LITTLE_ENDIAN);
    pack32(_H6, out, (outOff + 24), Endianness.LITTLE_ENDIAN);
    pack32(_H7, out, (outOff + 28), Endianness.LITTLE_ENDIAN);
    pack32(_H8, out, (outOff + 32), Endianness.LITTLE_ENDIAN);
    pack32(_H9, out, (outOff + 36), Endianness.LITTLE_ENDIAN);

    reset();

    return _DIGEST_LENGTH;
  }

  void processWord(Uint8List inp, int inpOff) {
    _X[_xOff++] = unpack32(inp, inpOff, Endianness.LITTLE_ENDIAN);

    if (_xOff == 16) {
        processBlock();
    }
  }

  void processLength(Register64 bitLength) {
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
    a = sum32(crotl32(a + _f1(b,c,d) + _X[ 0], 11), e); c = rotl32(c, 10);
    e = sum32(crotl32(e + _f1(a,b,c) + _X[ 1], 14), d); b = rotl32(b, 10);
    d = sum32(crotl32(d + _f1(e,a,b) + _X[ 2], 15), c); a = rotl32(a, 10);
    c = sum32(crotl32(c + _f1(d,e,a) + _X[ 3], 12), b); e = rotl32(e, 10);
    b = sum32(crotl32(b + _f1(c,d,e) + _X[ 4],  5), a); d = rotl32(d, 10);
    a = sum32(crotl32(a + _f1(b,c,d) + _X[ 5],  8), e); c = rotl32(c, 10);
    e = sum32(crotl32(e + _f1(a,b,c) + _X[ 6],  7), d); b = rotl32(b, 10);
    d = sum32(crotl32(d + _f1(e,a,b) + _X[ 7],  9), c); a = rotl32(a, 10);
    c = sum32(crotl32(c + _f1(d,e,a) + _X[ 8], 11), b); e = rotl32(e, 10);
    b = sum32(crotl32(b + _f1(c,d,e) + _X[ 9], 13), a); d = rotl32(d, 10);
    a = sum32(crotl32(a + _f1(b,c,d) + _X[10], 14), e); c = rotl32(c, 10);
    e = sum32(crotl32(e + _f1(a,b,c) + _X[11], 15), d); b = rotl32(b, 10);
    d = sum32(crotl32(d + _f1(e,a,b) + _X[12],  6), c); a = rotl32(a, 10);
    c = sum32(crotl32(c + _f1(d,e,a) + _X[13],  7), b); e = rotl32(e, 10);
    b = sum32(crotl32(b + _f1(c,d,e) + _X[14],  9), a); d = rotl32(d, 10);
    a = sum32(crotl32(a + _f1(b,c,d) + _X[15],  8), e); c = rotl32(c, 10);

    // right
    aa = sum32(crotl32(aa + _f5(bb,cc,dd) + _X[ 5] + 0x50a28be6,  8), ee); cc = rotl32(cc, 10);
    ee = sum32(crotl32(ee + _f5(aa,bb,cc) + _X[14] + 0x50a28be6,  9), dd); bb = rotl32(bb, 10);
    dd = sum32(crotl32(dd + _f5(ee,aa,bb) + _X[ 7] + 0x50a28be6,  9), cc); aa = rotl32(aa, 10);
    cc = sum32(crotl32(cc + _f5(dd,ee,aa) + _X[ 0] + 0x50a28be6, 11), bb); ee = rotl32(ee, 10);
    bb = sum32(crotl32(bb + _f5(cc,dd,ee) + _X[ 9] + 0x50a28be6, 13), aa); dd = rotl32(dd, 10);
    aa = sum32(crotl32(aa + _f5(bb,cc,dd) + _X[ 2] + 0x50a28be6, 15), ee); cc = rotl32(cc, 10);
    ee = sum32(crotl32(ee + _f5(aa,bb,cc) + _X[11] + 0x50a28be6, 15), dd); bb = rotl32(bb, 10);
    dd = sum32(crotl32(dd + _f5(ee,aa,bb) + _X[ 4] + 0x50a28be6,  5), cc); aa = rotl32(aa, 10);
    cc = sum32(crotl32(cc + _f5(dd,ee,aa) + _X[13] + 0x50a28be6,  7), bb); ee = rotl32(ee, 10);
    bb = sum32(crotl32(bb + _f5(cc,dd,ee) + _X[ 6] + 0x50a28be6,  7), aa); dd = rotl32(dd, 10);
    aa = sum32(crotl32(aa + _f5(bb,cc,dd) + _X[15] + 0x50a28be6,  8), ee); cc = rotl32(cc, 10);
    ee = sum32(crotl32(ee + _f5(aa,bb,cc) + _X[ 8] + 0x50a28be6, 11), dd); bb = rotl32(bb, 10);
    dd = sum32(crotl32(dd + _f5(ee,aa,bb) + _X[ 1] + 0x50a28be6, 14), cc); aa = rotl32(aa, 10);
    cc = sum32(crotl32(cc + _f5(dd,ee,aa) + _X[10] + 0x50a28be6, 14), bb); ee = rotl32(ee, 10);
    bb = sum32(crotl32(bb + _f5(cc,dd,ee) + _X[ 3] + 0x50a28be6, 12), aa); dd = rotl32(dd, 10);
    aa = sum32(crotl32(aa + _f5(bb,cc,dd) + _X[12] + 0x50a28be6,  6), ee); cc = rotl32(cc, 10);

    t = a; a = aa; aa = t;

    //
    // Rounds 16-31
    //
    // left
    e = sum32(crotl32(e + _f2(a,b,c) + _X[ 7] + 0x5a827999,  7), d); b = rotl32(b, 10);
    d = sum32(crotl32(d + _f2(e,a,b) + _X[ 4] + 0x5a827999,  6), c); a = rotl32(a, 10);
    c = sum32(crotl32(c + _f2(d,e,a) + _X[13] + 0x5a827999,  8), b); e = rotl32(e, 10);
    b = sum32(crotl32(b + _f2(c,d,e) + _X[ 1] + 0x5a827999, 13), a); d = rotl32(d, 10);
    a = sum32(crotl32(a + _f2(b,c,d) + _X[10] + 0x5a827999, 11), e); c = rotl32(c, 10);
    e = sum32(crotl32(e + _f2(a,b,c) + _X[ 6] + 0x5a827999,  9), d); b = rotl32(b, 10);
    d = sum32(crotl32(d + _f2(e,a,b) + _X[15] + 0x5a827999,  7), c); a = rotl32(a, 10);
    c = sum32(crotl32(c + _f2(d,e,a) + _X[ 3] + 0x5a827999, 15), b); e = rotl32(e, 10);
    b = sum32(crotl32(b + _f2(c,d,e) + _X[12] + 0x5a827999,  7), a); d = rotl32(d, 10);
    a = sum32(crotl32(a + _f2(b,c,d) + _X[ 0] + 0x5a827999, 12), e); c = rotl32(c, 10);
    e = sum32(crotl32(e + _f2(a,b,c) + _X[ 9] + 0x5a827999, 15), d); b = rotl32(b, 10);
    d = sum32(crotl32(d + _f2(e,a,b) + _X[ 5] + 0x5a827999,  9), c); a = rotl32(a, 10);
    c = sum32(crotl32(c + _f2(d,e,a) + _X[ 2] + 0x5a827999, 11), b); e = rotl32(e, 10);
    b = sum32(crotl32(b + _f2(c,d,e) + _X[14] + 0x5a827999,  7), a); d = rotl32(d, 10);
    a = sum32(crotl32(a + _f2(b,c,d) + _X[11] + 0x5a827999, 13), e); c = rotl32(c, 10);
    e = sum32(crotl32(e + _f2(a,b,c) + _X[ 8] + 0x5a827999, 12), d); b = rotl32(b, 10);

    // right
    ee = sum32(crotl32(ee + _f4(aa,bb,cc) + _X[ 6] + 0x5c4dd124,  9), dd); bb = rotl32(bb, 10);
    dd = sum32(crotl32(dd + _f4(ee,aa,bb) + _X[11] + 0x5c4dd124, 13), cc); aa = rotl32(aa, 10);
    cc = sum32(crotl32(cc + _f4(dd,ee,aa) + _X[ 3] + 0x5c4dd124, 15), bb); ee = rotl32(ee, 10);
    bb = sum32(crotl32(bb + _f4(cc,dd,ee) + _X[ 7] + 0x5c4dd124,  7), aa); dd = rotl32(dd, 10);
    aa = sum32(crotl32(aa + _f4(bb,cc,dd) + _X[ 0] + 0x5c4dd124, 12), ee); cc = rotl32(cc, 10);
    ee = sum32(crotl32(ee + _f4(aa,bb,cc) + _X[13] + 0x5c4dd124,  8), dd); bb = rotl32(bb, 10);
    dd = sum32(crotl32(dd + _f4(ee,aa,bb) + _X[ 5] + 0x5c4dd124,  9), cc); aa = rotl32(aa, 10);
    cc = sum32(crotl32(cc + _f4(dd,ee,aa) + _X[10] + 0x5c4dd124, 11), bb); ee = rotl32(ee, 10);
    bb = sum32(crotl32(bb + _f4(cc,dd,ee) + _X[14] + 0x5c4dd124,  7), aa); dd = rotl32(dd, 10);
    aa = sum32(crotl32(aa + _f4(bb,cc,dd) + _X[15] + 0x5c4dd124,  7), ee); cc = rotl32(cc, 10);
    ee = sum32(crotl32(ee + _f4(aa,bb,cc) + _X[ 8] + 0x5c4dd124, 12), dd); bb = rotl32(bb, 10);
    dd = sum32(crotl32(dd + _f4(ee,aa,bb) + _X[12] + 0x5c4dd124,  7), cc); aa = rotl32(aa, 10);
    cc = sum32(crotl32(cc + _f4(dd,ee,aa) + _X[ 4] + 0x5c4dd124,  6), bb); ee = rotl32(ee, 10);
    bb = sum32(crotl32(bb + _f4(cc,dd,ee) + _X[ 9] + 0x5c4dd124, 15), aa); dd = rotl32(dd, 10);
    aa = sum32(crotl32(aa + _f4(bb,cc,dd) + _X[ 1] + 0x5c4dd124, 13), ee); cc = rotl32(cc, 10);
    ee = sum32(crotl32(ee + _f4(aa,bb,cc) + _X[ 2] + 0x5c4dd124, 11), dd); bb = rotl32(bb, 10);

    t = b; b = bb; bb = t;

    //
    // Rounds 32-47
    //
    // left
    d = sum32(crotl32(d + _f3(e,a,b) + _X[ 3] + 0x6ed9eba1, 11), c); a = rotl32(a, 10);
    c = sum32(crotl32(c + _f3(d,e,a) + _X[10] + 0x6ed9eba1, 13), b); e = rotl32(e, 10);
    b = sum32(crotl32(b + _f3(c,d,e) + _X[14] + 0x6ed9eba1,  6), a); d = rotl32(d, 10);
    a = sum32(crotl32(a + _f3(b,c,d) + _X[ 4] + 0x6ed9eba1,  7), e); c = rotl32(c, 10);
    e = sum32(crotl32(e + _f3(a,b,c) + _X[ 9] + 0x6ed9eba1, 14), d); b = rotl32(b, 10);
    d = sum32(crotl32(d + _f3(e,a,b) + _X[15] + 0x6ed9eba1,  9), c); a = rotl32(a, 10);
    c = sum32(crotl32(c + _f3(d,e,a) + _X[ 8] + 0x6ed9eba1, 13), b); e = rotl32(e, 10);
    b = sum32(crotl32(b + _f3(c,d,e) + _X[ 1] + 0x6ed9eba1, 15), a); d = rotl32(d, 10);
    a = sum32(crotl32(a + _f3(b,c,d) + _X[ 2] + 0x6ed9eba1, 14), e); c = rotl32(c, 10);
    e = sum32(crotl32(e + _f3(a,b,c) + _X[ 7] + 0x6ed9eba1,  8), d); b = rotl32(b, 10);
    d = sum32(crotl32(d + _f3(e,a,b) + _X[ 0] + 0x6ed9eba1, 13), c); a = rotl32(a, 10);
    c = sum32(crotl32(c + _f3(d,e,a) + _X[ 6] + 0x6ed9eba1,  6), b); e = rotl32(e, 10);
    b = sum32(crotl32(b + _f3(c,d,e) + _X[13] + 0x6ed9eba1,  5), a); d = rotl32(d, 10);
    a = sum32(crotl32(a + _f3(b,c,d) + _X[11] + 0x6ed9eba1, 12), e); c = rotl32(c, 10);
    e = sum32(crotl32(e + _f3(a,b,c) + _X[ 5] + 0x6ed9eba1,  7), d); b = rotl32(b, 10);
    d = sum32(crotl32(d + _f3(e,a,b) + _X[12] + 0x6ed9eba1,  5), c); a = rotl32(a, 10);

    // right
    dd = sum32(crotl32(dd + _f3(ee,aa,bb) + _X[15] + 0x6d703ef3,  9), cc); aa = rotl32(aa, 10);
    cc = sum32(crotl32(cc + _f3(dd,ee,aa) + _X[ 5] + 0x6d703ef3,  7), bb); ee = rotl32(ee, 10);
    bb = sum32(crotl32(bb + _f3(cc,dd,ee) + _X[ 1] + 0x6d703ef3, 15), aa); dd = rotl32(dd, 10);
    aa = sum32(crotl32(aa + _f3(bb,cc,dd) + _X[ 3] + 0x6d703ef3, 11), ee); cc = rotl32(cc, 10);
    ee = sum32(crotl32(ee + _f3(aa,bb,cc) + _X[ 7] + 0x6d703ef3,  8), dd); bb = rotl32(bb, 10);
    dd = sum32(crotl32(dd + _f3(ee,aa,bb) + _X[14] + 0x6d703ef3,  6), cc); aa = rotl32(aa, 10);
    cc = sum32(crotl32(cc + _f3(dd,ee,aa) + _X[ 6] + 0x6d703ef3,  6), bb); ee = rotl32(ee, 10);
    bb = sum32(crotl32(bb + _f3(cc,dd,ee) + _X[ 9] + 0x6d703ef3, 14), aa); dd = rotl32(dd, 10);
    aa = sum32(crotl32(aa + _f3(bb,cc,dd) + _X[11] + 0x6d703ef3, 12), ee); cc = rotl32(cc, 10);
    ee = sum32(crotl32(ee + _f3(aa,bb,cc) + _X[ 8] + 0x6d703ef3, 13), dd); bb = rotl32(bb, 10);
    dd = sum32(crotl32(dd + _f3(ee,aa,bb) + _X[12] + 0x6d703ef3,  5), cc); aa = rotl32(aa, 10);
    cc = sum32(crotl32(cc + _f3(dd,ee,aa) + _X[ 2] + 0x6d703ef3, 14), bb); ee = rotl32(ee, 10);
    bb = sum32(crotl32(bb + _f3(cc,dd,ee) + _X[10] + 0x6d703ef3, 13), aa); dd = rotl32(dd, 10);
    aa = sum32(crotl32(aa + _f3(bb,cc,dd) + _X[ 0] + 0x6d703ef3, 13), ee); cc = rotl32(cc, 10);
    ee = sum32(crotl32(ee + _f3(aa,bb,cc) + _X[ 4] + 0x6d703ef3,  7), dd); bb = rotl32(bb, 10);
    dd = sum32(crotl32(dd + _f3(ee,aa,bb) + _X[13] + 0x6d703ef3,  5), cc); aa = rotl32(aa, 10);

    t = c; c = cc; cc = t;

    //
    // Rounds 48-63
    //
    // left
    c = sum32(crotl32(c + _f4(d,e,a) + _X[ 1] + 0x8f1bbcdc, 11), b); e = rotl32(e, 10);
    b = sum32(crotl32(b + _f4(c,d,e) + _X[ 9] + 0x8f1bbcdc, 12), a); d = rotl32(d, 10);
    a = sum32(crotl32(a + _f4(b,c,d) + _X[11] + 0x8f1bbcdc, 14), e); c = rotl32(c, 10);
    e = sum32(crotl32(e + _f4(a,b,c) + _X[10] + 0x8f1bbcdc, 15), d); b = rotl32(b, 10);
    d = sum32(crotl32(d + _f4(e,a,b) + _X[ 0] + 0x8f1bbcdc, 14), c); a = rotl32(a, 10);
    c = sum32(crotl32(c + _f4(d,e,a) + _X[ 8] + 0x8f1bbcdc, 15), b); e = rotl32(e, 10);
    b = sum32(crotl32(b + _f4(c,d,e) + _X[12] + 0x8f1bbcdc,  9), a); d = rotl32(d, 10);
    a = sum32(crotl32(a + _f4(b,c,d) + _X[ 4] + 0x8f1bbcdc,  8), e); c = rotl32(c, 10);
    e = sum32(crotl32(e + _f4(a,b,c) + _X[13] + 0x8f1bbcdc,  9), d); b = rotl32(b, 10);
    d = sum32(crotl32(d + _f4(e,a,b) + _X[ 3] + 0x8f1bbcdc, 14), c); a = rotl32(a, 10);
    c = sum32(crotl32(c + _f4(d,e,a) + _X[ 7] + 0x8f1bbcdc,  5), b); e = rotl32(e, 10);
    b = sum32(crotl32(b + _f4(c,d,e) + _X[15] + 0x8f1bbcdc,  6), a); d = rotl32(d, 10);
    a = sum32(crotl32(a + _f4(b,c,d) + _X[14] + 0x8f1bbcdc,  8), e); c = rotl32(c, 10);
    e = sum32(crotl32(e + _f4(a,b,c) + _X[ 5] + 0x8f1bbcdc,  6), d); b = rotl32(b, 10);
    d = sum32(crotl32(d + _f4(e,a,b) + _X[ 6] + 0x8f1bbcdc,  5), c); a = rotl32(a, 10);
    c = sum32(crotl32(c + _f4(d,e,a) + _X[ 2] + 0x8f1bbcdc, 12), b); e = rotl32(e, 10);

    // right
    cc = sum32(crotl32(cc + _f2(dd,ee,aa) + _X[ 8] + 0x7a6d76e9, 15), bb); ee = rotl32(ee, 10);
    bb = sum32(crotl32(bb + _f2(cc,dd,ee) + _X[ 6] + 0x7a6d76e9,  5), aa); dd = rotl32(dd, 10);
    aa = sum32(crotl32(aa + _f2(bb,cc,dd) + _X[ 4] + 0x7a6d76e9,  8), ee); cc = rotl32(cc, 10);
    ee = sum32(crotl32(ee + _f2(aa,bb,cc) + _X[ 1] + 0x7a6d76e9, 11), dd); bb = rotl32(bb, 10);
    dd = sum32(crotl32(dd + _f2(ee,aa,bb) + _X[ 3] + 0x7a6d76e9, 14), cc); aa = rotl32(aa, 10);
    cc = sum32(crotl32(cc + _f2(dd,ee,aa) + _X[11] + 0x7a6d76e9, 14), bb); ee = rotl32(ee, 10);
    bb = sum32(crotl32(bb + _f2(cc,dd,ee) + _X[15] + 0x7a6d76e9,  6), aa); dd = rotl32(dd, 10);
    aa = sum32(crotl32(aa + _f2(bb,cc,dd) + _X[ 0] + 0x7a6d76e9, 14), ee); cc = rotl32(cc, 10);
    ee = sum32(crotl32(ee + _f2(aa,bb,cc) + _X[ 5] + 0x7a6d76e9,  6), dd); bb = rotl32(bb, 10);
    dd = sum32(crotl32(dd + _f2(ee,aa,bb) + _X[12] + 0x7a6d76e9,  9), cc); aa = rotl32(aa, 10);
    cc = sum32(crotl32(cc + _f2(dd,ee,aa) + _X[ 2] + 0x7a6d76e9, 12), bb); ee = rotl32(ee, 10);
    bb = sum32(crotl32(bb + _f2(cc,dd,ee) + _X[13] + 0x7a6d76e9,  9), aa); dd = rotl32(dd, 10);
    aa = sum32(crotl32(aa + _f2(bb,cc,dd) + _X[ 9] + 0x7a6d76e9, 12), ee); cc = rotl32(cc, 10);
    ee = sum32(crotl32(ee + _f2(aa,bb,cc) + _X[ 7] + 0x7a6d76e9,  5), dd); bb = rotl32(bb, 10);
    dd = sum32(crotl32(dd + _f2(ee,aa,bb) + _X[10] + 0x7a6d76e9, 15), cc); aa = rotl32(aa, 10);
    cc = sum32(crotl32(cc + _f2(dd,ee,aa) + _X[14] + 0x7a6d76e9,  8), bb); ee = rotl32(ee, 10);

   t = d; d = dd; dd = t;

    //
    // Rounds 64-79
    //
    // left
    b = sum32(crotl32(b + _f5(c,d,e) + _X[ 4] + 0xa953fd4e,  9), a); d = rotl32(d, 10);
    a = sum32(crotl32(a + _f5(b,c,d) + _X[ 0] + 0xa953fd4e, 15), e); c = rotl32(c, 10);
    e = sum32(crotl32(e + _f5(a,b,c) + _X[ 5] + 0xa953fd4e,  5), d); b = rotl32(b, 10);
    d = sum32(crotl32(d + _f5(e,a,b) + _X[ 9] + 0xa953fd4e, 11), c); a = rotl32(a, 10);
    c = sum32(crotl32(c + _f5(d,e,a) + _X[ 7] + 0xa953fd4e,  6), b); e = rotl32(e, 10);
    b = sum32(crotl32(b + _f5(c,d,e) + _X[12] + 0xa953fd4e,  8), a); d = rotl32(d, 10);
    a = sum32(crotl32(a + _f5(b,c,d) + _X[ 2] + 0xa953fd4e, 13), e); c = rotl32(c, 10);
    e = sum32(crotl32(e + _f5(a,b,c) + _X[10] + 0xa953fd4e, 12), d); b = rotl32(b, 10);
    d = sum32(crotl32(d + _f5(e,a,b) + _X[14] + 0xa953fd4e,  5), c); a = rotl32(a, 10);
    c = sum32(crotl32(c + _f5(d,e,a) + _X[ 1] + 0xa953fd4e, 12), b); e = rotl32(e, 10);
    b = sum32(crotl32(b + _f5(c,d,e) + _X[ 3] + 0xa953fd4e, 13), a); d = rotl32(d, 10);
    a = sum32(crotl32(a + _f5(b,c,d) + _X[ 8] + 0xa953fd4e, 14), e); c = rotl32(c, 10);
    e = sum32(crotl32(e + _f5(a,b,c) + _X[11] + 0xa953fd4e, 11), d); b = rotl32(b, 10);
    d = sum32(crotl32(d + _f5(e,a,b) + _X[ 6] + 0xa953fd4e,  8), c); a = rotl32(a, 10);
    c = sum32(crotl32(c + _f5(d,e,a) + _X[15] + 0xa953fd4e,  5), b); e = rotl32(e, 10);
    b = sum32(crotl32(b + _f5(c,d,e) + _X[13] + 0xa953fd4e,  6), a); d = rotl32(d, 10);

    // right
    bb = sum32(crotl32(bb + _f1(cc,dd,ee) + _X[12],  8), aa); dd = rotl32(dd, 10);
    aa = sum32(crotl32(aa + _f1(bb,cc,dd) + _X[15],  5), ee); cc = rotl32(cc, 10);
    ee = sum32(crotl32(ee + _f1(aa,bb,cc) + _X[10], 12), dd); bb = rotl32(bb, 10);
    dd = sum32(crotl32(dd + _f1(ee,aa,bb) + _X[ 4],  9), cc); aa = rotl32(aa, 10);
    cc = sum32(crotl32(cc + _f1(dd,ee,aa) + _X[ 1], 12), bb); ee = rotl32(ee, 10);
    bb = sum32(crotl32(bb + _f1(cc,dd,ee) + _X[ 5],  5), aa); dd = rotl32(dd, 10);
    aa = sum32(crotl32(aa + _f1(bb,cc,dd) + _X[ 8], 14), ee); cc = rotl32(cc, 10);
    ee = sum32(crotl32(ee + _f1(aa,bb,cc) + _X[ 7],  6), dd); bb = rotl32(bb, 10);
    dd = sum32(crotl32(dd + _f1(ee,aa,bb) + _X[ 6],  8), cc); aa = rotl32(aa, 10);
    cc = sum32(crotl32(cc + _f1(dd,ee,aa) + _X[ 2], 13), bb); ee = rotl32(ee, 10);
    bb = sum32(crotl32(bb + _f1(cc,dd,ee) + _X[13],  6), aa); dd = rotl32(dd, 10);
    aa = sum32(crotl32(aa + _f1(bb,cc,dd) + _X[14],  5), ee); cc = rotl32(cc, 10);
    ee = sum32(crotl32(ee + _f1(aa,bb,cc) + _X[ 0], 15), dd); bb = rotl32(bb, 10);
    dd = sum32(crotl32(dd + _f1(ee,aa,bb) + _X[ 3], 13), cc); aa = rotl32(aa, 10);
    cc = sum32(crotl32(cc + _f1(dd,ee,aa) + _X[ 9], 11), bb); ee = rotl32(ee, 10);
    bb = sum32(crotl32(bb + _f1(cc,dd,ee) + _X[11], 11), aa); dd = rotl32(dd, 10);

    // do (e, ee) swap as part of assignment.
    _H0 = sum32(_H0, a);
    _H1 = sum32(_H1, b);
    _H2 = sum32(_H2, c);
    _H3 = sum32(_H3, d);
    _H4 = sum32(_H4, ee);
    _H5 = sum32(_H5, aa);
    _H6 = sum32(_H6, bb);
    _H7 = sum32(_H7, cc);
    _H8 = sum32(_H8, dd);
    _H9 = sum32(_H9, e);

    // reset the offset and clean out the word buffer.
    _xOff = 0;
    _X.fillRange(0, _X.length, 0);
  }

  int _f1( int x, int y, int z ) => x ^ y ^ z;

  int _f2( int x, int y, int z ) => (x & y) | (~x & z);

  int _f3( int x, int y, int z ) => (x | ~y) ^ z;

  int _f4( int x, int y, int z ) => (x & z) | (y & ~z);

  int _f5( int x, int y, int z ) => x ^ (y | ~z);

}

