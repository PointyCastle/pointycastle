// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com  
// Use of this source code is governed by a LGPL v3 license. 
// See the LICENSE file for more information.

library cipher.digests.ripemd160;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/digests/general_digest.dart";

import "package:fixnum/fixnum.dart";

part "../src/digests/ripemd160/functions.dart";

// Useful links:
// http://homes.esat.kuleuven.be/~bosselae/ripemd160.html (description)
// http://homes.esat.kuleuven.be/~bosselae/ripemd/rmd160.txt (pseudocode)

class RIPEMD160Digest extends GeneralDigest implements Digest {

  static const _DIGEST_LENGTH = 20;

  //Int32 _H0, _H1, _H2, _H3, _H4; // IV's
  var _H = new List<Int32>(5);//Uint32List(5);

  var _X = new List<Int32>(16);//new int[16];
  //var _X = new Uint32List(16);
  int _xOff;

  RIPEMD160Digest() {
    reset();
  }

  String get algorithmName => "RIPEMD160";
  int get digestSize => _DIGEST_LENGTH;

  void reset() {
    super.reset();

    _H[0] = new Int32(0x67452301);
    _H[1] = new Int32(0xefcdab89);
    _H[2] = new Int32(0x98badcfe);
    _H[3] = new Int32(0x10325476);
    _H[4] = new Int32(0xc3d2e1f0);

    _xOff = 0;

    for( var i=0 ; i!=_X.length ; i++ ) {
      _X[i] = Int32.ZERO;
    }
  }

  int doFinal( Uint8List out, int outOff ) {
    finish();

    _unpackWord( _H[0], out, outOff );
    _unpackWord( _H[1], out, outOff+4 );
    _unpackWord( _H[2], out, outOff+8 );
    _unpackWord( _H[3], out, outOff+12 );
    _unpackWord( _H[4], out, outOff+16 );

    reset();

    return _DIGEST_LENGTH;
  }

  void processWord( Uint8List inp, int inpOff ) {
    _X[_xOff++] = new Int32(
           inp[inpOff]
        | (inp[inpOff+1] << 8)
        | (inp[inpOff+2] << 16)
        | (inp[inpOff+3] << 24)
    );

    if( _xOff == 16 ) {
      processBlock();
    }
  }

  void processLength( /*long*/ int bitLength ) {
    if( _xOff > 14 ) {
      processBlock();
    }

    var bd = new ByteData.view(new Uint8List(8).buffer);
    bd.setInt64( 0, bitLength, Endianness.BIG_ENDIAN );
    _X[14] = new Int32( bd.getInt32(4) );//new Int32(bitLength & 0xffffffff);
    _X[15] = new Int32( bd.getInt32(0) );//lsr( truncatedBitLength, 32 );
  }

  void processBlock() {
    Int32 a, aa;
    Int32 b, bb;
    Int32 c, cc;
    Int32 d, dd;
    Int32 e, ee;

    a = aa = _H[0];
    b = bb = _H[1];
    c = cc = _H[2];
    d = dd = _H[3];
    e = ee = _H[4];

    //
    // Rounds 1 - 16
    //
    // left
    a = _clsl(a + _f1(b,c,d) + _X[ 0], 11) + e; c = _clsl(c, 10);
    e = _clsl(e + _f1(a,b,c) + _X[ 1], 14) + d; b = _clsl(b, 10);
    d = _clsl(d + _f1(e,a,b) + _X[ 2], 15) + c; a = _clsl(a, 10);
    c = _clsl(c + _f1(d,e,a) + _X[ 3], 12) + b; e = _clsl(e, 10);
    b = _clsl(b + _f1(c,d,e) + _X[ 4],  5) + a; d = _clsl(d, 10);
    a = _clsl(a + _f1(b,c,d) + _X[ 5],  8) + e; c = _clsl(c, 10);
    e = _clsl(e + _f1(a,b,c) + _X[ 6],  7) + d; b = _clsl(b, 10);
    d = _clsl(d + _f1(e,a,b) + _X[ 7],  9) + c; a = _clsl(a, 10);
    c = _clsl(c + _f1(d,e,a) + _X[ 8], 11) + b; e = _clsl(e, 10);
    b = _clsl(b + _f1(c,d,e) + _X[ 9], 13) + a; d = _clsl(d, 10);
    a = _clsl(a + _f1(b,c,d) + _X[10], 14) + e; c = _clsl(c, 10);
    e = _clsl(e + _f1(a,b,c) + _X[11], 15) + d; b = _clsl(b, 10);
    d = _clsl(d + _f1(e,a,b) + _X[12],  6) + c; a = _clsl(a, 10);
    c = _clsl(c + _f1(d,e,a) + _X[13],  7) + b; e = _clsl(e, 10);
    b = _clsl(b + _f1(c,d,e) + _X[14],  9) + a; d = _clsl(d, 10);
    a = _clsl(a + _f1(b,c,d) + _X[15],  8) + e; c = _clsl(c, 10);

    // right
    aa = _clsl(aa + _f5(bb,cc,dd) + _X[ 5] + 0x50a28be6,  8) + ee; cc = _clsl(cc, 10);
    ee = _clsl(ee + _f5(aa,bb,cc) + _X[14] + 0x50a28be6,  9) + dd; bb = _clsl(bb, 10);
    dd = _clsl(dd + _f5(ee,aa,bb) + _X[ 7] + 0x50a28be6,  9) + cc; aa = _clsl(aa, 10);
    cc = _clsl(cc + _f5(dd,ee,aa) + _X[ 0] + 0x50a28be6, 11) + bb; ee = _clsl(ee, 10);
    bb = _clsl(bb + _f5(cc,dd,ee) + _X[ 9] + 0x50a28be6, 13) + aa; dd = _clsl(dd, 10);
    aa = _clsl(aa + _f5(bb,cc,dd) + _X[ 2] + 0x50a28be6, 15) + ee; cc = _clsl(cc, 10);
    ee = _clsl(ee + _f5(aa,bb,cc) + _X[11] + 0x50a28be6, 15) + dd; bb = _clsl(bb, 10);
    dd = _clsl(dd + _f5(ee,aa,bb) + _X[ 4] + 0x50a28be6,  5) + cc; aa = _clsl(aa, 10);
    cc = _clsl(cc + _f5(dd,ee,aa) + _X[13] + 0x50a28be6,  7) + bb; ee = _clsl(ee, 10);
    bb = _clsl(bb + _f5(cc,dd,ee) + _X[ 6] + 0x50a28be6,  7) + aa; dd = _clsl(dd, 10);
    aa = _clsl(aa + _f5(bb,cc,dd) + _X[15] + 0x50a28be6,  8) + ee; cc = _clsl(cc, 10);
    ee = _clsl(ee + _f5(aa,bb,cc) + _X[ 8] + 0x50a28be6, 11) + dd; bb = _clsl(bb, 10);
    dd = _clsl(dd + _f5(ee,aa,bb) + _X[ 1] + 0x50a28be6, 14) + cc; aa = _clsl(aa, 10);
    cc = _clsl(cc + _f5(dd,ee,aa) + _X[10] + 0x50a28be6, 14) + bb; ee = _clsl(ee, 10);
    bb = _clsl(bb + _f5(cc,dd,ee) + _X[ 3] + 0x50a28be6, 12) + aa; dd = _clsl(dd, 10);
    aa = _clsl(aa + _f5(bb,cc,dd) + _X[12] + 0x50a28be6,  6) + ee; cc = _clsl(cc, 10);

    //
    // Rounds 16-31
    //
    // left
    e = _clsl(e + _f2(a,b,c) + _X[ 7] + 0x5a827999,  7) + d; b = _clsl(b, 10);
    d = _clsl(d + _f2(e,a,b) + _X[ 4] + 0x5a827999,  6) + c; a = _clsl(a, 10);
    c = _clsl(c + _f2(d,e,a) + _X[13] + 0x5a827999,  8) + b; e = _clsl(e, 10);
    b = _clsl(b + _f2(c,d,e) + _X[ 1] + 0x5a827999, 13) + a; d = _clsl(d, 10);
    a = _clsl(a + _f2(b,c,d) + _X[10] + 0x5a827999, 11) + e; c = _clsl(c, 10);
    e = _clsl(e + _f2(a,b,c) + _X[ 6] + 0x5a827999,  9) + d; b = _clsl(b, 10);
    d = _clsl(d + _f2(e,a,b) + _X[15] + 0x5a827999,  7) + c; a = _clsl(a, 10);
    c = _clsl(c + _f2(d,e,a) + _X[ 3] + 0x5a827999, 15) + b; e = _clsl(e, 10);
    b = _clsl(b + _f2(c,d,e) + _X[12] + 0x5a827999,  7) + a; d = _clsl(d, 10);
    a = _clsl(a + _f2(b,c,d) + _X[ 0] + 0x5a827999, 12) + e; c = _clsl(c, 10);
    e = _clsl(e + _f2(a,b,c) + _X[ 9] + 0x5a827999, 15) + d; b = _clsl(b, 10);
    d = _clsl(d + _f2(e,a,b) + _X[ 5] + 0x5a827999,  9) + c; a = _clsl(a, 10);
    c = _clsl(c + _f2(d,e,a) + _X[ 2] + 0x5a827999, 11) + b; e = _clsl(e, 10);
    b = _clsl(b + _f2(c,d,e) + _X[14] + 0x5a827999,  7) + a; d = _clsl(d, 10);
    a = _clsl(a + _f2(b,c,d) + _X[11] + 0x5a827999, 13) + e; c = _clsl(c, 10);
    e = _clsl(e + _f2(a,b,c) + _X[ 8] + 0x5a827999, 12) + d; b = _clsl(b, 10);

    // right
    ee = _clsl(ee + _f4(aa,bb,cc) + _X[ 6] + 0x5c4dd124,  9) + dd; bb = _clsl(bb, 10);
    dd = _clsl(dd + _f4(ee,aa,bb) + _X[11] + 0x5c4dd124, 13) + cc; aa = _clsl(aa, 10);
    cc = _clsl(cc + _f4(dd,ee,aa) + _X[ 3] + 0x5c4dd124, 15) + bb; ee = _clsl(ee, 10);
    bb = _clsl(bb + _f4(cc,dd,ee) + _X[ 7] + 0x5c4dd124,  7) + aa; dd = _clsl(dd, 10);
    aa = _clsl(aa + _f4(bb,cc,dd) + _X[ 0] + 0x5c4dd124, 12) + ee; cc = _clsl(cc, 10);
    ee = _clsl(ee + _f4(aa,bb,cc) + _X[13] + 0x5c4dd124,  8) + dd; bb = _clsl(bb, 10);
    dd = _clsl(dd + _f4(ee,aa,bb) + _X[ 5] + 0x5c4dd124,  9) + cc; aa = _clsl(aa, 10);
    cc = _clsl(cc + _f4(dd,ee,aa) + _X[10] + 0x5c4dd124, 11) + bb; ee = _clsl(ee, 10);
    bb = _clsl(bb + _f4(cc,dd,ee) + _X[14] + 0x5c4dd124,  7) + aa; dd = _clsl(dd, 10);
    aa = _clsl(aa + _f4(bb,cc,dd) + _X[15] + 0x5c4dd124,  7) + ee; cc = _clsl(cc, 10);
    ee = _clsl(ee + _f4(aa,bb,cc) + _X[ 8] + 0x5c4dd124, 12) + dd; bb = _clsl(bb, 10);
    dd = _clsl(dd + _f4(ee,aa,bb) + _X[12] + 0x5c4dd124,  7) + cc; aa = _clsl(aa, 10);
    cc = _clsl(cc + _f4(dd,ee,aa) + _X[ 4] + 0x5c4dd124,  6) + bb; ee = _clsl(ee, 10);
    bb = _clsl(bb + _f4(cc,dd,ee) + _X[ 9] + 0x5c4dd124, 15) + aa; dd = _clsl(dd, 10);
    aa = _clsl(aa + _f4(bb,cc,dd) + _X[ 1] + 0x5c4dd124, 13) + ee; cc = _clsl(cc, 10);
    ee = _clsl(ee + _f4(aa,bb,cc) + _X[ 2] + 0x5c4dd124, 11) + dd; bb = _clsl(bb, 10);

    //
    // Rounds 32-47
    //
    // left
    d = _clsl(d + _f3(e,a,b) + _X[ 3] + 0x6ed9eba1, 11) + c; a = _clsl(a, 10);
    c = _clsl(c + _f3(d,e,a) + _X[10] + 0x6ed9eba1, 13) + b; e = _clsl(e, 10);
    b = _clsl(b + _f3(c,d,e) + _X[14] + 0x6ed9eba1,  6) + a; d = _clsl(d, 10);
    a = _clsl(a + _f3(b,c,d) + _X[ 4] + 0x6ed9eba1,  7) + e; c = _clsl(c, 10);
    e = _clsl(e + _f3(a,b,c) + _X[ 9] + 0x6ed9eba1, 14) + d; b = _clsl(b, 10);
    d = _clsl(d + _f3(e,a,b) + _X[15] + 0x6ed9eba1,  9) + c; a = _clsl(a, 10);
    c = _clsl(c + _f3(d,e,a) + _X[ 8] + 0x6ed9eba1, 13) + b; e = _clsl(e, 10);
    b = _clsl(b + _f3(c,d,e) + _X[ 1] + 0x6ed9eba1, 15) + a; d = _clsl(d, 10);
    a = _clsl(a + _f3(b,c,d) + _X[ 2] + 0x6ed9eba1, 14) + e; c = _clsl(c, 10);
    e = _clsl(e + _f3(a,b,c) + _X[ 7] + 0x6ed9eba1,  8) + d; b = _clsl(b, 10);
    d = _clsl(d + _f3(e,a,b) + _X[ 0] + 0x6ed9eba1, 13) + c; a = _clsl(a, 10);
    c = _clsl(c + _f3(d,e,a) + _X[ 6] + 0x6ed9eba1,  6) + b; e = _clsl(e, 10);
    b = _clsl(b + _f3(c,d,e) + _X[13] + 0x6ed9eba1,  5) + a; d = _clsl(d, 10);
    a = _clsl(a + _f3(b,c,d) + _X[11] + 0x6ed9eba1, 12) + e; c = _clsl(c, 10);
    e = _clsl(e + _f3(a,b,c) + _X[ 5] + 0x6ed9eba1,  7) + d; b = _clsl(b, 10);
    d = _clsl(d + _f3(e,a,b) + _X[12] + 0x6ed9eba1,  5) + c; a = _clsl(a, 10);

    // right
    dd = _clsl(dd + _f3(ee,aa,bb) + _X[15] + 0x6d703ef3,  9) + cc; aa = _clsl(aa, 10);
    cc = _clsl(cc + _f3(dd,ee,aa) + _X[ 5] + 0x6d703ef3,  7) + bb; ee = _clsl(ee, 10);
    bb = _clsl(bb + _f3(cc,dd,ee) + _X[ 1] + 0x6d703ef3, 15) + aa; dd = _clsl(dd, 10);
    aa = _clsl(aa + _f3(bb,cc,dd) + _X[ 3] + 0x6d703ef3, 11) + ee; cc = _clsl(cc, 10);
    ee = _clsl(ee + _f3(aa,bb,cc) + _X[ 7] + 0x6d703ef3,  8) + dd; bb = _clsl(bb, 10);
    dd = _clsl(dd + _f3(ee,aa,bb) + _X[14] + 0x6d703ef3,  6) + cc; aa = _clsl(aa, 10);
    cc = _clsl(cc + _f3(dd,ee,aa) + _X[ 6] + 0x6d703ef3,  6) + bb; ee = _clsl(ee, 10);
    bb = _clsl(bb + _f3(cc,dd,ee) + _X[ 9] + 0x6d703ef3, 14) + aa; dd = _clsl(dd, 10);
    aa = _clsl(aa + _f3(bb,cc,dd) + _X[11] + 0x6d703ef3, 12) + ee; cc = _clsl(cc, 10);
    ee = _clsl(ee + _f3(aa,bb,cc) + _X[ 8] + 0x6d703ef3, 13) + dd; bb = _clsl(bb, 10);
    dd = _clsl(dd + _f3(ee,aa,bb) + _X[12] + 0x6d703ef3,  5) + cc; aa = _clsl(aa, 10);
    cc = _clsl(cc + _f3(dd,ee,aa) + _X[ 2] + 0x6d703ef3, 14) + bb; ee = _clsl(ee, 10);
    bb = _clsl(bb + _f3(cc,dd,ee) + _X[10] + 0x6d703ef3, 13) + aa; dd = _clsl(dd, 10);
    aa = _clsl(aa + _f3(bb,cc,dd) + _X[ 0] + 0x6d703ef3, 13) + ee; cc = _clsl(cc, 10);
    ee = _clsl(ee + _f3(aa,bb,cc) + _X[ 4] + 0x6d703ef3,  7) + dd; bb = _clsl(bb, 10);
    dd = _clsl(dd + _f3(ee,aa,bb) + _X[13] + 0x6d703ef3,  5) + cc; aa = _clsl(aa, 10);

    //
    // Rounds 48-63
    //
    // left
    c = _clsl(c + _f4(d,e,a) + _X[ 1] + 0x8f1bbcdc, 11) + b; e = _clsl(e, 10);
    b = _clsl(b + _f4(c,d,e) + _X[ 9] + 0x8f1bbcdc, 12) + a; d = _clsl(d, 10);
    a = _clsl(a + _f4(b,c,d) + _X[11] + 0x8f1bbcdc, 14) + e; c = _clsl(c, 10);
    e = _clsl(e + _f4(a,b,c) + _X[10] + 0x8f1bbcdc, 15) + d; b = _clsl(b, 10);
    d = _clsl(d + _f4(e,a,b) + _X[ 0] + 0x8f1bbcdc, 14) + c; a = _clsl(a, 10);
    c = _clsl(c + _f4(d,e,a) + _X[ 8] + 0x8f1bbcdc, 15) + b; e = _clsl(e, 10);
    b = _clsl(b + _f4(c,d,e) + _X[12] + 0x8f1bbcdc,  9) + a; d = _clsl(d, 10);
    a = _clsl(a + _f4(b,c,d) + _X[ 4] + 0x8f1bbcdc,  8) + e; c = _clsl(c, 10);
    e = _clsl(e + _f4(a,b,c) + _X[13] + 0x8f1bbcdc,  9) + d; b = _clsl(b, 10);
    d = _clsl(d + _f4(e,a,b) + _X[ 3] + 0x8f1bbcdc, 14) + c; a = _clsl(a, 10);
    c = _clsl(c + _f4(d,e,a) + _X[ 7] + 0x8f1bbcdc,  5) + b; e = _clsl(e, 10);
    b = _clsl(b + _f4(c,d,e) + _X[15] + 0x8f1bbcdc,  6) + a; d = _clsl(d, 10);
    a = _clsl(a + _f4(b,c,d) + _X[14] + 0x8f1bbcdc,  8) + e; c = _clsl(c, 10);
    e = _clsl(e + _f4(a,b,c) + _X[ 5] + 0x8f1bbcdc,  6) + d; b = _clsl(b, 10);
    d = _clsl(d + _f4(e,a,b) + _X[ 6] + 0x8f1bbcdc,  5) + c; a = _clsl(a, 10);
    c = _clsl(c + _f4(d,e,a) + _X[ 2] + 0x8f1bbcdc, 12) + b; e = _clsl(e, 10);

    // right
    cc = _clsl(cc + _f2(dd,ee,aa) + _X[ 8] + 0x7a6d76e9, 15) + bb; ee = _clsl(ee, 10);
    bb = _clsl(bb + _f2(cc,dd,ee) + _X[ 6] + 0x7a6d76e9,  5) + aa; dd = _clsl(dd, 10);
    aa = _clsl(aa + _f2(bb,cc,dd) + _X[ 4] + 0x7a6d76e9,  8) + ee; cc = _clsl(cc, 10);
    ee = _clsl(ee + _f2(aa,bb,cc) + _X[ 1] + 0x7a6d76e9, 11) + dd; bb = _clsl(bb, 10);
    dd = _clsl(dd + _f2(ee,aa,bb) + _X[ 3] + 0x7a6d76e9, 14) + cc; aa = _clsl(aa, 10);
    cc = _clsl(cc + _f2(dd,ee,aa) + _X[11] + 0x7a6d76e9, 14) + bb; ee = _clsl(ee, 10);
    bb = _clsl(bb + _f2(cc,dd,ee) + _X[15] + 0x7a6d76e9,  6) + aa; dd = _clsl(dd, 10);
    aa = _clsl(aa + _f2(bb,cc,dd) + _X[ 0] + 0x7a6d76e9, 14) + ee; cc = _clsl(cc, 10);
    ee = _clsl(ee + _f2(aa,bb,cc) + _X[ 5] + 0x7a6d76e9,  6) + dd; bb = _clsl(bb, 10);
    dd = _clsl(dd + _f2(ee,aa,bb) + _X[12] + 0x7a6d76e9,  9) + cc; aa = _clsl(aa, 10);
    cc = _clsl(cc + _f2(dd,ee,aa) + _X[ 2] + 0x7a6d76e9, 12) + bb; ee = _clsl(ee, 10);
    bb = _clsl(bb + _f2(cc,dd,ee) + _X[13] + 0x7a6d76e9,  9) + aa; dd = _clsl(dd, 10);
    aa = _clsl(aa + _f2(bb,cc,dd) + _X[ 9] + 0x7a6d76e9, 12) + ee; cc = _clsl(cc, 10);
    ee = _clsl(ee + _f2(aa,bb,cc) + _X[ 7] + 0x7a6d76e9,  5) + dd; bb = _clsl(bb, 10);
    dd = _clsl(dd + _f2(ee,aa,bb) + _X[10] + 0x7a6d76e9, 15) + cc; aa = _clsl(aa, 10);
    cc = _clsl(cc + _f2(dd,ee,aa) + _X[14] + 0x7a6d76e9,  8) + bb; ee = _clsl(ee, 10);

    //
    // Rounds 64-79
    //
    // left
    b = _clsl(b + _f5(c,d,e) + _X[ 4] + 0xa953fd4e,  9) + a; d = _clsl(d, 10);
    a = _clsl(a + _f5(b,c,d) + _X[ 0] + 0xa953fd4e, 15) + e; c = _clsl(c, 10);
    e = _clsl(e + _f5(a,b,c) + _X[ 5] + 0xa953fd4e,  5) + d; b = _clsl(b, 10);
    d = _clsl(d + _f5(e,a,b) + _X[ 9] + 0xa953fd4e, 11) + c; a = _clsl(a, 10);
    c = _clsl(c + _f5(d,e,a) + _X[ 7] + 0xa953fd4e,  6) + b; e = _clsl(e, 10);
    b = _clsl(b + _f5(c,d,e) + _X[12] + 0xa953fd4e,  8) + a; d = _clsl(d, 10);
    a = _clsl(a + _f5(b,c,d) + _X[ 2] + 0xa953fd4e, 13) + e; c = _clsl(c, 10);
    e = _clsl(e + _f5(a,b,c) + _X[10] + 0xa953fd4e, 12) + d; b = _clsl(b, 10);
    d = _clsl(d + _f5(e,a,b) + _X[14] + 0xa953fd4e,  5) + c; a = _clsl(a, 10);
    c = _clsl(c + _f5(d,e,a) + _X[ 1] + 0xa953fd4e, 12) + b; e = _clsl(e, 10);
    b = _clsl(b + _f5(c,d,e) + _X[ 3] + 0xa953fd4e, 13) + a; d = _clsl(d, 10);
    a = _clsl(a + _f5(b,c,d) + _X[ 8] + 0xa953fd4e, 14) + e; c = _clsl(c, 10);
    e = _clsl(e + _f5(a,b,c) + _X[11] + 0xa953fd4e, 11) + d; b = _clsl(b, 10);
    d = _clsl(d + _f5(e,a,b) + _X[ 6] + 0xa953fd4e,  8) + c; a = _clsl(a, 10);
    c = _clsl(c + _f5(d,e,a) + _X[15] + 0xa953fd4e,  5) + b; e = _clsl(e, 10);
    b = _clsl(b + _f5(c,d,e) + _X[13] + 0xa953fd4e,  6) + a; d = _clsl(d, 10);

    // right
    bb = _clsl(bb + _f1(cc,dd,ee) + _X[12],  8) + aa; dd = _clsl(dd, 10);
    aa = _clsl(aa + _f1(bb,cc,dd) + _X[15],  5) + ee; cc = _clsl(cc, 10);
    ee = _clsl(ee + _f1(aa,bb,cc) + _X[10], 12) + dd; bb = _clsl(bb, 10);
    dd = _clsl(dd + _f1(ee,aa,bb) + _X[ 4],  9) + cc; aa = _clsl(aa, 10);
    cc = _clsl(cc + _f1(dd,ee,aa) + _X[ 1], 12) + bb; ee = _clsl(ee, 10);
    bb = _clsl(bb + _f1(cc,dd,ee) + _X[ 5],  5) + aa; dd = _clsl(dd, 10);
    aa = _clsl(aa + _f1(bb,cc,dd) + _X[ 8], 14) + ee; cc = _clsl(cc, 10);
    ee = _clsl(ee + _f1(aa,bb,cc) + _X[ 7],  6) + dd; bb = _clsl(bb, 10);
    dd = _clsl(dd + _f1(ee,aa,bb) + _X[ 6],  8) + cc; aa = _clsl(aa, 10);
    cc = _clsl(cc + _f1(dd,ee,aa) + _X[ 2], 13) + bb; ee = _clsl(ee, 10);
    bb = _clsl(bb + _f1(cc,dd,ee) + _X[13],  6) + aa; dd = _clsl(dd, 10);
    aa = _clsl(aa + _f1(bb,cc,dd) + _X[14],  5) + ee; cc = _clsl(cc, 10);
    ee = _clsl(ee + _f1(aa,bb,cc) + _X[ 0], 15) + dd; bb = _clsl(bb, 10);
    dd = _clsl(dd + _f1(ee,aa,bb) + _X[ 3], 13) + cc; aa = _clsl(aa, 10);
    cc = _clsl(cc + _f1(dd,ee,aa) + _X[ 9], 11) + bb; ee = _clsl(ee, 10);
    bb = _clsl(bb + _f1(cc,dd,ee) + _X[11], 11) + aa; dd = _clsl(dd, 10);

    dd += c + _H[1];
    _H[1] = _H[2] + d + ee;
    _H[2] = _H[3] + e + aa;
    _H[3] = _H[4] + a + bb;
    _H[4] = _H[0] + b + cc;
    _H[0] = dd;

    //
    // reset the offset and clean out the word buffer.
    //
    _xOff = 0;
    for (int i = 0; i != _X.length; i++)
    {
      _X[i] = Int32.ZERO;
    }
  }

  void _unpackWord( Int32 word, Uint8List out, int outOff ) {
    out[outOff]   = word.toInt();
    out[outOff+1] = _lsr( word, 8 ).toInt();
    out[outOff+2] = _lsr( word, 16 ).toInt();
    out[outOff+3] = _lsr( word, 24 ).toInt();
  }

}



