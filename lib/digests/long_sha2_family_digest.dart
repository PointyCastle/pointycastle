// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.digests.long_sha2_family_digest;

import "dart:typed_data";

import "package:cipher/api.dart";

/// Base implementation of SHA-2 family algorithms SHA-384 and SHA-512.
abstract class LongSHA2FamilyDigest implements Digest {

  static const _BYTE_LENGTH = 128;

  Uint8List _xBuf;
  int _xBufOff;

  Uint64 _byteCount1;
  Uint64 _byteCount2;

  Uint64 H1, H2, H3, H4, H5, H6, H7, H8;

  final _W = new List<Uint64>(80);
  int _wOff;

  LongSHA2FamilyDigest() {
    _xBuf = new Uint8List(8);
    _xBufOff = 0;

    reset();
  }

  int get byteLength => _BYTE_LENGTH;

  void reset() {
    _byteCount1 = new Uint64(0);
    _byteCount2 = new Uint64(0);

    _xBufOff = 0;
    for (var i = 0; i < _xBuf.length ; i++) {
      _xBuf[i] = 0;
    }

    _wOff = 0;
    for (var i = 0; i != _W.length; i++) {
      _W[i] = new Uint64(0);
    }
  }

  void updateByte(int inp) {
    _xBuf[_xBufOff++] = inp;

    if( _xBufOff == _xBuf.length ) {
      _processWord(_xBuf, 0);
      _xBufOff = 0;
    }

    _byteCount1++;
  }

  void update( Uint8List inp, int inpOff, int len ) {
    // fill the current word
    while( (_xBufOff != 0) && (len > 0) ) {
      updateByte(inp[inpOff]);

      inpOff++;
      len--;
    }

    // process whole words.
    while( len > _xBuf.length ) {
      _processWord(inp, inpOff);

      inpOff += _xBuf.length;
      len -= _xBuf.length;
      _byteCount1 += _xBuf.length;
    }

    // load in the remainder.
    while (len > 0) {
      updateByte(inp[inpOff]);

      inpOff++;
      len--;
    }
  }

  void finish() {
    _adjustByteCounts();

    var lowBitLength = _byteCount1 << 3;
    var hiBitLength = _byteCount2;

    // add the pad bytes.
    updateByte(128);

    while( _xBufOff != 0 ) {
      updateByte(0);
    }

    _processLength(lowBitLength, hiBitLength);

    _processBlock();
  }

  void _processWord( Uint8List inp, int inpOff ) {
    _W[_wOff] = new Uint64.fromBigEndian(inp, inpOff);

    if (++_wOff == 16) {
      _processBlock();
    }
  }

  /**
   * adjust the byte counts so that byteCount2 represents the
   * upper long (less 3 bits) word of the byte count.
   */
  void _adjustByteCounts() {
    if (_byteCount1 > 0x1fffffffffffffff) {
      _byteCount2 += (_byteCount1 >> 61);
      _byteCount1 &= 0x1fffffffffffffff;
    }
  }

  void _processLength( Uint64 lowW, Uint64 hiW ) {
    if (_wOff > 14) {
      _processBlock();
    }

    _W[14] = hiW;
    _W[15] = lowW;
  }

  void _processBlock() {
    _adjustByteCounts();

    // expand 16 word block into 80 word blocks.
    for (var t = 16; t <= 79; t++) {
      _W[t] = _Sigma1(_W[t - 2]) + _W[t - 7] + _Sigma0(_W[t - 15]) + _W[t - 16];
    }

    //
    // set up working variables.
    //
    var a = H1;
    var b = H2;
    var c = H3;
    var d = H4;
    var e = H5;
    var f = H6;
    var g = H7;
    var h = H8;

    var t = 0;
    for(var i = 0; i < 10; i ++) {
      // t = 8 * i
      h += _Sum1(e) + _Ch(e, f, g) + _K[t] + _W[t++];
      d += h;
      h += _Sum0(a) + _Maj(a, b, c);

      // t = 8 * i + 1
      g += _Sum1(d) + _Ch(d, e, f) + _K[t] + _W[t++];
      c += g;
      g += _Sum0(h) + _Maj(h, a, b);

      // t = 8 * i + 2
      f += _Sum1(c) + _Ch(c, d, e) + _K[t] + _W[t++];
      b += f;
      f += _Sum0(g) + _Maj(g, h, a);

      // t = 8 * i + 3
      e += _Sum1(b) + _Ch(b, c, d) + _K[t] + _W[t++];
      a += e;
      e += _Sum0(f) + _Maj(f, g, h);

      // t = 8 * i + 4
      d += _Sum1(a) + _Ch(a, b, c) + _K[t] + _W[t++];
      h += d;
      d += _Sum0(e) + _Maj(e, f, g);

      // t = 8 * i + 5
      c += _Sum1(h) + _Ch(h, a, b) + _K[t] + _W[t++];
      g += c;
      c += _Sum0(d) + _Maj(d, e, f);

      // t = 8 * i + 6
      b += _Sum1(g) + _Ch(g, h, a) + _K[t] + _W[t++];
      f += b;
      b += _Sum0(c) + _Maj(c, d, e);

      // t = 8 * i + 7
      a += _Sum1(f) + _Ch(f, g, h) + _K[t] + _W[t++];
      e += a;
      a += _Sum0(b) + _Maj(b, c, d);
    }

    H1 += a;
    H2 += b;
    H3 += c;
    H4 += d;
    H5 += e;
    H6 += f;
    H7 += g;
    H8 += h;

    // reset the offset and clean out the word buffer.
    _wOff = 0;
    _W.fillRange(0, 16, new Uint64(0) );
  }

  // SHA-384 and SHA-512 functions (as for SHA-256 but for longs)
  Uint64 _Ch(Uint64 x, Uint64 y, Uint64 z) => ((x & y) ^ ((~x) & z));

  Uint64 _Maj(Uint64 x, Uint64 y, Uint64 z) => ((x & y) ^ (x & z) ^ (y & z));

  Uint64 _Sum0(Uint64 x) => ((x << 36)|(x >> 28)) ^ ((x << 30)|(x >> 34)) ^ ((x << 25)|(x >> 39));

  Uint64 _Sum1(Uint64 x) => ((x << 50)|(x >> 14)) ^ ((x << 46)|(x >> 18)) ^ ((x << 23)|(x >> 41));

  Uint64 _Sigma0(Uint64 x) => ((x << 63)|(x >> 1)) ^ ((x << 56)|(x >> 8)) ^ (x >> 7);

  Uint64 _Sigma1(Uint64 x) => ((x << 45)|(x >> 19)) ^ ((x << 3)|(x >> 61)) ^ (x >> 6);

  /**
   * SHA-384 and SHA-512 Constants: represent the first 64 bits of the fractional parts of the cube roots of the first
   * sixty-four prime numbers)
   */
  static final _K = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
  ];

}