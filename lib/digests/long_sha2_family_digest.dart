// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.digests.long_sha2_family_digest;

import "dart:typed_data";

import "package:cipher/api/ufixnum.dart";
import "package:cipher/digests/base_digest.dart";

/// Base implementation of SHA-2 family algorithms SHA-384 and SHA-512.
abstract class LongSHA2FamilyDigest extends BaseDigest {

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
    _byteCount1 = new Uint64(0,0);
    _byteCount2 = new Uint64(0,0);

    _xBufOff = 0;
    for (var i = 0; i < _xBuf.length ; i++) {
      _xBuf[i] = 0;
    }

    _wOff = 0;
    for (var i = 0; i != _W.length; i++) {
      _W[i] = new Uint64(0,0);
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

  static final _MAX_BYTE_COUNT1 = new Uint64(0x1fffffff,0xffffffff);

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
    if (_byteCount1 > _MAX_BYTE_COUNT1) {
      _byteCount2 += (_byteCount1 >> 61);
      _byteCount1 &= _MAX_BYTE_COUNT1;
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
    _W.fillRange(0, 16, new Uint64(0,0) );
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
  static final List<Uint64> _K = [
    new Uint64(0x428a2f98,0xd728ae22), new Uint64(0x71374491,0x23ef65cd), new Uint64(0xb5c0fbcf,0xec4d3b2f), new Uint64(0xe9b5dba5,0x8189dbbc),
    new Uint64(0x3956c25b,0xf348b538), new Uint64(0x59f111f1,0xb605d019), new Uint64(0x923f82a4,0xaf194f9b), new Uint64(0xab1c5ed5,0xda6d8118),
    new Uint64(0xd807aa98,0xa3030242), new Uint64(0x12835b01,0x45706fbe), new Uint64(0x243185be,0x4ee4b28c), new Uint64(0x550c7dc3,0xd5ffb4e2),
    new Uint64(0x72be5d74,0xf27b896f), new Uint64(0x80deb1fe,0x3b1696b1), new Uint64(0x9bdc06a7,0x25c71235), new Uint64(0xc19bf174,0xcf692694),
    new Uint64(0xe49b69c1,0x9ef14ad2), new Uint64(0xefbe4786,0x384f25e3), new Uint64(0x0fc19dc6,0x8b8cd5b5), new Uint64(0x240ca1cc,0x77ac9c65),
    new Uint64(0x2de92c6f,0x592b0275), new Uint64(0x4a7484aa,0x6ea6e483), new Uint64(0x5cb0a9dc,0xbd41fbd4), new Uint64(0x76f988da,0x831153b5),
    new Uint64(0x983e5152,0xee66dfab), new Uint64(0xa831c66d,0x2db43210), new Uint64(0xb00327c8,0x98fb213f), new Uint64(0xbf597fc7,0xbeef0ee4),
    new Uint64(0xc6e00bf3,0x3da88fc2), new Uint64(0xd5a79147,0x930aa725), new Uint64(0x06ca6351,0xe003826f), new Uint64(0x14292967,0x0a0e6e70),
    new Uint64(0x27b70a85,0x46d22ffc), new Uint64(0x2e1b2138,0x5c26c926), new Uint64(0x4d2c6dfc,0x5ac42aed), new Uint64(0x53380d13,0x9d95b3df),
    new Uint64(0x650a7354,0x8baf63de), new Uint64(0x766a0abb,0x3c77b2a8), new Uint64(0x81c2c92e,0x47edaee6), new Uint64(0x92722c85,0x1482353b),
    new Uint64(0xa2bfe8a1,0x4cf10364), new Uint64(0xa81a664b,0xbc423001), new Uint64(0xc24b8b70,0xd0f89791), new Uint64(0xc76c51a3,0x0654be30),
    new Uint64(0xd192e819,0xd6ef5218), new Uint64(0xd6990624,0x5565a910), new Uint64(0xf40e3585,0x5771202a), new Uint64(0x106aa070,0x32bbd1b8),
    new Uint64(0x19a4c116,0xb8d2d0c8), new Uint64(0x1e376c08,0x5141ab53), new Uint64(0x2748774c,0xdf8eeb99), new Uint64(0x34b0bcb5,0xe19b48a8),
    new Uint64(0x391c0cb3,0xc5c95a63), new Uint64(0x4ed8aa4a,0xe3418acb), new Uint64(0x5b9cca4f,0x7763e373), new Uint64(0x682e6ff3,0xd6b2b8a3),
    new Uint64(0x748f82ee,0x5defb2fc), new Uint64(0x78a5636f,0x43172f60), new Uint64(0x84c87814,0xa1f0ab72), new Uint64(0x8cc70208,0x1a6439ec),
    new Uint64(0x90befffa,0x23631e28), new Uint64(0xa4506ceb,0xde82bde9), new Uint64(0xbef9a3f7,0xb2c67915), new Uint64(0xc67178f2,0xe372532b),
    new Uint64(0xca273ece,0xea26619c), new Uint64(0xd186b8c7,0x21c0c207), new Uint64(0xeada7dd6,0xcde0eb1e), new Uint64(0xf57d4f7f,0xee6ed178),
    new Uint64(0x06f067aa,0x72176fba), new Uint64(0x0a637dc5,0xa2c898a6), new Uint64(0x113f9804,0xbef90dae), new Uint64(0x1b710b35,0x131c471b),
    new Uint64(0x28db77f5,0x23047d84), new Uint64(0x32caab7b,0x40c72493), new Uint64(0x3c9ebe0a,0x15c9bebc), new Uint64(0x431d67c4,0x9c100d4c),
    new Uint64(0x4cc5d4be,0xcb3e42b6), new Uint64(0x597f299c,0xfc657e2a), new Uint64(0x5fcb6fab,0x3ad6faec), new Uint64(0x6c44198c,0x4a475817)
  ];

}