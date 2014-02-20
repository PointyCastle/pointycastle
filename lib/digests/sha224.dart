// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.digests.sha224;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/api/ufixnum.dart";
import "package:cipher/digests/md4_family_digest.dart";

/// Implementation of SHA-224 digest.
class SHA224Digest extends MD4FamilyDigest implements Digest {

  static const _DIGEST_LENGTH = 28;

  Uint32 _H1, _H2, _H3, _H4, _H5, _H6, _H7, _H8;

  final _X = new List<Uint32>(64);
  int _xOff;

  SHA224Digest() {
    reset();
  }

  String get algorithmName => "SHA-224";

  int get digestSize => _DIGEST_LENGTH;

  void reset() {
    super.reset();

    _H1 = new Uint32(0xc1059ed8);
    _H2 = new Uint32(0x367cd507);
    _H3 = new Uint32(0x3070dd17);
    _H4 = new Uint32(0xf70e5939);
    _H5 = new Uint32(0xffc00b31);
    _H6 = new Uint32(0x68581511);
    _H7 = new Uint32(0x64f98fa7);
    _H8 = new Uint32(0xbefa4fa4);

    _xOff = 0;
    _X.fillRange( 0, _X.length, new Uint32(0) );
  }

  int doFinal( Uint8List out, int outOff ) {
    finish();

    _H1.toBigEndian(out, outOff);
    _H2.toBigEndian(out, outOff+4);
    _H3.toBigEndian(out, outOff+8);
    _H4.toBigEndian(out, outOff+12);
    _H5.toBigEndian(out, outOff+16);
    _H6.toBigEndian(out, outOff+20);
    _H7.toBigEndian(out, outOff+24);

    reset();

    return _DIGEST_LENGTH;
  }

  void processWord( Uint8List inp, int inpOff ) {
    _X[_xOff] = new Uint32.fromBigEndian( inp, inpOff );

    if( ++_xOff == 16 ) {
      processBlock();
    }
  }

  void processLength( Uint64 bitLength ) {
    if( _xOff > 14 ) {
      processBlock();
    }

    packLittleEndianLength( bitLength, _X, 14 );
  }

  void processBlock() {
    // expand 16 word block into 64 word blocks.
    for (var t = 16; t <= 63; t++)
    {
      _X[t] = Theta1(_X[t - 2]) + _X[t - 7] + Theta0(_X[t - 15]) + _X[t - 16];
    }

    // set up working variables.
    var a = _H1;
    var b = _H2;
    var c = _H3;
    var d = _H4;
    var e = _H5;
    var f = _H6;
    var g = _H7;
    var h = _H8;


    var t = 0;
    for(var i = 0; i < 8; i ++) {
      // t = 8 * i
      h += Sum1(e) + Ch(e, f, g) + K[t] + _X[t];
      d += h;
      h += Sum0(a) + Maj(a, b, c);
      ++t;

      // t = 8 * i + 1
      g += Sum1(d) + Ch(d, e, f) + K[t] + _X[t];
      c += g;
      g += Sum0(h) + Maj(h, a, b);
      ++t;

      // t = 8 * i + 2
      f += Sum1(c) + Ch(c, d, e) + K[t] + _X[t];
      b += f;
      f += Sum0(g) + Maj(g, h, a);
      ++t;

      // t = 8 * i + 3
      e += Sum1(b) + Ch(b, c, d) + K[t] + _X[t];
      a += e;
      e += Sum0(f) + Maj(f, g, h);
      ++t;

      // t = 8 * i + 4
      d += Sum1(a) + Ch(a, b, c) + K[t] + _X[t];
      h += d;
      d += Sum0(e) + Maj(e, f, g);
      ++t;

      // t = 8 * i + 5
      c += Sum1(h) + Ch(h, a, b) + K[t] + _X[t];
      g += c;
      c += Sum0(d) + Maj(d, e, f);
      ++t;

      // t = 8 * i + 6
      b += Sum1(g) + Ch(g, h, a) + K[t] + _X[t];
      f += b;
      b += Sum0(c) + Maj(c, d, e);
      ++t;

      // t = 8 * i + 7
      a += Sum1(f) + Ch(f, g, h) + K[t] + _X[t];
      e += a;
      a += Sum0(b) + Maj(b, c, d);
      ++t;
    }

    _H1 += a;
    _H2 += b;
    _H3 += c;
    _H4 += d;
    _H5 += e;
    _H6 += f;
    _H7 += g;
    _H8 += h;

    // reset the offset and clean out the word buffer.
    _xOff = 0;
    _X.fillRange(0, 16, new Uint32(0));
  }

  // SHA-224 functions
  Uint32 Ch( Uint32 x, Uint32 y, Uint32 z ) => ((x & y) ^ ((~x) & z));

  Uint32 Maj( Uint32 x, Uint32 y, Uint32 z ) => ((x & y) ^ (x & z) ^ (y & z));

  Uint32 Sum0( Uint32 x ) => ((x >> 2) | (x << 30)) ^ ((x >> 13) | (x << 19)) ^ ((x >> 22) | (x << 10));

  Uint32 Sum1( Uint32 x ) => ((x >> 6) | (x << 26)) ^ ((x >> 11) | (x << 21)) ^ ((x >> 25) | (x << 7));

  Uint32 Theta0( Uint32 x ) => ((x >> 7) | (x << 25)) ^ ((x >> 18) | (x << 14)) ^ (x >> 3);

  Uint32 Theta1( Uint32 x ) => ((x >> 17) | (x << 15)) ^ ((x >> 19) | (x << 13)) ^ (x >> 10);

  /**
   * SHA-224 Constants (represent the first 32 bits of the fractional parts of the cube roots of the first sixty-four prime
   * numbers)
   */
  static final K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

}



