// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.digests.sha1;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/api/ufixnum.dart";
import "package:cipher/digests/md4_family_digest.dart";

/// Implementation of SHA-1 digest
class SHA1Digest extends MD4FamilyDigest implements Digest {

  static const _DIGEST_LENGTH = 20;

  int _H1, _H2, _H3, _H4, _H5;
  final _X = new List<int>(80);
  int _xOff;

  SHA1Digest() {
    reset();
  }

  final algorithmName = "SHA-1";
  final digestSize = _DIGEST_LENGTH;

  void reset() {
    super.reset();

    _H1 = 0x67452301;
    _H2 = 0xefcdab89;
    _H3 = 0x98badcfe;
    _H4 = 0x10325476;
    _H5 = 0xc3d2e1f0;

    _xOff = 0;
    _X.fillRange(0, _X.length, 0);
  }

  int doFinal(Uint8List out, int outOff) {
    finish();

    pack32(_H1, out, (outOff     ), Endianness.BIG_ENDIAN);
    pack32(_H2, out, (outOff +  4), Endianness.BIG_ENDIAN);
    pack32(_H3, out, (outOff +  8), Endianness.BIG_ENDIAN);
    pack32(_H4, out, (outOff + 12), Endianness.BIG_ENDIAN);
    pack32(_H5, out, (outOff + 16), Endianness.BIG_ENDIAN);

    reset();

    return _DIGEST_LENGTH;
  }

  void processWord(Uint8List inp, int inpOff) {
    _X[_xOff++] = unpack32(inp, inpOff, Endianness.BIG_ENDIAN);

    if (_xOff == 16) {
      processBlock();
    }
  }

  void processLength(Register64 bitLength) {
    if (_xOff > 14) {
      processBlock();
    }

    packLittleEndianLength(bitLength, _X, 14);
  }

  void processBlock() {
    // expand 16 word block into 80 word block.
    for (var i = 16; i < 80; i++) {
      var t = _X[i - 3] ^ _X[i - 8] ^ _X[i - 14] ^ _X[i - 16];
      _X[i] = rotl32(t, 1);
    }

    // set up working variables.
    var A = _H1;
    var B = _H2;
    var C = _H3;
    var D = _H4;
    var E = _H5;

    var idx = 0;

    // round 1
    for (var j = 0; j < 4; j++) {
      E = clip32(E + rotl32(A, 5) + _f(B, C, D) + _X[idx++] + Y1);
      B = rotl32(B, 30);

      D = clip32(D + rotl32(E, 5) + _f(A, B, C) + _X[idx++] + Y1);
      A = rotl32(A, 30);

      C = clip32(C + rotl32(D, 5) + _f(E, A, B) + _X[idx++] + Y1);
      E = rotl32(E, 30);

      B = clip32(B + rotl32(C, 5) + _f(D, E, A) + _X[idx++] + Y1);
      D = rotl32(D, 30);

      A = clip32(A + rotl32(B, 5) + _f(C, D, E) + _X[idx++] + Y1);
      C = rotl32(C, 30);
    }

    // round 2
    for (var j = 0; j < 4; j++) {
      E = clip32(E + rotl32(A, 5) + _h(B, C, D) + _X[idx++] + Y2);
      B = rotl32(B, 30);

      D = clip32(D + rotl32(E, 5) + _h(A, B, C) + _X[idx++] + Y2);
      A = rotl32(A, 30);

      C = clip32(C + rotl32(D, 5) + _h(E, A, B) + _X[idx++] + Y2);
      E = rotl32(E, 30);

      B = clip32(B + rotl32(C, 5) + _h(D, E, A) + _X[idx++] + Y2);
      D = rotl32(D, 30);

      A = clip32(A + rotl32(B, 5) + _h(C, D, E) + _X[idx++] + Y2);
      C = rotl32(C, 30);
    }

    // round 3
    for (var j = 0; j < 4; j++) {
      E = clip32(E + rotl32(A, 5) + _g(B, C, D) + _X[idx++] + Y3);
      B = rotl32(B, 30);

      D = clip32(D + rotl32(E, 5) + _g(A, B, C) + _X[idx++] + Y3);
      A = rotl32(A, 30);

      C = clip32(C + rotl32(D, 5) + _g(E, A, B) + _X[idx++] + Y3);
      E = rotl32(E, 30);

      B = clip32(B + rotl32(C, 5) + _g(D, E, A) + _X[idx++] + Y3);
      D = rotl32(D, 30);

      A = clip32(A + rotl32(B, 5) + _g(C, D, E) + _X[idx++] + Y3);
      C = rotl32(C, 30);
    }

    // round 4
    for (var j = 0; j < 4; j++) {
      E = clip32(E + rotl32(A, 5) + _h(B, C, D) + _X[idx++] + Y4);
      B = rotl32(B, 30);

      D = clip32(D + rotl32(E, 5) + _h(A, B, C) + _X[idx++] + Y4);
      A = rotl32(A, 30);

      C = clip32(C + rotl32(D, 5) + _h(E, A, B) + _X[idx++] + Y4);
      E = rotl32(E, 30);

      B = clip32(B + rotl32(C, 5) + _h(D, E, A) + _X[idx++] + Y4);
      D = rotl32(D, 30);

      A = clip32(A + rotl32(B, 5) + _h(C, D, E) + _X[idx++] + Y4);
      C = rotl32(C, 30);
    }

    _H1 = clip32(_H1 + A);
    _H2 = clip32(_H2 + B);
    _H3 = clip32(_H3 + C);
    _H4 = clip32(_H4 + D);
    _H5 = clip32(_H5 + E);

    // reset start of the buffer.
    _xOff = 0;
    _X.fillRange(0, 16, 0);
  }

  // Additive constants
  static final Y1 = 0x5a827999;
  static final Y2 = 0x6ed9eba1;
  static final Y3 = 0x8f1bbcdc;
  static final Y4 = 0xca62c1d6;

  int _f(int u, int v, int w) => ((u & v) | ((~u) & w));

  int _h(int u, int v, int w) => (u ^ v ^ w);

  int _g(int u, int v, int w) => ((u & v) | (u & w) | (v & w));

}



