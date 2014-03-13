// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.digests.md4;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/api/ufixnum.dart";
import "package:cipher/digests/md4_family_digest.dart";

/// Implementation of MD4 digest
class MD4Digest extends MD4FamilyDigest implements Digest {

  static const _DIGEST_LENGTH = 16;

  int _H1, _H2, _H3, _H4;
  final _X = new List<int>(16);
  int _xOff = 0;

  MD4Digest() {
    reset();
  }

  final algorithmName = "MD4";
  final digestSize = _DIGEST_LENGTH;

  void reset() {
    super.reset();

    _H1 = 0x67452301;
    _H2 = 0xefcdab89;
    _H3 = 0x98badcfe;
    _H4 = 0x10325476;

    _xOff = 0;
    _X.fillRange(0, _X.length, 0);
  }

  int doFinal(Uint8List out, int outOff) {
    finish();

    pack32(_H1, out, (outOff     ), Endianness.LITTLE_ENDIAN);
    pack32(_H2, out, (outOff +  4), Endianness.LITTLE_ENDIAN);
    pack32(_H3, out, (outOff +  8), Endianness.LITTLE_ENDIAN);
    pack32(_H4, out, (outOff + 12), Endianness.LITTLE_ENDIAN);

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
    var a = _H1;
    var b = _H2;
    var c = _H3;
    var d = _H4;

    // Round 1 - F cycle, 16 times.
    a = crotl32(a + _F(b, c, d) + _X[ 0], _S11);
    d = crotl32(d + _F(a, b, c) + _X[ 1], _S12);
    c = crotl32(c + _F(d, a, b) + _X[ 2], _S13);
    b = crotl32(b + _F(c, d, a) + _X[ 3], _S14);
    a = crotl32(a + _F(b, c, d) + _X[ 4], _S11);
    d = crotl32(d + _F(a, b, c) + _X[ 5], _S12);
    c = crotl32(c + _F(d, a, b) + _X[ 6], _S13);
    b = crotl32(b + _F(c, d, a) + _X[ 7], _S14);
    a = crotl32(a + _F(b, c, d) + _X[ 8], _S11);
    d = crotl32(d + _F(a, b, c) + _X[ 9], _S12);
    c = crotl32(c + _F(d, a, b) + _X[10], _S13);
    b = crotl32(b + _F(c, d, a) + _X[11], _S14);
    a = crotl32(a + _F(b, c, d) + _X[12], _S11);
    d = crotl32(d + _F(a, b, c) + _X[13], _S12);
    c = crotl32(c + _F(d, a, b) + _X[14], _S13);
    b = crotl32(b + _F(c, d, a) + _X[15], _S14);

    // Round 2 - G cycle, 16 times.
    a = crotl32(a + _G(b, c, d) + _X[ 0] + 0x5a827999, _S21);
    d = crotl32(d + _G(a, b, c) + _X[ 4] + 0x5a827999, _S22);
    c = crotl32(c + _G(d, a, b) + _X[ 8] + 0x5a827999, _S23);
    b = crotl32(b + _G(c, d, a) + _X[12] + 0x5a827999, _S24);
    a = crotl32(a + _G(b, c, d) + _X[ 1] + 0x5a827999, _S21);
    d = crotl32(d + _G(a, b, c) + _X[ 5] + 0x5a827999, _S22);
    c = crotl32(c + _G(d, a, b) + _X[ 9] + 0x5a827999, _S23);
    b = crotl32(b + _G(c, d, a) + _X[13] + 0x5a827999, _S24);
    a = crotl32(a + _G(b, c, d) + _X[ 2] + 0x5a827999, _S21);
    d = crotl32(d + _G(a, b, c) + _X[ 6] + 0x5a827999, _S22);
    c = crotl32(c + _G(d, a, b) + _X[10] + 0x5a827999, _S23);
    b = crotl32(b + _G(c, d, a) + _X[14] + 0x5a827999, _S24);
    a = crotl32(a + _G(b, c, d) + _X[ 3] + 0x5a827999, _S21);
    d = crotl32(d + _G(a, b, c) + _X[ 7] + 0x5a827999, _S22);
    c = crotl32(c + _G(d, a, b) + _X[11] + 0x5a827999, _S23);
    b = crotl32(b + _G(c, d, a) + _X[15] + 0x5a827999, _S24);

    // Round 3 - H cycle, 16 times.
    a = crotl32(a + _H(b, c, d) + _X[ 0] + 0x6ed9eba1, _S31);
    d = crotl32(d + _H(a, b, c) + _X[ 8] + 0x6ed9eba1, _S32);
    c = crotl32(c + _H(d, a, b) + _X[ 4] + 0x6ed9eba1, _S33);
    b = crotl32(b + _H(c, d, a) + _X[12] + 0x6ed9eba1, _S34);
    a = crotl32(a + _H(b, c, d) + _X[ 2] + 0x6ed9eba1, _S31);
    d = crotl32(d + _H(a, b, c) + _X[10] + 0x6ed9eba1, _S32);
    c = crotl32(c + _H(d, a, b) + _X[ 6] + 0x6ed9eba1, _S33);
    b = crotl32(b + _H(c, d, a) + _X[14] + 0x6ed9eba1, _S34);
    a = crotl32(a + _H(b, c, d) + _X[ 1] + 0x6ed9eba1, _S31);
    d = crotl32(d + _H(a, b, c) + _X[ 9] + 0x6ed9eba1, _S32);
    c = crotl32(c + _H(d, a, b) + _X[ 5] + 0x6ed9eba1, _S33);
    b = crotl32(b + _H(c, d, a) + _X[13] + 0x6ed9eba1, _S34);
    a = crotl32(a + _H(b, c, d) + _X[ 3] + 0x6ed9eba1, _S31);
    d = crotl32(d + _H(a, b, c) + _X[11] + 0x6ed9eba1, _S32);
    c = crotl32(c + _H(d, a, b) + _X[ 7] + 0x6ed9eba1, _S33);
    b = crotl32(b + _H(c, d, a) + _X[15] + 0x6ed9eba1, _S34);

    _H1 = clip32(_H1 + a);
    _H2 = clip32(_H2 + b);
    _H3 = clip32(_H3 + c);
    _H4 = clip32(_H4 + d);

    // reset the offset and clean out the word buffer.
    _xOff = 0;
    _X.fillRange(0, _X.length, 0);
  }

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

  // F, G and H are the basic MD4 functions.
  int _F(int u, int v, int w) => (u & v) | (not32(u) & w);
  int _G(int u, int v, int w) => (u & v) | (u & w) | (v & w);
  int _H(int u, int v, int w) => u ^ v ^ w;

}



