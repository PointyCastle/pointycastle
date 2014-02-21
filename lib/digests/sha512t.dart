// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.digests.sha512t;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/api/ufixnum.dart";
import "package:cipher/digests/long_sha2_family_digest.dart";

/// Implementation of SHA-512/t digest (see FIPS 180-4).
class SHA512tDigest extends LongSHA2FamilyDigest implements Digest {

  final int digestSize;

  Uint64 _H1t, _H2t, _H3t, _H4t, _H5t, _H6t, _H7t, _H8t;

  SHA512tDigest(this.digestSize) {
    if( digestSize >= 64 ) {
      throw new ArgumentError("Digest size cannot be >= 64 bytes (512 bits)");
    }
    if( digestSize == 48 ) {
      throw new ArgumentError("Digest size cannot be 48 bytes (384 bits): use SHA-384 instead");
    }

    tIvGenerate(digestSize * 8);

    reset();
  }

  String get algorithmName => "SHA-512/${digestSize*8}";

  void reset() {
    super.reset();

    // initial hash values use the iv generation algorithm for t.
    H1 = _H1t;
    H2 = _H2t;
    H3 = _H3t;
    H4 = _H4t;
    H5 = _H5t;
    H6 = _H6t;
    H7 = _H7t;
    H8 = _H8t;
  }

  int doFinal(Uint8List out, int outOff) {
    finish();

    var tmp = new Uint8List(64);

    H1.toBigEndian(tmp, 0);
    H2.toBigEndian(tmp, 8);
    H3.toBigEndian(tmp, 16);
    H4.toBigEndian(tmp, 24);
    H5.toBigEndian(tmp, 32);
    H6.toBigEndian(tmp, 40);
    H7.toBigEndian(tmp, 48);
    H8.toBigEndian(tmp, 56);

    out.setRange( outOff, outOff+digestSize, tmp );

    reset();

    return digestSize;
  }

  final Uint64 _H_MASK = new Uint64(0xa5a5a5a5, 0xa5a5a5a5);

  void tIvGenerate(int bitLength) {
    H1 = (new Uint64(0x6a09e667,0xf3bcc908) ^ _H_MASK);
    H2 = (new Uint64(0xbb67ae85,0x84caa73b) ^ _H_MASK);
    H3 = (new Uint64(0x3c6ef372,0xfe94f82b) ^ _H_MASK);
    H4 = (new Uint64(0xa54ff53a,0x5f1d36f1) ^ _H_MASK);
    H5 = (new Uint64(0x510e527f,0xade682d1) ^ _H_MASK);
    H6 = (new Uint64(0x9b05688c,0x2b3e6c1f) ^ _H_MASK);
    H7 = (new Uint64(0x1f83d9ab,0xfb41bd6b) ^ _H_MASK);
    H8 = (new Uint64(0x5be0cd19,0x137e2179) ^ _H_MASK);

    updateByte(0x53);
    updateByte(0x48);
    updateByte(0x41);
    updateByte(0x2D);
    updateByte(0x35);
    updateByte(0x31);
    updateByte(0x32);
    updateByte(0x2F);

    if( bitLength > 100 ) {
      updateByte(bitLength ~/ 100 + 0x30);
      bitLength = bitLength % 100;
      updateByte(bitLength ~/ 10 + 0x30);
      bitLength = bitLength % 10;
      updateByte(bitLength + 0x30);
    }
    else if( bitLength > 10 ) {
      updateByte(bitLength ~/ 10 + 0x30);
      bitLength = bitLength % 10;
      updateByte(bitLength + 0x30);
    }
    else {
      updateByte(bitLength + 0x30);
    }

    finish();

    _H1t = H1;
    _H2t = H2;
    _H3t = H3;
    _H4t = H4;
    _H5t = H5;
    _H6t = H6;
    _H7t = H7;
    _H8t = H8;
  }

}



