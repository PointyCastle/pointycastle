// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.digests.sha512;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/digests/long_sha2_family_digest.dart";

/// Implementation of SHA-512 digest.
class SHA512Digest extends LongSHA2FamilyDigest implements Digest {

  static const _DIGEST_LENGTH = 64;

  String get algorithmName => "SHA-512";

  int get digestSize => _DIGEST_LENGTH;

  void reset() {
    super.reset();

    // SHA-512 initial hash value: the first 64 bits of the fractional parts of the square roots of the first eight prime
    // numbers
    H1 = new Uint64(0x6a09e667f3bcc908);
    H2 = new Uint64(0xbb67ae8584caa73b);
    H3 = new Uint64(0x3c6ef372fe94f82b);
    H4 = new Uint64(0xa54ff53a5f1d36f1);
    H5 = new Uint64(0x510e527fade682d1);
    H6 = new Uint64(0x9b05688c2b3e6c1f);
    H7 = new Uint64(0x1f83d9abfb41bd6b);
    H8 = new Uint64(0x5be0cd19137e2179);
  }

  int doFinal( Uint8List out, int outOff ) {
    finish();

    H1.toBigEndian(out, outOff);
    H2.toBigEndian(out, outOff+8);
    H3.toBigEndian(out, outOff+16);
    H4.toBigEndian(out, outOff+24);
    H5.toBigEndian(out, outOff+32);
    H6.toBigEndian(out, outOff+40);
    H7.toBigEndian(out, outOff+48);
    H8.toBigEndian(out, outOff+56);

    reset();

    return _DIGEST_LENGTH;
  }

}



