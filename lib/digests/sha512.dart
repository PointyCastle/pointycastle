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

  SHA512Digest() {
    reset();
  }

  final algorithmName = "SHA-512";
  final digestSize = _DIGEST_LENGTH;

  void reset() {
    super.reset();

    H1.set(0x6a09e667, 0xf3bcc908);
    H2.set(0xbb67ae85, 0x84caa73b);
    H3.set(0x3c6ef372, 0xfe94f82b);
    H4.set(0xa54ff53a, 0x5f1d36f1);
    H5.set(0x510e527f, 0xade682d1);
    H6.set(0x9b05688c, 0x2b3e6c1f);
    H7.set(0x1f83d9ab, 0xfb41bd6b);
    H8.set(0x5be0cd19, 0x137e2179);
  }

  int doFinal( Uint8List out, int outOff ) {
    finish();

    H1.pack(out, outOff     , Endianness.BIG_ENDIAN);
    H2.pack(out, outOff +  8, Endianness.BIG_ENDIAN);
    H3.pack(out, outOff + 16, Endianness.BIG_ENDIAN);
    H4.pack(out, outOff + 24, Endianness.BIG_ENDIAN);
    H5.pack(out, outOff + 32, Endianness.BIG_ENDIAN);
    H6.pack(out, outOff + 40, Endianness.BIG_ENDIAN);
    H7.pack(out, outOff + 48, Endianness.BIG_ENDIAN);
    H8.pack(out, outOff + 56, Endianness.BIG_ENDIAN);

    reset();

    return _DIGEST_LENGTH;
  }

}



