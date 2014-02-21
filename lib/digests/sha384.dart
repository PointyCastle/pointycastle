// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.digests.sha384;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/api/ufixnum.dart";
import "package:cipher/digests/long_sha2_family_digest.dart";

/// Implementation of SHA-384 digest.
class SHA384Digest extends LongSHA2FamilyDigest implements Digest {

  static final _DIGEST_LENGTH = 48;

  String get algorithmName => "SHA-384";

  int get digestSize => _DIGEST_LENGTH;

  void reset() {
    super.reset();

    // SHA-384 initial hash value: The first 64 bits of the fractional parts of the square roots of the 9th through 16th prime
    // numbers
    H1 = new Uint64(0xcbbb9d5d, 0xc1059ed8);
    H2 = new Uint64(0x629a292a, 0x367cd507);
    H3 = new Uint64(0x9159015a, 0x3070dd17);
    H4 = new Uint64(0x152fecd8, 0xf70e5939);
    H5 = new Uint64(0x67332667, 0xffc00b31);
    H6 = new Uint64(0x8eb44a87, 0x68581511);
    H7 = new Uint64(0xdb0c2e0d, 0x64f98fa7);
    H8 = new Uint64(0x47b5481d, 0xbefa4fa4);
  }

  int doFinal(Uint8List out, int outOff) {
    finish();

    H1.toBigEndian(out, outOff);
    H2.toBigEndian(out, outOff+8);
    H3.toBigEndian(out, outOff+16);
    H4.toBigEndian(out, outOff+24);
    H5.toBigEndian(out, outOff+32);
    H6.toBigEndian(out, outOff+40);

    reset();

    return _DIGEST_LENGTH;
  }

}



