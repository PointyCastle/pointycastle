// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.digests.sha384;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/digests/long_sha2_family_digest.dart";

/// Implementation of SHA-384 digest.
class SHA384Digest extends LongSHA2FamilyDigest implements Digest {

  static const _DIGEST_LENGTH = 48;

  SHA384Digest() {
    reset();
  }

  final algorithmName = "SHA-384";
  final digestSize = _DIGEST_LENGTH;

  void reset() {
    super.reset();

    H1.set(0xcbbb9d5d, 0xc1059ed8);
    H2.set(0x629a292a, 0x367cd507);
    H3.set(0x9159015a, 0x3070dd17);
    H4.set(0x152fecd8, 0xf70e5939);
    H5.set(0x67332667, 0xffc00b31);
    H6.set(0x8eb44a87, 0x68581511);
    H7.set(0xdb0c2e0d, 0x64f98fa7);
    H8.set(0x47b5481d, 0xbefa4fa4);
  }

  int doFinal(Uint8List out, int outOff) {
    finish();

    var view = new ByteData.view(out.buffer);
    H1.pack(view, outOff     , Endianness.BIG_ENDIAN);
    H2.pack(view, outOff +  8, Endianness.BIG_ENDIAN);
    H3.pack(view, outOff + 16, Endianness.BIG_ENDIAN);
    H4.pack(view, outOff + 24, Endianness.BIG_ENDIAN);
    H5.pack(view, outOff + 32, Endianness.BIG_ENDIAN);
    H6.pack(view, outOff + 40, Endianness.BIG_ENDIAN);

    reset();

    return _DIGEST_LENGTH;
  }

}



