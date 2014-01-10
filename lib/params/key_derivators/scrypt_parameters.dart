// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.params.key_derivators.scrypt_parameters;

import "dart:typed_data";

import "package:cipher/api.dart";

/**
 * [CipherParameters] for the scrypt password based key derivation function.
 */
class ScryptParameters implements CipherParameters {

    final int N;
    final int r;
    final int p;
    final int desiredKeyLength;
    final Uint8List salt;

    ScryptParameters( this.N, this.r, this.p, this.desiredKeyLength, this.salt );

}
