// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

/**
 * This library contains all out-of-the-box implementations of the interfaces provided in the API
 * which are compatible with client and server sides.
 *
 * You can extend it with client side algorithms by including library [cipher.impl_client] in
 * addition to this one. You can also extend is with its server side counterpart by including
 * library [cipher.impl_server] in addition to this one
 *
 * You must call [initCipher] method before using this library to load all implementations into
 * cipher's API factories.
 */
library cipher.impl;

import "package:bignum/bignum.dart";

import "package:cipher/adapters/stream_cipher_as_block_cipher.dart";

import "package:cipher/api.dart";

export "package:cipher/asymmetric/api.dart";
import "package:cipher/asymmetric/rsa.dart";
import "package:cipher/asymmetric/pkcs1.dart";

import "package:cipher/block/aes_fast.dart";

import "package:cipher/digests/md2.dart";
import "package:cipher/digests/md4.dart";
import "package:cipher/digests/md5.dart";
import "package:cipher/digests/ripemd128.dart";
import "package:cipher/digests/ripemd160.dart";
import "package:cipher/digests/ripemd256.dart";
import "package:cipher/digests/ripemd320.dart";
import "package:cipher/digests/sha1.dart";
import "package:cipher/digests/sha224.dart";
import "package:cipher/digests/sha256.dart";
import "package:cipher/digests/sha3.dart";
import "package:cipher/digests/sha384.dart";
import "package:cipher/digests/sha512.dart";
import "package:cipher/digests/sha512t.dart";
import "package:cipher/digests/tiger.dart";
import "package:cipher/digests/whirlpool.dart";

export "package:cipher/ecc/api.dart";
import "package:cipher/ecc/api.dart";
import "package:cipher/ecc/ecc_base.dart";
import "package:cipher/ecc/ecc_fp.dart" as fp;

export "package:cipher/key_derivators/api.dart";
import "package:cipher/key_derivators/pbkdf2.dart";
import "package:cipher/key_derivators/scrypt.dart";

export "package:cipher/key_generators/api.dart";
import "package:cipher/key_generators/ec_key_generator.dart";
import "package:cipher/key_generators/rsa_key_generator.dart";

import "package:cipher/macs/hmac.dart";

import "package:cipher/modes/cbc.dart";
import "package:cipher/modes/cfb.dart";
import "package:cipher/modes/ecb.dart";
import "package:cipher/modes/gctr.dart";
import "package:cipher/modes/ofb.dart";
import "package:cipher/modes/sic.dart";

import "package:cipher/paddings/padded_block_cipher.dart";
import "package:cipher/paddings/pkcs7.dart";

import "package:cipher/random/auto_seed_block_ctr_random.dart";
import "package:cipher/random/block_ctr_random.dart";
import "package:cipher/random/fortuna_random.dart";

import "package:cipher/signers/ecdsa_signer.dart";
import "package:cipher/signers/rsa_signer.dart";

import "package:cipher/stream/salsa20.dart";

part "./src/impl/ecc_curves.dart";
part "./src/impl/registration.dart";

bool _initialized = false;

/**
 * This is the initializer method for this library. It must be called prior to use any of the
 * implementations.
 */
void initCipher() {

  if (!_initialized) {
    _initialized = true;

    _registerAsymmetricBlockCiphers();
    _registerBlockCiphers();
    _registerDigests();
    _registerEccStandardCurves();
    _registerKeyDerivators();
    _registerKeyGenerators();
    _registerMacs();
    _registerModesOfOperation();
    _registerPaddedBlockCiphers();
    _registerPaddings();
    _registerSecureRandoms();
    _registerSigners();
    _registerStreamCiphers();
  }
}



