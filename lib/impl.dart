// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

/**
 * This library contains all out-of-the-box implementations of the interfaces
 * provided in the API.
 *
 * You must call [initCipher] method before using this library to load all
 * implementations into cipher's API factories.
 */
library cipher.impl;

import "package:cipher/api.dart";

import "package:cipher/digests/ripemd160.dart";

import "package:cipher/engines/aes_fast.dart";
import "package:cipher/engines/salsa20.dart";
import "package:cipher/engines/null_cipher.dart";

import "package:cipher/modes/sic.dart";

bool _initialized = false;

/**
 *  This is the initializer method for this library. It must be called prior
 *  to use any of the implementations.
 */
void initCipher() {

  if( !_initialized ) {
    _initialized = true;

    // Register block ciphers
    BlockCipher.register( "AES", () => new AESFastEngine() );
    BlockCipher.register( "Null", () => new NullBlockCipher() );

    // Register chaining block ciphers
    ChainingBlockCipher.register( "SIC", (underlyingCipher) => new SICBlockCipher(underlyingCipher) );
    ChainingBlockCipher.register( "CTR", (underlyingCipher) => new SICBlockCipher(underlyingCipher) );

    // Register stream ciphers
    StreamCipher.register( "Salsa20", () => new Salsa20Engine() );

    // Register digests
    Digest.register( "RIPEMD-160", () => new RIPEMD160Digest() );
  }

}