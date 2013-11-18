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

import "package:cipher/adapters/stream_cipher_adapters.dart";

import "package:cipher/digests/ripemd160.dart";

import "package:cipher/engines/aes_fast.dart";
import "package:cipher/engines/salsa20.dart";
import "package:cipher/engines/null_block_cipher.dart";
import "package:cipher/engines/null_stream_cipher.dart";

import "package:cipher/modes/sic.dart";
import "package:cipher/modes/cbc.dart";

import "package:cipher/paddings/padded_block_cipher.dart";
import "package:cipher/paddings/pkcs7.dart";

bool _initialized = false;

/**
 *  This is the initializer method for this library. It must be called prior 
 *  to use any of the implementations.
 */
void initCipher() {
  if( !_initialized ) {
    _initialized = true;
    _registerBlockCiphers();
    _registerChainingBlockCiphers();
    _registerStreamCiphers();
    _registerDigests();
    _registerPaddings();
    _registerPaddedBlockCiphers();
  }
}

void _registerBlockCiphers() {
  BlockCipher.registry["AES"] = (_) => new AESFastEngine();
  BlockCipher.registry["Null"] = (_) => new NullBlockCipher();
}

void _registerChainingBlockCiphers() {
  ChainingBlockCipher.registry.registerDynamicFactory( ( String algorithmName ) {
    var parts = algorithmName.split("/");

    if( parts.length!=2 ) return null;

    var underlyingCipher = _createOrNull( () =>
        new BlockCipher(parts[0])
    );

    if( underlyingCipher!=null ) {
      switch( parts[1] ) {

        case "SIC":
          return new StreamCipherAsChainingBlockCipher(
              underlyingCipher.blockSize,
              new SICStreamCipher(underlyingCipher),
              underlyingCipher
          );

        case "CTR":
          return new StreamCipherAsChainingBlockCipher(
              underlyingCipher.blockSize,
              new CTRStreamCipher(underlyingCipher),
              underlyingCipher
          );

        case "CBC":
          return new CBCBlockCipher( underlyingCipher );

        default:
          return null;
      }
    }

  });
}

void _registerStreamCiphers() {
  StreamCipher.registry["Null"] = (_) => new NullStreamCipher();
  StreamCipher.registry["Salsa20"] = (_) => new Salsa20Engine();
  StreamCipher.registry.registerDynamicFactory( ( String algorithmName ) {
    var parts = algorithmName.split("/");

    if( parts.length!=2 ) return null;
    if( parts[1]!="SIC" && parts[1]!="CTR" ) return null;

    var underlyingCipher = _createOrNull( () =>
        new BlockCipher(parts[0])
    );

    if( underlyingCipher!=null ) {
      switch( parts[1] ) {

        case "SIC":
          return new SICStreamCipher( underlyingCipher );

        case "CTR":
          return new CTRStreamCipher( underlyingCipher );

        default:
          return null;
      }
    }

  });
}

void _registerDigests() {
  Digest.registry["RIPEMD-160"] = (_) => new RIPEMD160Digest();
}

void _registerPaddings() {
  Padding.registry["PKCS7"] = (_) => new PKCS7Padding();
}

void _registerPaddedBlockCiphers() {
  PaddedBlockCipher.registry.registerDynamicFactory( (String algorithmName) {
    var lastSepIndex = algorithmName.lastIndexOf("/");

    if( lastSepIndex==-1 ) return null;

    var padding = _createOrNull( () =>
      new Padding(algorithmName.substring(lastSepIndex+1))
    );
    var underlyingCipher = _createOrNull( () =>
      new ChainingBlockCipher(algorithmName.substring(0,lastSepIndex))
    );

    return new PaddedBlockCipherImpl(padding, underlyingCipher);
  });
}

dynamic _createOrNull( closure() ) {
  try {
   return closure();
  } on ArgumentError catch( e ) {
    return null;
  }
}