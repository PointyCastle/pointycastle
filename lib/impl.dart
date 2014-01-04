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

import "package:cipher/ecc/ecc_base.dart";
import "package:cipher/ecc/ecc_fp.dart" as fp;

import "package:cipher/engines/aes_fast.dart";
import "package:cipher/engines/null_block_cipher.dart";
import "package:cipher/engines/null_stream_cipher.dart";
import "package:cipher/engines/salsa20.dart";

import "package:cipher/entropy/file_entropy_source.dart";
import "package:cipher/entropy/url_entropy_source.dart";

import "package:cipher/modes/cbc.dart";
import "package:cipher/modes/sic.dart";

import "package:cipher/paddings/padded_block_cipher.dart";
import "package:cipher/paddings/pkcs7.dart";

import "package:cipher/random/auto_reseed_block_ctr_random.dart";
import "package:cipher/random/block_ctr_random.dart";

import "package:cipher/signers/ecdsa_signer.dart";


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
    _registerEccStandardCurves();
    _registerSigners();
    _registerSecureRandoms();
    _registerEntropySources();
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

void _registerEccStandardCurves() {
  _registerFpStandardCurve("prime192v1",
      q: new BigInteger("6277101735386680763835789423207666416083908700390324961279"),
      a: new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16),
      b: new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16),
      g: new BigInteger("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16),
      n: new BigInteger("ffffffffffffffffffffffff99def836146bc9b1b4d22831", 16),
      h: BigInteger.ONE,
      seed: new BigInteger("3045ae6fc8422f64ed579528d38120eae12196d5", 16)
  );
}

void _registerFpStandardCurve( String name, {BigInteger q, BigInteger a, BigInteger b, BigInteger g, BigInteger n,
  BigInteger h, BigInteger seed } ) {

  var curve = new fp.ECCurve(q,a,b);
  ECDomainParameters.registry[name] = (_)
		=> new ECDomainParametersImpl( name, curve, curve.decodePoint( g.toByteArray() ), n, h, seed.toByteArray() );
}

void _registerSigners() {
	Signer.registry["ECDSA"] = (_) => new ECDSASigner();
}

void _registerSecureRandoms() {
	SecureRandom.registry.registerDynamicFactory( (String algorithmName) {

		if( algorithmName.endsWith("/CTR/PRNG") ) {
			var blockCipherName = algorithmName.substring(0, algorithmName.length-9);
		  var blockCipher = _createOrNull( () => new BlockCipher(blockCipherName) );
		  return new BlockCtrRandom(blockCipher);

		} else if( algorithmName.endsWith("/CTR/AUTO_RESEED_PRNG") ) {
			var blockCipherName = algorithmName.substring(0, algorithmName.length-21);
		  var blockCipher = _createOrNull( () => new BlockCipher(blockCipherName) );
		  return new AutoReseedBlockCtrRandom(blockCipher);

		}

	});
}

void _registerEntropySources() {
	EntropySource.registry.registerDynamicFactory( (String algorithmName) {

	  if( algorithmName.startsWith("file://") ) {
      var filePath = algorithmName.substring(7);
      return new FileEntropySource(filePath);

	  } else if( algorithmName.startsWith("http://") || algorithmName.startsWith("https://") ) {
	    return new UrlEntropySource(algorithmName);

	  }

	});

}

dynamic _createOrNull( closure() ) {
  try {
   return closure();
  } on ArgumentError catch( e ) {
    return null;
  }
}