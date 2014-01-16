// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

/**
 * This library contains all out-of-the-box implementations of the interfaces provided in the API which are compatible with
 * client and server sides.
 *
 * You can extend it with client side algorithms by including library [cipher.impl_client] in addition to this one. You can
 * also extend is with its server side counterpart by including library [cipher.impl_server] in addition to this one
 *
 * You must call [initCipher] method before using this library to load all implementations into cipher's API factories.
 */
library cipher.impl;

import "package:bignum/bignum.dart";

import "package:cipher/api.dart";

import "package:cipher/block/aes_fast.dart";

import "package:cipher/digests/ripemd160.dart";
import "package:cipher/digests/sha1.dart";
import "package:cipher/digests/sha256.dart";

import "package:cipher/ecc/ecc_base.dart";
import "package:cipher/ecc/ecc_fp.dart" as fp;

import "package:cipher/key_derivators/pbkdf2.dart";
import "package:cipher/key_derivators/scrypt.dart";

import "package:cipher/key_generators/ec_key_generator.dart";

import "package:cipher/macs/hmac.dart";

import "package:cipher/modes/cbc.dart";
import "package:cipher/modes/sic.dart";

import "package:cipher/paddings/padded_block_cipher.dart";
import "package:cipher/paddings/pkcs7.dart";

import "package:cipher/random/auto_seed_block_ctr_random.dart";
import "package:cipher/random/block_ctr_random.dart";

import "package:cipher/signers/ecdsa_signer.dart";

import "package:cipher/stream/salsa20.dart";

import "package:cipher/src/adapters/stream_cipher_adapters.dart";


bool _initialized = false;

/// This is the initializer method for this library. It must be called prior to use any of the implementations.
void initCipher() {
  if( !_initialized ) {
    _initialized = true;
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

void _registerBlockCiphers() {
  BlockCipher.registry["AES"] = (_) => new AESFastEngine();
}

void _registerDigests() {
  Digest.registry["RIPEMD-160"] = (_) => new RIPEMD160Digest();
  Digest.registry["SHA-1"] = (_) => new SHA1Digest();
  Digest.registry["SHA-256"] = (_) => new SHA256Digest();
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

void _registerKeyDerivators() {
  KeyDerivator.registry["scrypt"] = (_) => new Scrypt();
  KeyDerivator.registry.registerDynamicFactory( _pbkdf2KeyDerivatorFactory );
}

void _registerKeyGenerators() {
  KeyGenerator.registry["EC"] = (_) => new ECKeyGenerator();
}

void _registerMacs() {
  /*
  blockLengths.put("SHA-384", Integers.valueOf(128));
  blockLengths.put("SHA-512", Integers.valueOf(128));
  blockLengths.put("MD4", Integers.valueOf(64));
  blockLengths.put("MD5", Integers.valueOf(64));
  blockLengths.put("RIPEMD128", Integers.valueOf(64));
  blockLengths.put("SHA-224", Integers.valueOf(64));
  blockLengths.put("Tiger", Integers.valueOf(64));
  blockLengths.put("Whirlpool", Integers.valueOf(64));
  blockLengths.put("GOST3411", Integers.valueOf(32));
  blockLengths.put("MD2", Integers.valueOf(16));
  */
  Mac.registry["SHA-1/HMAC"] = (_) => new HMac(new Digest("SHA-1"), 64);
  Mac.registry["SHA-256/HMAC"] = (_) => new HMac(new Digest("SHA-256"), 64);
  Mac.registry["RIPEMD-160/HMAC"] = (_) => new HMac(new Digest("RIPEMD-160"), 64);
}

void _registerModesOfOperation() {
  BlockCipher.registry.registerDynamicFactory( _cbcBlockCipherFactory );
  BlockCipher.registry.registerDynamicFactory( _ctrBlockCipherFactory );
  BlockCipher.registry.registerDynamicFactory( _sicBlockCipherFactory );
}

void _registerPaddedBlockCiphers() {
  PaddedBlockCipher.registry.registerDynamicFactory( _paddedBlockCipherFactory );
}

void _registerPaddings() {
  Padding.registry["PKCS7"] = (_) => new PKCS7Padding();
}

void _registerSecureRandoms() {
  SecureRandom.registry.registerDynamicFactory( _ctrPrngSecureRandomFactory );
  SecureRandom.registry.registerDynamicFactory( _ctrAutoSeedPrngSecureRandomFactory );
}

void _registerSigners() {
  Signer.registry["ECDSA"] = (_) => new ECDSASigner();
}

void _registerStreamCiphers() {
  StreamCipher.registry["Salsa20"] = (_) => new Salsa20Engine();
  StreamCipher.registry.registerDynamicFactory( _ctrStreamCipherFactory );
  StreamCipher.registry.registerDynamicFactory( _sicStreamCipherFactory );
}


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

KeyDerivator _pbkdf2KeyDerivatorFactory(String algorithmName) {
  var i = algorithmName.lastIndexOf("/");

  if( i==-1 ) return null;
  if( algorithmName.substring(i+1)!="PBKDF2" ) return null;

  var mac = _createOrNull( () =>
      new Mac(algorithmName.substring(0, i))
  );
  if( mac!=null ) {
    return new PBKDF2KeyDerivator(mac);
  }
}

BlockCipher _cbcBlockCipherFactory( String algorithmName ) {
  var parts = algorithmName.split("/");

  if( parts.length!=2 ) return null;
  if( parts[1]!="CBC") return null;

  var underlyingCipher = _createOrNull( () =>
      new BlockCipher(parts[0])
  );

  if( underlyingCipher!=null ) {
    return new CBCBlockCipher( underlyingCipher );
  }
}

BlockCipher _ctrBlockCipherFactory( String algorithmName ) {
  var parts = algorithmName.split("/");

  if( parts.length!=2 ) return null;
  if( parts[1]!="CTR") return null;

  var underlyingCipher = _createOrNull( () =>
      new BlockCipher(parts[0])
  );

  if( underlyingCipher!=null ) {
    return new StreamCipherAsBlockCipher(
        underlyingCipher.blockSize,
        new CTRStreamCipher(underlyingCipher)
    );
  }
}

BlockCipher _sicBlockCipherFactory( String algorithmName ) {
  var parts = algorithmName.split("/");

  if( parts.length!=2 ) return null;
  if( parts[1]!="SIC") return null;

  var underlyingCipher = _createOrNull( () =>
      new BlockCipher(parts[0])
  );

  if( underlyingCipher!=null ) {
    return new StreamCipherAsBlockCipher(
        underlyingCipher.blockSize,
        new SICStreamCipher(underlyingCipher)
    );
  }
}

PaddedBlockCipher _paddedBlockCipherFactory(String algorithmName) {
  var lastSepIndex = algorithmName.lastIndexOf("/");

  if( lastSepIndex==-1 ) return null;

  var padding = _createOrNull( () =>
    new Padding(algorithmName.substring(lastSepIndex+1))
  );
  if( padding!=null ) {
    var underlyingCipher = _createOrNull( () =>
      new BlockCipher(algorithmName.substring(0,lastSepIndex))
    );
    if( underlyingCipher!=null ) {
      return new PaddedBlockCipherImpl(padding, underlyingCipher);
    }
  }
}

SecureRandom _ctrPrngSecureRandomFactory( String algorithmName ) {
  if( algorithmName.endsWith("/CTR/PRNG") ) {
    var blockCipherName = algorithmName.substring(0, algorithmName.length-9);
    var blockCipher = _createOrNull( () => new BlockCipher(blockCipherName) );
    return new BlockCtrRandom(blockCipher);
  }
}

SecureRandom _ctrAutoSeedPrngSecureRandomFactory( String algorithmName ) {
  if( algorithmName.endsWith("/CTR/AUTO-SEED-PRNG") ) {
    var blockCipherName = algorithmName.substring(0, algorithmName.length-19);
    var blockCipher = _createOrNull( () => new BlockCipher(blockCipherName) );
    return new AutoSeedBlockCtrRandom(blockCipher);
  }
}

StreamCipher _ctrStreamCipherFactory( String algorithmName ) {
  var parts = algorithmName.split("/");

  if( parts.length!=2 ) return null;
  if( parts[1]!="CTR" ) return null;

  var underlyingCipher = _createOrNull( () =>
      new BlockCipher(parts[0])
  );

  if( underlyingCipher!=null ) {
    return new CTRStreamCipher( underlyingCipher );
  }
}

StreamCipher _sicStreamCipherFactory( String algorithmName ) {
  var parts = algorithmName.split("/");

  if( parts.length!=2 ) return null;
  if( parts[1]!="SIC" ) return null;

  var underlyingCipher = _createOrNull( () =>
      new BlockCipher(parts[0])
  );

  if( underlyingCipher!=null ) {
    return new SICStreamCipher( underlyingCipher );
  }
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void _registerFpStandardCurve( String name, {BigInteger q, BigInteger a, BigInteger b, BigInteger g, BigInteger n,
  BigInteger h, BigInteger seed } ) {

  var curve = new fp.ECCurve(q,a,b);
  ECDomainParameters.registry[name] = (_)
    => new ECDomainParametersImpl( name, curve, curve.decodePoint( g.toByteArray() ), n, h, seed.toByteArray() );
}

dynamic _createOrNull( closure() ) {
  try {
   return closure();
  } on UnsupportedError catch( e ) {
    return null;
  }
}