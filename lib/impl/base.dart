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
library cipher.impl.base;

import "package:bignum/bignum.dart";

import "package:cipher/api.dart";

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

import "package:cipher/ecc/ecc_base.dart";
import "package:cipher/ecc/ecc_fp.dart" as fp;

import "package:cipher/key_derivators/pbkdf2.dart";
import "package:cipher/key_derivators/scrypt.dart";

import "package:cipher/key_generators/ec_key_generator.dart";

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

import "package:cipher/signers/ecdsa_signer.dart";

import "package:cipher/stream/salsa20.dart";

import "package:cipher/src/adapters/stream_cipher_adapters.dart";


part "../src/impl/base/ecc_curves.dart";


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
  Digest.registry["MD2"] = (_) => new MD2Digest();
  Digest.registry["MD4"] = (_) => new MD4Digest();
  Digest.registry["MD5"] = (_) => new MD5Digest();
  Digest.registry["RIPEMD-128"] = (_) => new RIPEMD128Digest();
  Digest.registry["RIPEMD-160"] = (_) => new RIPEMD160Digest();
  Digest.registry["RIPEMD-256"] = (_) => new RIPEMD256Digest();
  Digest.registry["RIPEMD-320"] = (_) => new RIPEMD320Digest();
  Digest.registry["SHA-1"] = (_) => new SHA1Digest();
  Digest.registry["SHA-224"] = (_) => new SHA224Digest();
  Digest.registry["SHA-256"] = (_) => new SHA256Digest();
  Digest.registry["SHA-384"] = (_) => new SHA384Digest();
  Digest.registry["SHA-512"] = (_) => new SHA512Digest();
  Digest.registry.registerDynamicFactory( _sha3DigestFactory );
  Digest.registry.registerDynamicFactory( _sha512tDigestFactory );
}

// See part ecc_curves.dart for _registerEccStandardCurves()

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
  blockLengths.put("RIPEMD128", Integers.valueOf(64));
  blockLengths.put("SHA-224", Integers.valueOf(64));
  blockLengths.put("Tiger", Integers.valueOf(64));
  blockLengths.put("Whirlpool", Integers.valueOf(64));
  blockLengths.put("GOST3411", Integers.valueOf(32));
  */
  Mac.registry["SHA-1/HMAC"] = (_) => new HMac(new Digest("SHA-1"), 64);
  Mac.registry["SHA-256/HMAC"] = (_) => new HMac(new Digest("SHA-256"), 64);
  Mac.registry["MD2/HMAC"] = (_) => new HMac(new Digest("MD2"), 16);
  Mac.registry["MD4/HMAC"] = (_) => new HMac(new Digest("MD4"), 64);
  Mac.registry["MD5/HMAC"] = (_) => new HMac(new Digest("MD5"), 64);
  Mac.registry["RIPEMD-160/HMAC"] = (_) => new HMac(new Digest("RIPEMD-160"), 64);
}

void _registerModesOfOperation() {
  BlockCipher.registry.registerDynamicFactory(
      (algorithmName) => _modeOfOperationFactory(algorithmName, "CBC", (underlyingCipher)
          => new CBCBlockCipher( underlyingCipher )
      )
  );
  BlockCipher.registry.registerDynamicFactory(
      (algorithmName) => _variableSizeModeOfOperationFactory(algorithmName, "CFB", (underlyingCipher, blockSize)
          => new CFBBlockCipher( underlyingCipher, blockSize )
      )
  );
  BlockCipher.registry.registerDynamicFactory(
      (algorithmName) => _modeOfOperationFactory(algorithmName, "CTR", (underlyingCipher)
          => new StreamCipherAsBlockCipher( underlyingCipher.blockSize, new CTRStreamCipher(underlyingCipher) )
      )
  );
  BlockCipher.registry.registerDynamicFactory(
      (algorithmName) => _modeOfOperationFactory(algorithmName, "ECB", (underlyingCipher)
          => new ECBBlockCipher( underlyingCipher )
      )
  );
  BlockCipher.registry.registerDynamicFactory(
      (algorithmName) => _modeOfOperationFactory(algorithmName, "GCTR", (underlyingCipher)
          => new GCTRBlockCipher( underlyingCipher )
      )
  );
  BlockCipher.registry.registerDynamicFactory(
      (algorithmName) => _variableSizeModeOfOperationFactory(algorithmName, "OFB", (underlyingCipher, blockSize)
          => new OFBBlockCipher( underlyingCipher, blockSize )
      )
  );
  BlockCipher.registry.registerDynamicFactory(
      (algorithmName) => _modeOfOperationFactory(algorithmName, "SIC", (underlyingCipher)
          => new StreamCipherAsBlockCipher( underlyingCipher.blockSize, new SICStreamCipher(underlyingCipher) )
      )
  );
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

Digest _sha512tDigestFactory(String algorithmName) {
  if( !algorithmName.startsWith("SHA-512/") ) return null;

  var digestSize = int.parse( algorithmName.substring(8) );
  if( (digestSize % 8) != 0 ) {
    throw new ArgumentError("Digest length for SHA-512/t is not a multiple of 8: ${digestSize}");
  }

  return new SHA512tDigest( digestSize~/8 );
}

Digest _sha3DigestFactory(String algorithmName) {
  if( !algorithmName.startsWith("SHA-3/") ) return null;

  var bitLength = int.parse( algorithmName.substring(6) );

  return new SHA3Digest( bitLength );
}

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

BlockCipher _modeOfOperationFactory( String algorithmName, String modeName,
                                     BlockCipher subFactory(BlockCipher underlyingCipher) ) {
  var sep = algorithmName.lastIndexOf("/");

  if( sep==-1 ) return null;
  if( algorithmName.substring(sep+1)!=modeName) return null;

  var underlyingCipher = _createOrNull( () =>
      new BlockCipher(algorithmName.substring(0, sep))
  );

  if( underlyingCipher!=null ) {
    return subFactory(underlyingCipher);
  }
}

BlockCipher _variableSizeModeOfOperationFactory( String algorithmName, String modeName,
                                                 BlockCipher subFactory(BlockCipher underlyingCipher, int blockSize) ) {
  var sep = algorithmName.lastIndexOf("/");

  if( sep==-1 ) return null;
  if( !algorithmName.substring(sep+1).startsWith(modeName+"-") ) return null;

  var blockSizeInBits = int.parse(algorithmName.substring(sep+1+modeName.length+1));
  if( (blockSizeInBits%8) != 0 ) {
    throw new ArgumentError("Bad ${modeName} block size: $blockSizeInBits (must be a multiple of 8)");
  }

  var underlyingCipher = _createOrNull( () =>
      new BlockCipher(algorithmName.substring(0, sep))
  );

  if( underlyingCipher!=null ) {
    return subFactory(underlyingCipher, blockSizeInBits~/8 );
  }
}

BlockCipher _cfbBlockCipherFactory( String algorithmName ) {
  var parts = algorithmName.split("/");

  if( parts.length!=2 ) return null;
  if( !parts[1].startsWith("CFB-") ) return null;

  var blockSizeInBits = int.parse(parts[1].substring(4));
  if( (blockSizeInBits%8) != 0 ) {
    throw new ArgumentError("Bad CFB block size: $blockSizeInBits (must be a multiple of 8)");
  }

  var underlyingCipher = _createOrNull( () =>
      new BlockCipher(parts[0])
  );

  if( underlyingCipher!=null ) {
    return new CFBBlockCipher(underlyingCipher, blockSizeInBits~/8 );
  }
}

BlockCipher _ofbBlockCipherFactory( String algorithmName ) {
  var parts = algorithmName.split("/");

  if( parts.length!=2 ) return null;
  if( !parts[1].startsWith("OFB-") ) return null;

  var blockSizeInBits = int.parse(parts[1].substring(4));
  if( (blockSizeInBits%8) != 0 ) {
    throw new ArgumentError("Bad OFB block size: $blockSizeInBits (must be a multiple of 8)");
  }

  var underlyingCipher = _createOrNull( () =>
      new BlockCipher(parts[0])
  );

  if( underlyingCipher!=null ) {
    return new OFBBlockCipher(underlyingCipher, blockSizeInBits~/8 );
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

dynamic _createOrNull( closure() ) {
  try {
   return closure();
  } on UnsupportedError catch( e ) {
    return null;
  }
}