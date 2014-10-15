// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

part of cipher.impl;

////////////////////////////////////////////////////////////////////////////////////////////////////
void _registerAsymmetricBlockCiphers() {
  AsymmetricBlockCipher.registry.registerDynamicFactory(_pkcs1AsymmetricBlockCipherFactory);
  AsymmetricBlockCipher.registry["RSA"] = (_) => new RSAEngine();
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
  Digest.registry["Tiger"] = (_) => new TigerDigest();
  Digest.registry["Whirlpool"] = (_) => new WhirlpoolDigest();
  Digest.registry.registerDynamicFactory(_sha3DigestFactory);
  Digest.registry.registerDynamicFactory(_sha512tDigestFactory);
}

// See part ecc_curves.dart for _registerEccStandardCurves()

void _registerKeyDerivators() {
  KeyDerivator.registry["scrypt"] = (_) => new Scrypt();
  KeyDerivator.registry.registerDynamicFactory(_pbkdf2KeyDerivatorFactory);
}

void _registerKeyGenerators() {
  KeyGenerator.registry["EC"] = (_) => new ECKeyGenerator();
  KeyGenerator.registry["RSA"] = (_) => new RSAKeyGenerator();
}

void _registerMacs() {
  Mac.registry["GOST3411/HMAC"] = (_) => new HMac(new Digest("GOST3411"), 32);
  Mac.registry["MD2/HMAC"] = (_) => new HMac(new Digest("MD2"), 16);
  Mac.registry["MD4/HMAC"] = (_) => new HMac(new Digest("MD4"), 64);
  Mac.registry["MD5/HMAC"] = (_) => new HMac(new Digest("MD5"), 64);
  Mac.registry["RIPEMD-128/HMAC"] = (_) => new HMac(new Digest("RIPEMD-128"), 64);
  Mac.registry["RIPEMD-160/HMAC"] = (_) => new HMac(new Digest("RIPEMD-160"), 64);
  Mac.registry["SHA-1/HMAC"] = (_) => new HMac(new Digest("SHA-1"), 64);
  Mac.registry["SHA-224/HMAC"] = (_) => new HMac(new Digest("SHA-224"), 64);
  Mac.registry["SHA-256/HMAC"] = (_) => new HMac(new Digest("SHA-256"), 64);
  Mac.registry["SHA-384/HMAC"] = (_) => new HMac(new Digest("SHA-384"), 128);
  Mac.registry["SHA-512/HMAC"] = (_) => new HMac(new Digest("SHA-512"), 128);
  Mac.registry["Tiger/HMAC"] = (_) => new HMac(new Digest("Tiger"), 64);
  Mac.registry["Whirlpool/HMAC"] = (_) => new HMac(new Digest("Whirlpool"), 64);
}

void _registerModesOfOperation() {
  BlockCipher.registry.registerDynamicFactory(
      (algorithmName) =>
          _modeOfOperationFactory(
              algorithmName,
              "CBC",
              (underlyingCipher) => new CBCBlockCipher(underlyingCipher)));
  BlockCipher.registry.registerDynamicFactory(
      (algorithmName) =>
          _variableSizeModeOfOperationFactory(
              algorithmName,
              "CFB",
              (underlyingCipher, blockSize) => new CFBBlockCipher(underlyingCipher, blockSize)));
  BlockCipher.registry.registerDynamicFactory(
      (algorithmName) =>
          _modeOfOperationFactory(
              algorithmName,
              "CTR",
              (underlyingCipher) =>
                  new StreamCipherAsBlockCipher(underlyingCipher.blockSize, new CTRStreamCipher(underlyingCipher))));
  BlockCipher.registry.registerDynamicFactory(
      (algorithmName) =>
          _modeOfOperationFactory(
              algorithmName,
              "ECB",
              (underlyingCipher) => new ECBBlockCipher(underlyingCipher)));
  BlockCipher.registry.registerDynamicFactory(
      (algorithmName) =>
          _modeOfOperationFactory(
              algorithmName,
              "GCTR",
              (underlyingCipher) => new GCTRBlockCipher(underlyingCipher)));
  BlockCipher.registry.registerDynamicFactory(
      (algorithmName) =>
          _variableSizeModeOfOperationFactory(
              algorithmName,
              "OFB",
              (underlyingCipher, blockSize) => new OFBBlockCipher(underlyingCipher, blockSize)));
  BlockCipher.registry.registerDynamicFactory(
      (algorithmName) =>
          _modeOfOperationFactory(
              algorithmName,
              "SIC",
              (underlyingCipher) =>
                  new StreamCipherAsBlockCipher(underlyingCipher.blockSize, new SICStreamCipher(underlyingCipher))));
}

void _registerPaddedBlockCiphers() {
  PaddedBlockCipher.registry.registerDynamicFactory(_paddedBlockCipherFactory);
}

void _registerPaddings() {
  Padding.registry["PKCS7"] = (_) => new PKCS7Padding();
}

void _registerSecureRandoms() {
  SecureRandom.registry["Fortuna"] = (_) => new FortunaRandom();
  SecureRandom.registry.registerDynamicFactory(_ctrPrngSecureRandomFactory);
  SecureRandom.registry.registerDynamicFactory(_ctrAutoSeedPrngSecureRandomFactory);
}

void _registerSigners() {
  Signer.registry.registerDynamicFactory(_ecdsaSignerFactory);
  Signer.registry["MD2/RSA"] = (_) => new RSASigner(new Digest("MD2"), "06082a864886f70d0202");
  Signer.registry["MD4/RSA"] = (_) => new RSASigner(new Digest("MD4"), "06082a864886f70d0204");
  Signer.registry["MD5/RSA"] = (_) => new RSASigner(new Digest("MD5"), "06082a864886f70d0205");
  Signer.registry["RIPEMD-128/RSA"] =
      (_) => new RSASigner(new Digest("RIPEMD-128"), "06052b24030202");
  Signer.registry["RIPEMD-160/RSA"] =
      (_) => new RSASigner(new Digest("RIPEMD-160"), "06052b24030201");
  Signer.registry["RIPEMD-256/RSA"] =
      (_) => new RSASigner(new Digest("RIPEMD-256"), "06052b24030203");
  Signer.registry["SHA-1/RSA"] = (_) => new RSASigner(new Digest("SHA-1"), "06052b0e03021a");
  Signer.registry["SHA-224/RSA"] =
      (_) => new RSASigner(new Digest("SHA-224"), "0609608648016503040204");
  Signer.registry["SHA-256/RSA"] =
      (_) => new RSASigner(new Digest("SHA-256"), "0609608648016503040201");
  Signer.registry["SHA-384/RSA"] =
      (_) => new RSASigner(new Digest("SHA-384"), "0609608648016503040202");
  Signer.registry["SHA-512/RSA"] =
      (_) => new RSASigner(new Digest("SHA-512"), "0609608648016503040203");
}

void _registerStreamCiphers() {
  StreamCipher.registry["Salsa20"] = (_) => new Salsa20Engine();
  StreamCipher.registry.registerDynamicFactory(_ctrStreamCipherFactory);
  StreamCipher.registry.registerDynamicFactory(_sicStreamCipherFactory);
}

////////////////////////////////////////////////////////////////////////////////////////////////////
AsymmetricBlockCipher _pkcs1AsymmetricBlockCipherFactory(String algorithmName) {
  var sep = algorithmName.lastIndexOf("/");

  if (sep == -1) return null;
  if (algorithmName.substring(sep + 1) != "PKCS1") return null;

  var underlyingCipher =
      _createOrNull(() => new AsymmetricBlockCipher(algorithmName.substring(0, sep)));

  if (underlyingCipher != null) {
    return new PKCS1Encoding(underlyingCipher);
  }

  return null;
}

Digest _sha512tDigestFactory(String algorithmName) {
  if (!algorithmName.startsWith("SHA-512/")) return null;

  var bitLength = int.parse(algorithmName.substring(8));
  if ((bitLength % 8) != 0) {
    throw new ArgumentError("Digest length for SHA-512/t is not a multiple of 8: ${bitLength}");
  }

  return new SHA512tDigest(bitLength ~/ 8);
}

Digest _sha3DigestFactory(String algorithmName) {
  if (!algorithmName.startsWith("SHA-3/")) return null;

  var bitLength = int.parse(algorithmName.substring(6));

  return new SHA3Digest(bitLength);
}

KeyDerivator _pbkdf2KeyDerivatorFactory(String algorithmName) {
  var i = algorithmName.lastIndexOf("/");

  if (i == -1) return null;
  if (algorithmName.substring(i + 1) != "PBKDF2") return null;

  var mac = _createOrNull(() => new Mac(algorithmName.substring(0, i)));
  if (mac != null) {
    return new PBKDF2KeyDerivator(mac);
  }

  return null;
}

BlockCipher _modeOfOperationFactory(String algorithmName, String modeName, BlockCipher
    subFactory(BlockCipher underlyingCipher)) {
  var sep = algorithmName.lastIndexOf("/");

  if (sep == -1) return null;
  if (algorithmName.substring(sep + 1) != modeName) return null;

  var underlyingCipher = _createOrNull(() => new BlockCipher(algorithmName.substring(0, sep)));

  if (underlyingCipher != null) {
    return subFactory(underlyingCipher);
  }

  return null;
}

BlockCipher _variableSizeModeOfOperationFactory(String algorithmName, String modeName, BlockCipher
    subFactory(BlockCipher underlyingCipher, int blockSize)) {
  var sep = algorithmName.lastIndexOf("/");

  if (sep == -1) return null;
  if (!algorithmName.substring(sep + 1).startsWith(modeName + "-")) return null;

  var blockSizeInBits = int.parse(algorithmName.substring(sep + 1 + modeName.length + 1));
  if ((blockSizeInBits % 8) != 0) {
    throw new ArgumentError(
        "Bad ${modeName} block size: $blockSizeInBits (must be a multiple of 8)");
  }

  var underlyingCipher = _createOrNull(() => new BlockCipher(algorithmName.substring(0, sep)));

  if (underlyingCipher != null) {
    return subFactory(underlyingCipher, blockSizeInBits ~/ 8);
  }

  return null;
}

BlockCipher _cfbBlockCipherFactory(String algorithmName) {
  var parts = algorithmName.split("/");

  if (parts.length != 2) return null;
  if (!parts[1].startsWith("CFB-")) return null;

  var blockSizeInBits = int.parse(parts[1].substring(4));
  if ((blockSizeInBits % 8) != 0) {
    throw new ArgumentError("Bad CFB block size: $blockSizeInBits (must be a multiple of 8)");
  }

  var underlyingCipher = _createOrNull(() => new BlockCipher(parts[0]));

  if (underlyingCipher != null) {
    return new CFBBlockCipher(underlyingCipher, blockSizeInBits ~/ 8);
  }

  return null;
}

BlockCipher _ofbBlockCipherFactory(String algorithmName) {
  var parts = algorithmName.split("/");

  if (parts.length != 2) return null;
  if (!parts[1].startsWith("OFB-")) return null;

  var blockSizeInBits = int.parse(parts[1].substring(4));
  if ((blockSizeInBits % 8) != 0) {
    throw new ArgumentError("Bad OFB block size: $blockSizeInBits (must be a multiple of 8)");
  }

  var underlyingCipher = _createOrNull(() => new BlockCipher(parts[0]));

  if (underlyingCipher != null) {
    return new OFBBlockCipher(underlyingCipher, blockSizeInBits ~/ 8);
  }

  return null;
}

PaddedBlockCipher _paddedBlockCipherFactory(String algorithmName) {
  var lastSepIndex = algorithmName.lastIndexOf("/");

  if (lastSepIndex == -1) return null;

  var padding = _createOrNull(() => new Padding(algorithmName.substring(lastSepIndex + 1)));
  if (padding != null) {
    var underlyingCipher =
        _createOrNull(() => new BlockCipher(algorithmName.substring(0, lastSepIndex)));
    if (underlyingCipher != null) {
      return new PaddedBlockCipherImpl(padding, underlyingCipher);
    }
  }

  return null;
}

SecureRandom _ctrPrngSecureRandomFactory(String algorithmName) {
  if (algorithmName.endsWith("/CTR/PRNG")) {
    var blockCipherName = algorithmName.substring(0, algorithmName.length - 9);
    var blockCipher = _createOrNull(() => new BlockCipher(blockCipherName));
    return new BlockCtrRandom(blockCipher);
  }

  return null;
}

SecureRandom _ctrAutoSeedPrngSecureRandomFactory(String algorithmName) {
  if (algorithmName.endsWith("/CTR/AUTO-SEED-PRNG")) {
    var blockCipherName = algorithmName.substring(0, algorithmName.length - 19);
    var blockCipher = _createOrNull(() => new BlockCipher(blockCipherName));
    return new AutoSeedBlockCtrRandom(blockCipher);
  }

  return null;
}

Signer _ecdsaSignerFactory(String algorithmName) {
  var sep = algorithmName.lastIndexOf("/");

  if (sep == -1) return null;

  var ecdsaName = algorithmName.substring(sep + 1);
  if ((ecdsaName != "ECDSA") && (ecdsaName != "DET-ECDSA")) return null;

  var digestName = algorithmName.substring(0, sep);

  var underlyingDigest = _createOrNull(() => new Digest(digestName));

  if (underlyingDigest != null) {
    var mac = null;
    if (ecdsaName == "DET-ECDSA") {
      mac = new Mac("${digestName}/HMAC");
    }

    return new ECDSASigner(underlyingDigest, mac);
  }

  return null;
}

StreamCipher _ctrStreamCipherFactory(String algorithmName) {
  var parts = algorithmName.split("/");

  if (parts.length != 2) return null;
  if (parts[1] != "CTR") return null;

  var underlyingCipher = _createOrNull(() => new BlockCipher(parts[0]));

  if (underlyingCipher != null) {
    return new CTRStreamCipher(underlyingCipher);
  }

  return null;
}

StreamCipher _sicStreamCipherFactory(String algorithmName) {
  var parts = algorithmName.split("/");

  if (parts.length != 2) return null;
  if (parts[1] != "SIC") return null;

  var underlyingCipher = _createOrNull(() => new BlockCipher(parts[0]));

  if (underlyingCipher != null) {
    return new SICStreamCipher(underlyingCipher);
  }

  return null;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

dynamic _createOrNull(closure()) {
  try {
    return closure();
  } on UnsupportedError catch (e) {
    return null;
  }
}
