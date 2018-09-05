// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.
library pointycastle.impl.block_cipher.modes.cbc_hmac;

import "dart:typed_data";

import "package:pointycastle/api.dart";
import "package:pointycastle/src/registry/registry.dart";
import "package:pointycastle/src/impl/base_aead_block_cipher.dart";
import "package:pointycastle/macs/hmac.dart";
import "package:pointycastle/digests/sha256.dart";
import "package:pointycastle/digests/sha384.dart";
import "package:pointycastle/digests/sha512.dart";
import "package:pointycastle/padded_block_cipher/padded_block_cipher_impl.dart";
import "package:pointycastle/paddings/pkcs7.dart";

import "cbc.dart";

/// Implementation of [Authenticated Encryption with AES-CBC and HMAC-SHA]
/// (https://tools.ietf.org/html/rfc7518#section-5.2)
class CBCHMACAuthenticatedEncryptionCipher extends BaseAEADBlockCipher {

  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG =
  new DynamicFactoryConfig.suffix(BlockCipher, "/CBC_HMAC",
          (_, final Match match) =>
          () {
        BlockCipher underlying = new BlockCipher(match.group(1));
        return new CBCHMACAuthenticatedEncryptionCipher(underlying);
      });

  Mac _underlyingMac;
  Uint8List _hash;

  CBCHMACAuthenticatedEncryptionCipher(BlockCipher underlyingCipher) :
        super(new PaddedBlockCipherImpl(new PKCS7Padding(), new CBCBlockCipher(underlyingCipher)));

  @override
  String get algorithmName => "${underlyingCipher.algorithmName.substring(0,7)}_HMAC";



  @override
  void prepare(KeyParameter keyParam) {
    var key = keyParam.key;

    var macKey = new Uint8List.view(key.buffer, key.offsetInBytes, key.length~/2);
    var encKey = new Uint8List.view(key.buffer, key.offsetInBytes+key.length~/2);

    switch (macSize) {
      case 16:
        _underlyingMac = new HMac(new SHA256Digest(), 64);
        break;
      case 24:
        _underlyingMac = new HMac(new SHA384Digest(), 64);
        break;
      case 64:
        _underlyingMac = new HMac(new SHA512Digest(), 64);
        break;
      default:
        throw new ArgumentError("Invalid mac size $macSize");
    }
    _underlyingMac.init(new KeyParameter(macKey));
    underlyingCipher.init(forEncryption, new PaddedBlockCipherParameters(
        new ParametersWithIV(
          new KeyParameter(encKey),
          nonce,
        ), null));

  }

  @override
  void processAADBytes(Uint8List inp, int inpOff, int len) {
    _underlyingMac.update(inp, inpOff, len);
    _underlyingMac.update(nonce, 0, nonce.length);
  }

  @override
  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    var l = underlyingCipher.processBlock(inp, inpOff, out, outOff);
    if (forEncryption) {
      _underlyingMac.update(out, outOff, l);
    } else {
      _underlyingMac.update(inp, inpOff, blockSize);
    }
    return l;
  }

  @override
  int doFinal(Uint8List out, int outOff) {
    var l = 0;

    if (remainingInput.isNotEmpty) {
      l += (underlyingCipher as PaddedBlockCipher).doFinal(remainingInput, 0, out, outOff);
      if (forEncryption) {
        _underlyingMac.update(out, outOff, blockSize);
      } else {
        _underlyingMac.update(remainingInput, 0, blockSize);
      }
      outOff += l;
    }

    var al = new Uint8List.view((new Uint64List(1)..[0] = aad.length*8).buffer);
    al = new Uint8List.fromList(al.reversed.toList());
    _underlyingMac.update(al, 0, 8);

    _hash = new Uint8List(macSize*2);
    _underlyingMac.doFinal(_hash, 0);
    _hash = new Uint8List.view(_hash.buffer, 0, macSize);
    if (forEncryption) {
      out.setAll(outOff, _hash);
      l += _hash.length;
    }

    validateMac();

    return l;

  }

  @override
  Uint8List get mac => _hash;
}
