// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.impl.signer.rsa_signer;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/asymmetric/api.dart";
import "package:cipher/src/registry/registry.dart";

// TODO: implement full ASN1 encoding (for now I will do a little ad-hoc implementation of just what is needed here)
class RSASigner implements Signer {

  /// Intended for internal use.
  static final FactoryConfig FACTORY_CONFIG =
      new DynamicFactoryConfig.suffix("/RSA", (String algorithmName, _) {
        int sep = algorithmName.lastIndexOf("/");
        final String digestName = algorithmName.substring(0, sep);
        final String digestIdentifierHex = _DIGEST_IDENTIFIER_HEXES[digestName];
        if (digestIdentifierHex == null) {
          throw new RegistryFactoryException(
            "RSA signing with digest $digestName is not supported");
        }
        return () => new RSASigner(new Digest(digestName), digestIdentifierHex);
      });
  
  static final Map<String, String> _DIGEST_IDENTIFIER_HEXES = {
    "MD2": "06082a864886f70d0202",
    "MD4": "06082a864886f70d0204",
    "MD5": "06082a864886f70d0205",
    "RIPEMD-128": "06052b24030202",
    "RIPEMD-160": "06052b24030201",
    "RIPEMD-256": "06052b24030203",
    "SHA-1": "06052b0e03021a",
    "SHA-224": "0609608648016503040204",
    "SHA-256": "0609608648016503040201",
    "SHA-384": "0609608648016503040202",
    "SHA-512": "0609608648016503040203"
  };

  final AsymmetricBlockCipher _rsa = new AsymmetricBlockCipher("RSA/PKCS1");
  final Digest _digest;
  Uint8List _digestIdentifier; // DER encoded with trailing tag (06)+length byte
  bool _forSigning;

  RSASigner(this._digest, String digestIdentifierHex) {
    _digestIdentifier = _hexStringToBytes(digestIdentifierHex);
  }

  String get algorithmName => "${_digest.algorithmName}/RSA";

  void reset() {
    _digest.reset();
    _rsa.reset();
  }

  void init(bool forSigning, CipherParameters params) {
    _forSigning = forSigning;

    AsymmetricKeyParameter akparams;
    if (params is ParametersWithRandom) {
      akparams = params.parameters;
    } else {
      akparams = params;
    }
    RSAAsymmetricKey k = akparams.key;

    if (forSigning && (k is! RSAPrivateKey)) {
      throw new ArgumentError("Signing requires private key");
    }

    if (!forSigning && (k is! RSAPublicKey)) {
      throw new ArgumentError("Verification requires public key");
    }

    reset();

    _rsa.init(forSigning, params);
  }

  RSASignature generateSignature(Uint8List message) {
    if (!_forSigning) {
      throw new StateError("Signer was not initialised for signature generation");
    }

    var hash = new Uint8List(_digest.digestSize);
    _digest.reset();
    _digest.update(message, 0, message.length);
    _digest.doFinal(hash, 0);

    var data = _derEncode(hash);
    var out = new Uint8List(_rsa.outputBlockSize);
    var len = _rsa.processBlock(data, 0, data.length, out, 0);
    return new RSASignature(out.sublist(0, len));
  }

  bool verifySignature(Uint8List message, RSASignature signature) {
    if (_forSigning) {
      throw new StateError("Signer was not initialised for signature verification");
    }

    var hash = new Uint8List(_digest.digestSize);
    _digest.reset();
    _digest.update(message, 0, message.length);
    _digest.doFinal(hash, 0);


    var sig = new Uint8List(_rsa.outputBlockSize);
    var len = _rsa.processBlock(signature.bytes, 0, signature.bytes.length, sig, 0);
    sig = sig.sublist(0, len);

    var expected = _derEncode(hash);

    if (sig.length == expected.length) {
      for (var i=0; i<sig.length; i++) {
        if (sig[i] != expected[i]) {
          return false;
        }
      }
      return true; //return Arrays.constantTimeAreEqual(sig, expected);

    } else if (sig.length == expected.length - 2) { // NULL left out
      var sigOffset = sig.length - hash.length - 2;
      var expectedOffset = expected.length - hash.length - 2;

      expected[1] -= 2;      // adjust lengths
      expected[3] -= 2;

      var nonEqual = 0;

      for (var i = 0; i < hash.length; i++) {
        nonEqual |= (sig[sigOffset + i] ^ expected[expectedOffset + i]);
      }

      for (int i = 0; i < sigOffset; i++) {
        nonEqual |= (sig[i] ^ expected[i]);  // check header less NULL
      }

      return nonEqual == 0;

    } else {
      return false;
    }
  }

  Uint8List _derEncode(Uint8List hash) {
    var out = new Uint8List(2+2+_digestIdentifier.length+2+2+hash.length);
    var i = 0;

    // header
    out[i++] = 48;
    out[i++] = out.length-2;

    // algorithmIdentifier.header
    out[i++] = 48;
    out[i++] = _digestIdentifier.length+2;

    // algorithmIdentifier.bytes
    out.setAll(i, _digestIdentifier);
    i += _digestIdentifier.length;

    // algorithmIdentifier.null
    out[i++] = 5;
    out[i++] = 0;

    // hash.header
    out[i++] = 4;
    out[i++] = hash.length;

    // hash.bytes
    out.setAll(i, hash);

    return out;
  }

  Uint8List _hexStringToBytes(String hex) {
    var result = new Uint8List(hex.length~/2);
    for( var i=0 ; i<hex.length ; i+=2 ) {
      var num = hex.substring(i, i+2);
      var byte = int.parse( num, radix: 16 );
      result[i~/2] = byte;
    }
    return result;
  }

}
