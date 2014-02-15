// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.signers.rsa_signer;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/api/rsa.dart";
import "package:cipher/params/parameters_with_random.dart";
import "package:cipher/params/asymmetric_key_parameter.dart";

// TODO: implement full ASN1 encoding (for now I will do a little ad-hoc implementation of just what is needed here)
class RSASigner implements Signer {

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
