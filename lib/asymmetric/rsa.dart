// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.asymmetric.rsa;

import "dart:typed_data";

import "package:bignum/bignum.dart";

import "package:cipher/api.dart";
import "package:cipher/asymmetric/base_asymmetric_block_cipher.dart";
import "package:cipher/asymmetric/api.dart";

class RSAEngine extends BaseAsymmetricBlockCipher {

  bool _forEncryption;
  RSAAsymmetricKey _key;
  BigInteger _dP;
  BigInteger _dQ;
  BigInteger _qInv;

  String get algorithmName => "RSA";

  int get inputBlockSize {
    if (_key==null) {
      throw new StateError("Input block size cannot be calculated until init() called");
    }

    var bitSize = _key.modulus.bitLength();
    if (_forEncryption) {
      return ((bitSize + 7) ~/ 8) - 1;
    } else {
      return (bitSize + 7) ~/ 8;
    }
  }

  int get outputBlockSize {
    if (_key==null) {
      throw new StateError("Output block size cannot be calculated until init() called");
    }

    var bitSize = _key.modulus.bitLength();
    if (_forEncryption) {
      return (bitSize + 7) ~/ 8;
    } else {
      return ((bitSize + 7) ~/ 8) - 1;
    }
  }

  void reset() {
  }

  void init(bool forEncryption, AsymmetricKeyParameter<RSAAsymmetricKey> params) {
    _forEncryption = forEncryption;
    _key = params.key;

    if (_key is RSAPrivateKey) {
      var privKey = (_key as RSAPrivateKey);
      var pSub1 = (privKey.p - BigInteger.ONE);
      var qSub1 = (privKey.q - BigInteger.ONE);
      _dP = privKey.d.remainder(pSub1);
      _dQ = privKey.d.remainder(qSub1);
      _qInv = privKey.q.modInverse(privKey.p);
    }
  }

  int processBlock(Uint8List inp, int inpOff, int len, Uint8List out, int outOff) {
    var input = _convertInput(inp, inpOff, len);
    var output = _processBigInteger(input);
    return _convertOutput(output, out, outOff);
  }


  BigInteger _convertInput(Uint8List inp, int inpOff, int len) {
    var inpLen = inp.length;

    if (inpLen > (inputBlockSize + 1)) {
       throw new ArgumentError("Input too large for RSA cipher");
    }

    if ((inpLen == (inputBlockSize + 1)) && !_forEncryption) {
      throw new ArgumentError("Input too large for RSA cipher");
    }

    var res = new BigInteger.fromBytes(1, inp.sublist(inpOff, inpOff+len));
    if (res >= _key.modulus) {
      throw new ArgumentError("Input too large for RSA cipher");
    }

    return res;
  }

  int _convertOutput(BigInteger result, Uint8List out, int outOff) {
    final output = result.toByteArray();

    if (_forEncryption) {
      if ((output[0] == 0) && (output.length > outputBlockSize)) { // have ended up with an extra zero byte, copy down.
        var len = (output.length - 1);
        out.setRange(outOff, outOff+len, output.sublist(1));
        return len;
      }
      if (output.length < outputBlockSize) { // have ended up with less bytes than normal, lengthen
        var len = outputBlockSize;
        out.setRange((outOff + len - output.length), (outOff + len), output);
        return len;
      }
    }
    else
    {
      if (output[0] == 0) { // have ended up with an extra zero byte, copy down.
        var len = (output.length - 1);
        out.setRange(outOff, outOff+len, output.sublist(1));
        return len;
      }
    }

    out.setAll(outOff, output);
    return output.length;
  }

  BigInteger _processBigInteger(BigInteger input) {
    if (_key is RSAPrivateKey) {
      var privKey = (_key as RSAPrivateKey);
      var mP, mQ, h, m;

      mP = (input.remainder(privKey.p)).modPow(_dP, privKey.p);

      mQ = (input.remainder(privKey.q)).modPow(_dQ, privKey.q);

      h = mP.subtract(mQ);
      h = h.multiply(_qInv);
      h = h.mod(privKey.p);

      m = h.multiply(privKey.q);
      m = m.add(mQ);

      return m;
    } else {
      return input.modPow(_key.exponent, _key.modulus);
    }
  }

}
