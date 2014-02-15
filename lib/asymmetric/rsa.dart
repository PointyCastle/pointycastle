// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.asymmetric.rsa;

import "dart:typed_data";

import "package:bignum/bignum.dart";
import "package:cipher/api/rsa.dart";
import "package:cipher/params/asymmetric_key_parameter.dart";
import "package:cipher/asymmetric/base_asymmetric_block_cipher.dart";

class RSAEngine extends BaseAsymmetricBlockCipher {

  RSAAsymmetricKey _key;
  bool _forEncryption;

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

  BigInteger _processBigInteger(BigInteger input) => input.modPow(_key.exponent, _key.modulus);


  // TODO: make use of Chinese Remainder Theorem
  /*
  CRT: calculate dP, dQ, etc. inside init and cache them
    // calculate the CRT factors
    var pSub1 = (p - BigInteger.ONE);
    var qSub1 = (q - BigInteger.ONE);
    var dP = d.remainder(pSub1);
    var dQ = d.remainder(qSub1);
    var qInv = q.modInverse(p);

    var dP = d.remainder(pSub1);
    var dQ = d.remainder(qSub1);
    var qInv = q.modInverse(p);
  */

  /*
  CRT: use it in _processBigInteger()
  if (key is RSAPrivateCrtKeyParameters)
  {
      //
      // we have the extra factors, use the Chinese Remainder Theorem - the author
      // wishes to express his thanks to Dirk Bonekaemper at rtsffm.com for
      // advice regarding the expression of this.
      //
      RSAPrivateCrtKeyParameters crtKey = (RSAPrivateCrtKeyParameters)key;

      BigInteger p = crtKey.getP();
      BigInteger q = crtKey.getQ();
      BigInteger dP = crtKey.getDP();
      BigInteger dQ = crtKey.getDQ();
      BigInteger qInv = crtKey.getQInv();

      BigInteger mP, mQ, h, m;

      // mP = ((input mod p) ^ dP)) mod p
      mP = (input.remainder(p)).modPow(dP, p);

      // mQ = ((input mod q) ^ dQ)) mod q
      mQ = (input.remainder(q)).modPow(dQ, q);

      // h = qInv * (mP - mQ) mod p
      h = mP.subtract(mQ);
      h = h.multiply(qInv);
      h = h.mod(p);               // mod (in Java) returns the positive residual

      // m = h * q + mQ
      m = h.multiply(q);
      m = m.add(mQ);

      return m;
  }
  else
  {
      return input.modPow(_key.exponent, _key.modulus);
  }
  */
}
