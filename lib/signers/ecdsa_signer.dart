// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.signers.ecdsa_signer;

import "dart:typed_data";
import "dart:math";

import 'package:bignum/bignum.dart';

import "package:cipher/api.dart";
import "package:cipher/api/ecc.dart";
import "package:cipher/params/asymmetric_key_parameter.dart";
import "package:cipher/params/parameters_with_random.dart";
import "package:cipher/params/key_parameter.dart";

class ECDSASigner implements Signer {

  ECPublicKey _pbkey;
  ECPrivateKey _pvkey;
  SecureRandom _random;
  bool _deterministic;
  Digest _digest;

  /// If [_deterministic] is true, RFC 6979 is used for k calculation.
  ECDSASigner(this._digest, [this._deterministic=false]);

  String get algorithmName => "${_digest.algorithmName}/${_deterministic ? "DET-" : ""}ECDSA";

  void reset() {
  }

  /**
   * Init this [Signer]. The [params] argument can be:
   * -A [ParametersWithRandom] containing an [ECPrivateKeyParameters] or an [ECPrivateKeyParameters] for signing
   * -An [ECPublicKeyParameters] for verifying.
   */
  void init(bool forSigning, CipherParameters params) {
    _pbkey = _pvkey = null;

    if (forSigning) {
      PrivateKeyParameter pvparams;

      if( params is ParametersWithRandom ) {
        _random = params.random;
        pvparams = params.parameters;
      } else {
        _random = new SecureRandom();
        pvparams = params;
      }

      if( pvparams is! PrivateKeyParameter ) {
        throw new ArgumentError("Unsupported parameters type ${pvparams.runtimeType}: should be PrivateKeyParameter");
      }
      _pvkey = pvparams.key;

    } else {
      PublicKeyParameter pbparams;

      pbparams = params;

      if( pbparams is! PublicKeyParameter ) {
        throw new ArgumentError("Unsupported parameters type ${pbparams.runtimeType}: should be PublicKeyParameter");
      }
      _pbkey = pbparams.key;
    }
  }

  Signature generateSignature(Uint8List message) {
    message = _hashMessage(message);

    var n = _pvkey.parameters.n;
    var e = _calculateE(n, message);
    var r = null;
    var s = null;

    var kCalculator;
    if (_deterministic) {
      kCalculator = new _RFC6979KCalculator(_digest, n, _pvkey.d, message);
    } else {
      kCalculator = new _RandomKCalculator(n, _random);
    }

    // 5.3.2
    do {// generate s
      var k = null;

      do { // generate r
        k = kCalculator.nextK();

        var p = _pvkey.parameters.G*k;

        // 5.3.3
        var x = p.x.toBigInteger();

        r = x%n;
      } while( r==BigInteger.ZERO );

      var d = _pvkey.d;

      s = (k.modInverse(n)*(e+(d*r)))%n;

    } while( s==BigInteger.ZERO );

    return new ECSignature(r,s);
  }

  Uint8List _hashMessage(Uint8List message) {
    _digest.reset();
    return _digest.process(message);
  }

  bool verifySignature(Uint8List message, ECSignature signature) {
    message = _hashMessage(message);

    var n = _pbkey.parameters.n;
    var e = _calculateE(n, message);

    var r = signature.r;
    var s = signature.s;

    // r in the range [1,n-1]
    if( r.compareTo(BigInteger.ONE) < 0 || r.compareTo(n) >= 0 ) {
      return false;
    }

    // s in the range [1,n-1]
    if( s.compareTo(BigInteger.ONE) < 0 || s.compareTo(n) >= 0 ) {
      return false;
    }

    var c = s.modInverse(n);

    var u1 = e.multiply(c).mod(n);
    var u2 = r.multiply(c).mod(n);

    var G = _pbkey.parameters.G;
    var Q = _pbkey.Q;

    var point = _sumOfTwoMultiplies(G, u1, Q, u2);

    // components must be bogus.
    if( point.isInfinity ) {
      return false;
    }

    var v = point.x.toBigInteger().mod(n);

    return v==r;
  }

  BigInteger _calculateE(BigInteger n, Uint8List message) {
    var log2n = n.bitLength();
    var messageBitLength = message.length * 8;

    if( log2n >= messageBitLength ) {
      return new BigInteger.fromBytes( 1, message );
    } else {
      BigInteger trunc = new BigInteger.fromBytes(1, message);

      trunc = trunc >> (messageBitLength - log2n);

      return trunc;
    }
  }

  ECPoint _sumOfTwoMultiplies( ECPoint P, BigInteger a, ECPoint Q, BigInteger b ) {
    ECCurve c = P.curve;

    if( c!=Q.curve ) {
      throw new ArgumentError("P and Q must be on same curve");
    }

    // Point multiplication for Koblitz curves (using WTNAF) beats Shamir's trick
    /* TODO: uncomment this when F2m available
    if( c is ECCurve.F2m ) {
      ECCurve.F2m f2mCurve = (ECCurve.F2m)c;
      if( f2mCurve.isKoblitz() ) {
        return P.multiply(a).add(Q.multiply(b));
      }
    }
    */

    return _implShamirsTrick(P, a, Q, b);
  }

  ECPoint _implShamirsTrick(ECPoint P, BigInteger k, ECPoint Q, BigInteger l) {
    int m = max(k.bitLength(), l.bitLength());

    ECPoint Z = P+Q;
    ECPoint R = P.curve.infinity;

    for( int i=m-1 ; i>=0 ; --i ) {
      R = R.twice();

      if( k.testBit(i) ) {
        if( l.testBit(i) ) {
          R = R+Z;
        } else {
          R = R+P;
        }
      } else {
        if (l.testBit(i)) {
          R = R+Q;
        }
      }
    }

    return R;
  }

}

class _RFC6979KCalculator {

  Mac _mac;
  Uint8List _K;
  Uint8List _V;
  BigInteger _n;

  _RFC6979KCalculator(Digest digest, this._n, BigInteger d, Uint8List message) {
    _mac = new Mac("${digest.algorithmName}/HMAC");
    _V = new Uint8List(_mac.macSize);
    _K = new Uint8List(_mac.macSize);
    _init(d, message);
  }

  void _init(BigInteger d, Uint8List message) {
    _V.fillRange(0, _V.length, 0x01);
    _K.fillRange(0, _K.length, 0x00);

    var x = new Uint8List((_n.bitLength() + 7) ~/ 8);
    var dVal = _asUnsignedByteArray(d);

    x.setRange((x.length - dVal.length), x.length, dVal);

    var m = new Uint8List((_n.bitLength() + 7) ~/ 8);

    var mInt = _bitsToInt(message);

    if (mInt > _n) {
      mInt -= _n;
    }

    var mVal = _asUnsignedByteArray(mInt);

    m.setRange((m.length - mVal.length), m.length, mVal);

    _mac.init(new KeyParameter(_K));

    _mac.update(_V, 0, _V.length);
    _mac.updateByte(0x00);
    _mac.update(x, 0, x.length);
    _mac.update(m, 0, m.length);
    _mac.doFinal(_K, 0);

    _mac.init(new KeyParameter(_K));
    _mac.update(_V, 0, _V.length);
    _mac.doFinal(_V, 0);

    _mac.update(_V, 0, _V.length);
    _mac.updateByte(0x01);
    _mac.update(x, 0, x.length);
    _mac.update(m, 0, m.length);
    _mac.doFinal(_K, 0);

    _mac.init(new KeyParameter(_K));
    _mac.update(_V, 0, _V.length);
    _mac.doFinal(_V, 0);
  }

  BigInteger nextK() {
    var t = new Uint8List((_n.bitLength() + 7) ~/ 8);

    for (;;) {
      var tOff = 0;

      while (tOff < t.length) {
        _mac.update(_V, 0, _V.length);
        _mac.doFinal(_V, 0);

        if ((t.length - tOff) < _V.length) {
          t.setRange(tOff, t.length, _V);
          tOff += (t.length - tOff);
        } else {
          t.setRange(tOff, tOff + _V.length, _V);
          tOff += _V.length;
        }
      }

      var k = _bitsToInt(t);

      if ((k == 0) || (k >= _n)) {
        _mac.update(_V, 0, _V.length);
        _mac.updateByte(0x00);
        _mac.doFinal(_K, 0);

        _mac.init(new KeyParameter(_K));
        _mac.update(_V, 0, _V.length);
        _mac.doFinal(_V, 0);
      } else {
        return k;
      }
    }
  }

  BigInteger _bitsToInt(Uint8List t) {
    var v = new BigInteger.fromBytes(1, t);
    if ((t.length * 8) > _n.bitLength()) {
      v = v >> ((t.length * 8) - _n.bitLength());
    }

    return v;
  }


  Uint8List _asUnsignedByteArray(BigInteger value) {
    var bytes = value.toByteArray();

    if (bytes[0] == 0) {
      return new Uint8List.fromList(bytes.sublist(1));
    } else {
      return new Uint8List.fromList(bytes);
    }
  }

}

class _RandomKCalculator {

  BigInteger _n;
  SecureRandom _random;

  _RandomKCalculator(this._n, this._random);

  BigInteger nextK() {
    var k;
    do {
      k = _random.nextBigInteger(_n.bitLength());
    }
    while( k==BigInteger.ZERO || k>=_n );
    return k;
  }

}




String formatBytesAsHexString(Uint8List bytes) {
  var result = new StringBuffer();
  for( var i=0 ; i<bytes.lengthInBytes ; i++ ) {
    var part = bytes[i];
    result.write('${part < 16 ? '0' : ''}${part.toRadixString(16)}');
  }
  return result.toString();
}
