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

class ECDSASigner implements Signer {

  ECPublicKey _pbkey;
  ECPrivateKey _pvkey;
  SecureRandom _random;

  String get algorithmName => "ECDSA";

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
    var n = _pvkey.parameters.n;
    var e = _calculateE(n, message);
    var r = null;
    var s = null;

    // 5.3.2
    do {// generate s
      var k = null;

      do { // generate r
        do {
          k = _random.nextBigInteger(n.bitLength());
        }
        while( k==BigInteger.ZERO || k>=n );

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

  bool verifySignature(Uint8List message, ECSignature signature) {
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
