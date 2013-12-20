// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.signers.ecdsa_signer;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/params/ec_key_parameters.dart";
import "package:cipher/params/parameters_with_random.dart";

class ECDSASigner implements Signer {

  ECPublicKeyParameters _pbkey;
  ECPrivateKeyParameters _pvkey;
  SecureRandom _random;

  String get algorithmName => "ECDSA";

  void reset() {
    // TODO implement this method
  }

  /**
   * Init this [Signer]. The [params] argument can be:
   * -A [ParametersWithRandom] containing an [ECPrivateKeyParameters] or an [ECPrivateKeyParameters] for signing
   * -An [ECPublicKeyParameters] for verifying.
   */
  void init(bool forSigning, CipherParameters params) {
    _pbkey = _pvkey = null;

    if (forSigning) {
      if( params is ParametersWithRandom ) {
        _random = params.random;
        _pvkey = params.parameters;
      } else {
        _random = new SecureRandom();
        _pvkey = params;
      }
      if( !(_pvkey is ECPrivateKeyParameters) ) {
        throw new ArgumentError("Unsupported parameters type ${_pvkey.runtimeType}: should be ECPrivateKeyParameters");
      }
    } else {
      _pbkey = params;
      if( !(_pbkey is ECPublicKeyParameters) ) {
        throw new ArgumentError("Unsupported parameters type ${_pvkey.runtimeType}: should be ECPublicKeyParameters");
      }
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

    return new Signature(r,s);
  }

  bool verifySignature(Uint8List message, Signature signature) {
    // TODO implement this method
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



















/* TODO:
  // 5.4 pg 29
  /**
   * return true if the value r and s represent a DSA signature for
   * the passed in message (for standard DSA the message should be
   * a SHA-1 hash of the real message to be verified).
   */
  public boolean verifySignature(
                                 byte[]      message,
                                 BigInteger  r,
                                 BigInteger  s)
  {
    BigInteger n = key.getParameters().getN();
    BigInteger e = calculateE(n, message);

    // r in the range [1,n-1]
    if (r.compareTo(ONE) < 0 || r.compareTo(n) >= 0)
    {
      return false;
    }

    // s in the range [1,n-1]
    if (s.compareTo(ONE) < 0 || s.compareTo(n) >= 0)
    {
      return false;
    }

    BigInteger c = s.modInverse(n);

    BigInteger u1 = e.multiply(c).mod(n);
    BigInteger u2 = r.multiply(c).mod(n);

    ECPoint G = key.getParameters().getG();
    ECPoint Q = ((ECPublicKeyParameters)key).getQ();

    ECPoint point = ECAlgorithms.sumOfTwoMultiplies(G, u1, Q, u2);

    // components must be bogus.
    if (point.isInfinity())
    {
      return false;
    }

    BigInteger v = point.getX().toBigInteger().mod(n);

    return v.equals(r);
  }

*/



}
