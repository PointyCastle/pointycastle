// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.api.rsa;

import "package:bignum/bignum.dart";
import "package:cipher/api.dart";

/// Base class for asymmetric keys in RSA
abstract class RSAAsymmetricKey implements AsymmetricKey {

  // The parameters of this key
  final BigInteger modulus;
  final BigInteger exponent;

  /// Create an asymmetric key for the given domain parameters
  RSAAsymmetricKey(this.modulus, this.exponent);

  /// Get modulus [n] = p·q
  BigInteger get n => modulus;

}

/// Private keys in RSA
class RSAPrivateKey extends RSAAsymmetricKey implements PrivateKey {

  // The secret prime factors of n
  final BigInteger p;
  final BigInteger q;

  /// Create an RSA private key for the given parameters.
  RSAPrivateKey(BigInteger modulus, BigInteger exponent, this.p, this.q) : super(modulus, exponent);

  /// Get private exponent [d] = e^-1
  BigInteger get d => exponent;

  bool operator ==( other ) {
    if( other==null ) return false;
    if( other is! RSAPrivateKey ) return false;
    return (other.n==this.n) && (other.d==this.d);
  }

  int get hashCode => modulus.hashCode+exponent.hashCode;

}

/// Public keys in RSA
class RSAPublicKey extends RSAAsymmetricKey implements PublicKey {

  /// Create an RSA public key for the given parameters.
  RSAPublicKey(BigInteger modulus, BigInteger exponent) : super(modulus, exponent);

  /// Get public exponent [e]
  BigInteger get e => exponent;

  bool operator ==( other ) {
    if( other==null ) return false;
    if( other is! RSAPublicKey ) return false;
    return (other.n==this.n) && (other.e==this.e);
  }

  int get hashCode => modulus.hashCode+exponent.hashCode;

}
