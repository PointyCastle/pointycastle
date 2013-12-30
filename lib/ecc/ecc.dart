// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.ecc.ecc;

import "dart:typed_data";

import "package:cipher/api.dart";

/// Standard curve description
class ECDomainParameters {

	/// The [Registry] for [ECDomainParameters] objects
	static final registry = new Registry<ECDomainParameters>();

	final ECCurve curve;
  final List<int> seed;
  final ECPoint G;
  final BigInteger n;
  BigInteger _h;

  factory ECDomainParameters( String standardCurveName ) => registry.create(standardCurveName);

  ECDomainParameters.fromValues( this.curve, this.G, this.n, [this._h=null, this.seed=null] ) {
		if( _h==null ) {
			_h = BigInteger.ONE;
		}
  }

	BigInteger get h => _h;

}

/// Type for coordinates of an [ECPoint]
abstract class ECFieldElement {

  BigInteger toBigInteger();
  String get fieldName;
  int get fieldSize;
  int get byteLength => ((fieldSize + 7) ~/ 8);

  ECFieldElement operator +( ECFieldElement b );
  ECFieldElement operator -( ECFieldElement b );
  ECFieldElement operator *( ECFieldElement b );
  ECFieldElement operator /( ECFieldElement b );

  ECFieldElement operator -(); //ECFieldElement negate();

  ECFieldElement invert();
  ECFieldElement square();
  ECFieldElement sqrt();

  String toString() => toBigInteger().toString();//toBigInteger().toString(2);

}

/// An elliptic curve point
abstract class ECPoint {

  final ECCurve curve;
  final ECFieldElement x;
  final ECFieldElement y;
  final bool isCompressed;
  final ECMultiplier _multiplier;

  PreCompInfo _preCompInfo;

  ECPoint( this.curve, this.x, this.y, this.isCompressed, [this._multiplier=_FpNafMultiplier] );

  bool get isInfinity => (x == null && y == null);

  void set preCompInfo( PreCompInfo preCompInfo ) {
    _preCompInfo = preCompInfo;
  }

  bool operator ==(other) {
    if( other is ECPoint ) {
      if( isInfinity ) {
        return other.isInfinity;
      }
      return x==other.x && y==other.y;
    }
    return false;
  }

  String toString() => "($x,$y)";

  int get hashCode {
    if( isInfinity ){
        return 0;
    }
    return x.hashCode ^ y.hashCode;
  }

  Uint8List getEncoded([bool compressed = true]);

  ECPoint operator +(ECPoint b);
  ECPoint operator -(ECPoint b);
  ECPoint operator -();

  ECPoint twice();

  /**
   * Multiplies this <code>ECPoint</code> by the given number.
   * @param k The multiplicator.
   * @return <code>k * this</code>.
   */
  ECPoint operator *(BigInteger k) {
    if( k.signum() < 0 ) {
      throw new ArgumentError("The multiplicator cannot be negative");
    }

    if( isInfinity ) {
      return this;
    }

    if( k.signum() == 0 ) {
      return curve.infinity;
    }

    return _multiplier( this, k, _preCompInfo );
  }

}

/// An elliptic curve
abstract class ECCurve {

  ECFieldElement _a;
  ECFieldElement _b;

  ECCurve( BigInteger a , BigInteger b ) {
    this._a = fromBigInteger(a);
    this._b = fromBigInteger(b);
  }

  ECFieldElement get a => _a;
  ECFieldElement get b => _b;

  int get fieldSize;
  ECPoint get infinity;

  ECFieldElement fromBigInteger( BigInteger x );
  ECPoint createPoint( BigInteger x, BigInteger y, [bool withCompression=false] );
  ECPoint decompressPoint( int yTilde, BigInteger X1 );

  /**
   * Decode a point on this curve from its ASN.1 encoding. The different
   * encodings are taken account of, including point compression for
   * <code>F<sub>p</sub></code> (X9.62 s 4.2.1 pg 17).
   * @return The decoded point.
   */
  ECPoint decodePoint( List<int> encoded ) {
      ECPoint p = null;
      int expectedLength = (fieldSize + 7) ~/ 8;

      switch( encoded[0] ) {
        case 0x00: // infinity
            if (encoded.length != 1) {
                throw new ArgumentError("Incorrect length for infinity encoding");
            }

            p = infinity;
            break;

        case 0x02: // compressed
        case 0x03: // compressed
            if (encoded.length != (expectedLength + 1)) {
                throw new ArgumentError("Incorrect length for compressed encoding");
            }

            int yTilde = encoded[0] & 1;
            var X1 = _fromArray( encoded, 1, expectedLength );

            p = decompressPoint(yTilde, X1);
            break;

        case 0x04: // uncompressed
        case 0x06: // hybrid
        case 0x07: // hybrid
            if (encoded.length != (2 * expectedLength + 1)) {
                throw new ArgumentError("Incorrect length for uncompressed/hybrid encoding");
            }

            BigInteger X1 = _fromArray(encoded, 1, expectedLength);
            BigInteger Y1 = _fromArray(encoded, 1 + expectedLength, expectedLength);

            p = createPoint(X1, Y1, false);
            break;

        default:
            throw new ArgumentError("Invalid point encoding 0x" + encoded[0].toRadixString(16) );
      }

      return p;
  }

  BigInteger _fromArray( List<int> buf, int off, int length ) {
    return new BigInteger.fromBytes(1, buf.sublist(off, off+length));
  }

}

/// Interface for classes storing precomputation data for multiplication algorithms.
abstract class PreCompInfo {
}

/**
 * Interface for functions encapsulating a point multiplication algorithm for [ECPoint]. Multiplies [p] by [k], i.e. [p] is
 * added [k] times to itself.
 */
typedef ECPoint ECMultiplier( ECPoint p, BigInteger k, PreCompInfo preCompInfo );

/// Function implementing the NAF (Non-Adjacent Form) multiplication algorithm.
ECPoint _FpNafMultiplier(ECPoint p, BigInteger k, PreCompInfo preCompInfo) {
    // TODO Probably should try to add this
    // BigInteger e = k.mod(n); // n == order of p
    BigInteger e = k;
    BigInteger h = e*BigInteger.THREE;

    ECPoint neg = -p;
    ECPoint R = p;

    for( var i=h.bitLength()-2 ; i>0 ; --i ) {
      R = R.twice();

      var hBit = h.testBit(i);
      var eBit = e.testBit(i);

      if( hBit!=eBit ) {
          R += (hBit ? p : neg);
      }
    }

    return R;
}
