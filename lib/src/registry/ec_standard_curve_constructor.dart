

library cipher.src.registry.ec_standard_curve_constructor;

import "package:bignum/bignum.dart";

import "package:cipher/ecc/ecc_base.dart";
import "package:cipher/ecc/ecc_fp.dart" as fp;

ECDomainParametersImpl constructFpStandardCurve( String name, {BigInteger q, BigInteger a, BigInteger b, BigInteger g, BigInteger n,
BigInteger h, BigInteger seed } ) {

  var curve = new fp.ECCurve(q,a,b);
  var seedBytes = (seed == null) ? null : seed.toByteArray();
  return new ECDomainParametersImpl( name, curve, curve.decodePoint( g.toByteArray() ), n, h, seedBytes );
}