

library pointycastle.src.registry.ec_standard_curve_constructor;

import "package:bignum/bignum.dart";

import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/ecc/ecc_fp.dart" as fp;

ECDomainParametersImpl constructFpStandardCurve( String name, Function constructor,
  {BigInteger q, BigInteger a, BigInteger b, BigInteger g, BigInteger n,
BigInteger h, BigInteger seed } ) {

  var curve = new fp.ECCurve(q,a,b);
  var seedBytes = (seed == null) ? null : seed.toByteArray();
  return constructor( name, curve, curve.decodePoint( g.toByteArray() ), n, h, seedBytes );
}