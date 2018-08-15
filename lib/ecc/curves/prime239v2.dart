// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.ec_domain_parameters.prime239v2;

import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/src/ec_standard_curve_constructor.dart";

class ECCurve_prime239v2 extends ECDomainParametersImpl {
  factory ECCurve_prime239v2() => constructFpStandardCurve(
      "prime239v2", ECCurve_prime239v2._make,
      q: BigInt.parse(
          "7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff",
          radix: 16),
      a: BigInt.parse(
          "7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc",
          radix: 16),
      b: BigInt.parse(
          "617fab6832576cbbfed50d99f0249c3fee58b94ba0038c7ae84c8c832f2c",
          radix: 16),
      g: BigInt.parse(
          "0238af09d98727705120c921bb5e9e26296a3cdcf2f35757a0eafd87b830e7",
          radix: 16),
      n: BigInt.parse(
          "7fffffffffffffffffffffff800000cfa7e8594377d414c03821bc582063",
          radix: 16),
      h: BigInt.parse("1", radix: 16),
      seed:
          BigInt.parse("e8b4011604095303ca3b8099982be09fcb9ae616", radix: 16));

  static ECCurve_prime239v2 _make(domainName, curve, G, n, _h, seed) =>
      new ECCurve_prime239v2._super(domainName, curve, G, n, _h, seed);

  ECCurve_prime239v2._super(domainName, curve, G, n, _h, seed)
      : super(domainName, curve, G, n, _h, seed);
}
