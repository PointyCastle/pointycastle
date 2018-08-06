// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.ec_domain_parameters.prime239v1;

import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/src/ec_standard_curve_constructor.dart";

class ECCurve_prime239v1 extends ECDomainParametersImpl {
  factory ECCurve_prime239v1() => constructFpStandardCurve(
      "prime239v1", ECCurve_prime239v1._make,
      q: BigInt.parse(
          "7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff",
          radix: 16),
      a: BigInt.parse(
          "7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc",
          radix: 16),
      b: BigInt.parse(
          "6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a",
          radix: 16),
      g: BigInt.parse(
          "020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf",
          radix: 16),
      n: BigInt.parse(
          "7fffffffffffffffffffffff7fffff9e5e9a9f5d9071fbd1522688909d0b",
          radix: 16),
      h: BigInt.parse("1", radix: 16),
      seed:
          BigInt.parse("e43bb460f0b80cc0c0b075798e948060f8321b7d", radix: 16));

  static ECCurve_prime239v1 _make(domainName, curve, G, n, _h, seed) =>
      new ECCurve_prime239v1._super(domainName, curve, G, n, _h, seed);

  ECCurve_prime239v1._super(domainName, curve, G, n, _h, seed)
      : super(domainName, curve, G, n, _h, seed);
}
