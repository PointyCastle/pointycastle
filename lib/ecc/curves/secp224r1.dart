// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.ec_domain_parameters.secp224r1;

import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/src/ec_standard_curve_constructor.dart";

class ECCurve_secp224r1 extends ECDomainParametersImpl {
  factory ECCurve_secp224r1() => constructFpStandardCurve(
      "secp224r1", ECCurve_secp224r1._make,
      q: BigInt.parse(
          "ffffffffffffffffffffffffffffffff000000000000000000000001",
          radix: 16),
      a: BigInt.parse(
          "fffffffffffffffffffffffffffffffefffffffffffffffffffffffe",
          radix: 16),
      b: BigInt.parse(
          "b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4",
          radix: 16),
      g: BigInt.parse(
          "04b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34",
          radix: 16),
      n: BigInt.parse(
          "ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d",
          radix: 16),
      h: BigInt.parse("1", radix: 16),
      seed:
          BigInt.parse("bd71344799d5c7fcdc45b59fa3b9ab8f6a948bc5", radix: 16));

  static ECCurve_secp224r1 _make(domainName, curve, G, n, _h, seed) =>
      new ECCurve_secp224r1._super(domainName, curve, G, n, _h, seed);

  ECCurve_secp224r1._super(domainName, curve, G, n, _h, seed)
      : super(domainName, curve, G, n, _h, seed);
}
