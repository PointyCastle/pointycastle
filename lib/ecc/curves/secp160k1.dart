// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.ec_domain_parameters.secp160k1;

import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/src/ec_standard_curve_constructor.dart";

class ECCurve_secp160k1 extends ECDomainParametersImpl {
  factory ECCurve_secp160k1() => constructFpStandardCurve(
      "secp160k1", ECCurve_secp160k1._make,
      q: BigInt.parse("fffffffffffffffffffffffffffffffeffffac73", radix: 16),
      a: BigInt.parse("0", radix: 16),
      b: BigInt.parse("7", radix: 16),
      g: BigInt.parse(
          "043b4c382ce37aa192a4019e763036f4f5dd4d7ebb938cf935318fdced6bc28286531733c3f03c4fee",
          radix: 16),
      n: BigInt.parse("100000000000000000001b8fa16dfab9aca16b6b3", radix: 16),
      h: BigInt.parse("1", radix: 16),
      seed: null);

  static ECCurve_secp160k1 _make(domainName, curve, G, n, _h, seed) =>
      new ECCurve_secp160k1._super(domainName, curve, G, n, _h, seed);

  ECCurve_secp160k1._super(domainName, curve, G, n, _h, seed)
      : super(domainName, curve, G, n, _h, seed);
}
