// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.ec_domain_parameters.secp160r1;

import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/src/ec_standard_curve_constructor.dart";

class ECCurve_secp160r1 extends ECDomainParametersImpl {
  factory ECCurve_secp160r1() => constructFpStandardCurve(
      "secp160r1", ECCurve_secp160r1._make,
      q: BigInt.parse("ffffffffffffffffffffffffffffffff7fffffff", radix: 16),
      a: BigInt.parse("ffffffffffffffffffffffffffffffff7ffffffc", radix: 16),
      b: BigInt.parse("1c97befc54bd7a8b65acf89f81d4d4adc565fa45", radix: 16),
      g: BigInt.parse(
          "044a96b5688ef573284664698968c38bb913cbfc8223a628553168947d59dcc912042351377ac5fb32",
          radix: 16),
      n: BigInt.parse("100000000000000000001f4c8f927aed3ca752257", radix: 16),
      h: BigInt.parse("1", radix: 16),
      seed:
          BigInt.parse("1053cde42c14d696e67687561517533bf3f83345", radix: 16));

  static ECCurve_secp160r1 _make(domainName, curve, G, n, _h, seed) =>
      new ECCurve_secp160r1._super(domainName, curve, G, n, _h, seed);

  ECCurve_secp160r1._super(domainName, curve, G, n, _h, seed)
      : super(domainName, curve, G, n, _h, seed);
}
