// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.ec_domain_parameters.brainpoolp160t1;

import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/src/ec_standard_curve_constructor.dart";

class ECCurve_brainpoolp160t1 extends ECDomainParametersImpl {
  factory ECCurve_brainpoolp160t1() => constructFpStandardCurve(
      "brainpoolp160t1", ECCurve_brainpoolp160t1._make,
      q: BigInt.parse("e95e4a5f737059dc60dfc7ad95b3d8139515620f", radix: 16),
      a: BigInt.parse("e95e4a5f737059dc60dfc7ad95b3d8139515620c", radix: 16),
      b: BigInt.parse("7a556b6dae535b7b51ed2c4d7daa7a0b5c55f380", radix: 16),
      g: BigInt.parse(
          "04b199b13b9b34efc1397e64baeb05acc265ff2378add6718b7c7c1961f0991b842443772152c9e0ad",
          radix: 16),
      n: BigInt.parse("e95e4a5f737059dc60df5991d45029409e60fc09", radix: 16),
      h: BigInt.parse("1", radix: 16),
      seed: null);

  static ECCurve_brainpoolp160t1 _make(domainName, curve, G, n, _h, seed) =>
      new ECCurve_brainpoolp160t1._super(domainName, curve, G, n, _h, seed);

  ECCurve_brainpoolp160t1._super(domainName, curve, G, n, _h, seed)
      : super(domainName, curve, G, n, _h, seed);
}
