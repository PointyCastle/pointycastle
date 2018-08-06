// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.ec_domain_parameters.brainpoolp320t1;

import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/src/ec_standard_curve_constructor.dart";

class ECCurve_brainpoolp320t1 extends ECDomainParametersImpl {
  factory ECCurve_brainpoolp320t1() => constructFpStandardCurve(
      "brainpoolp320t1", ECCurve_brainpoolp320t1._make,
      q: BigInt.parse(
          "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27",
          radix: 16),
      a: BigInt.parse(
          "d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e24",
          radix: 16),
      b: BigInt.parse(
          "a7f561e038eb1ed560b3d147db782013064c19f27ed27c6780aaf77fb8a547ceb5b4fef422340353",
          radix: 16),
      g: BigInt.parse(
          "04925be9fb01afc6fb4d3e7d4990010f813408ab106c4f09cb7ee07868cc136fff3357f624a21bed5263ba3a7a27483ebf6671dbef7abb30ebee084e58a0b077ad42a5a0989d1ee71b1b9bc0455fb0d2c3",
          radix: 16),
      n: BigInt.parse(
          "d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311",
          radix: 16),
      h: BigInt.parse("1", radix: 16),
      seed: null);

  static ECCurve_brainpoolp320t1 _make(domainName, curve, G, n, _h, seed) =>
      new ECCurve_brainpoolp320t1._super(domainName, curve, G, n, _h, seed);

  ECCurve_brainpoolp320t1._super(domainName, curve, G, n, _h, seed)
      : super(domainName, curve, G, n, _h, seed);
}
