// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.ec_domain_parameters.brainpoolp224t1;

import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/src/ec_standard_curve_constructor.dart";

class ECCurve_brainpoolp224t1 extends ECDomainParametersImpl {
  factory ECCurve_brainpoolp224t1() => constructFpStandardCurve(
      "brainpoolp224t1", ECCurve_brainpoolp224t1._make,
      q: BigInt.parse(
          "d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff",
          radix: 16),
      a: BigInt.parse(
          "d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0fc",
          radix: 16),
      b: BigInt.parse(
          "4b337d934104cd7bef271bf60ced1ed20da14c08b3bb64f18a60888d",
          radix: 16),
      g: BigInt.parse(
          "046ab1e344ce25ff3896424e7ffe14762ecb49f8928ac0c76029b4d5800374e9f5143e568cd23f3f4d7c0d4b1e41c8cc0d1c6abd5f1a46db4c",
          radix: 16),
      n: BigInt.parse(
          "d7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f",
          radix: 16),
      h: BigInt.parse("1", radix: 16),
      seed: null);

  static ECCurve_brainpoolp224t1 _make(domainName, curve, G, n, _h, seed) =>
      new ECCurve_brainpoolp224t1._super(domainName, curve, G, n, _h, seed);

  ECCurve_brainpoolp224t1._super(domainName, curve, G, n, _h, seed)
      : super(domainName, curve, G, n, _h, seed);
}
