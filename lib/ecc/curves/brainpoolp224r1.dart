// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.ec_domain_parameters.brainpoolp224r1;

import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/src/ec_standard_curve_constructor.dart";

class ECCurve_brainpoolp224r1 extends ECDomainParametersImpl {
  factory ECCurve_brainpoolp224r1() => constructFpStandardCurve(
      "brainpoolp224r1", ECCurve_brainpoolp224r1._make,
      q: BigInt.parse(
          "d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff",
          radix: 16),
      a: BigInt.parse(
          "68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43",
          radix: 16),
      b: BigInt.parse(
          "2580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400b",
          radix: 16),
      g: BigInt.parse(
          "040d9029ad2c7e5cf4340823b2a87dc68c9e4ce3174c1e6efdee12c07d58aa56f772c0726f24c6b89e4ecdac24354b9e99caa3f6d3761402cd",
          radix: 16),
      n: BigInt.parse(
          "d7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f",
          radix: 16),
      h: BigInt.parse("1", radix: 16),
      seed: null);

  static ECCurve_brainpoolp224r1 _make(domainName, curve, G, n, _h, seed) =>
      new ECCurve_brainpoolp224r1._super(domainName, curve, G, n, _h, seed);

  ECCurve_brainpoolp224r1._super(domainName, curve, G, n, _h, seed)
      : super(domainName, curve, G, n, _h, seed);
}
