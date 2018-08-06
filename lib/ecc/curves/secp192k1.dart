// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.ec_domain_parameters.secp192k1;

import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/src/ec_standard_curve_constructor.dart";

class ECCurve_secp192k1 extends ECDomainParametersImpl {
  factory ECCurve_secp192k1() => constructFpStandardCurve(
      "secp192k1", ECCurve_secp192k1._make,
      q: BigInt.parse("fffffffffffffffffffffffffffffffffffffffeffffee37",
          radix: 16),
      a: BigInt.parse("0", radix: 16),
      b: BigInt.parse("3", radix: 16),
      g: BigInt.parse(
          "04db4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d",
          radix: 16),
      n: BigInt.parse("fffffffffffffffffffffffe26f2fc170f69466a74defd8d",
          radix: 16),
      h: BigInt.parse("1", radix: 16),
      seed: null);

  static ECCurve_secp192k1 _make(domainName, curve, G, n, _h, seed) =>
      new ECCurve_secp192k1._super(domainName, curve, G, n, _h, seed);

  ECCurve_secp192k1._super(domainName, curve, G, n, _h, seed)
      : super(domainName, curve, G, n, _h, seed);
}
