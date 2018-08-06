// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.ec_domain_parameters.brainpoolp192r1;

import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/src/ec_standard_curve_constructor.dart";

class ECCurve_brainpoolp192r1 extends ECDomainParametersImpl {
  factory ECCurve_brainpoolp192r1() => constructFpStandardCurve(
      "brainpoolp192r1", ECCurve_brainpoolp192r1._make,
      q: BigInt.parse("c302f41d932a36cda7a3463093d18db78fce476de1a86297",
          radix: 16),
      a: BigInt.parse("6a91174076b1e0e19c39c031fe8685c1cae040e5c69a28ef",
          radix: 16),
      b: BigInt.parse("469a28ef7c28cca3dc721d044f4496bcca7ef4146fbf25c9",
          radix: 16),
      g: BigInt.parse(
          "04c0a0647eaab6a48753b033c56cb0f0900a2f5c4853375fd614b690866abd5bb88b5f4828c1490002e6773fa2fa299b8f",
          radix: 16),
      n: BigInt.parse("c302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1",
          radix: 16),
      h: BigInt.parse("1", radix: 16),
      seed: null);

  static ECCurve_brainpoolp192r1 _make(domainName, curve, G, n, _h, seed) =>
      new ECCurve_brainpoolp192r1._super(domainName, curve, G, n, _h, seed);

  ECCurve_brainpoolp192r1._super(domainName, curve, G, n, _h, seed)
      : super(domainName, curve, G, n, _h, seed);
}
