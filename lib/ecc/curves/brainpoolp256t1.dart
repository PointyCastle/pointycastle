// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.ec_domain_parameters.brainpoolp256t1;

import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/src/ec_standard_curve_constructor.dart";

class ECCurve_brainpoolp256t1 extends ECDomainParametersImpl {
  factory ECCurve_brainpoolp256t1() => constructFpStandardCurve(
      "brainpoolp256t1", ECCurve_brainpoolp256t1._make,
      q: BigInt.parse(
          "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377",
          radix: 16),
      a: BigInt.parse(
          "a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5374",
          radix: 16),
      b: BigInt.parse(
          "662c61c430d84ea4fe66a7733d0b76b7bf93ebc4af2f49256ae58101fee92b04",
          radix: 16),
      g: BigInt.parse(
          "04a3e8eb3cc1cfe7b7732213b23a656149afa142c47aafbc2b79a191562e1305f42d996c823439c56d7f7b22e14644417e69bcb6de39d027001dabe8f35b25c9be",
          radix: 16),
      n: BigInt.parse(
          "a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7",
          radix: 16),
      h: BigInt.parse("1", radix: 16),
      seed: null);

  static ECCurve_brainpoolp256t1 _make(domainName, curve, G, n, _h, seed) =>
      new ECCurve_brainpoolp256t1._super(domainName, curve, G, n, _h, seed);

  ECCurve_brainpoolp256t1._super(domainName, curve, G, n, _h, seed)
      : super(domainName, curve, G, n, _h, seed);
}
