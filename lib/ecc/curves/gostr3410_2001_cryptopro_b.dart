// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.ec_domain_parameters.gostr3410_2001_cryptopro_b;

import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/src/ec_standard_curve_constructor.dart";

class ECCurve_gostr3410_2001_cryptopro_b extends ECDomainParametersImpl {
  factory ECCurve_gostr3410_2001_cryptopro_b() => constructFpStandardCurve(
      "GostR3410-2001-CryptoPro-B", ECCurve_gostr3410_2001_cryptopro_b._make,
      q: BigInt.parse(
          "8000000000000000000000000000000000000000000000000000000000000c99",
          radix: 16),
      a: BigInt.parse(
          "8000000000000000000000000000000000000000000000000000000000000c96",
          radix: 16),
      b: BigInt.parse(
          "3e1af419a269a5f866a7d3c25c3df80ae979259373ff2b182f49d4ce7e1bbc8b",
          radix: 16),
      g: BigInt.parse(
          "0400000000000000000000000000000000000000000000000000000000000000013fa8124359f96680b83d1c3eb2c070e5c545c9858d03ecfb744bf8d717717efc",
          radix: 16),
      n: BigInt.parse(
          "800000000000000000000000000000015f700cfff1a624e5e497161bcc8a198f",
          radix: 16),
      h: BigInt.parse("1", radix: 16),
      seed: null);

  static ECCurve_gostr3410_2001_cryptopro_b _make(
          domainName, curve, G, n, _h, seed) =>
      new ECCurve_gostr3410_2001_cryptopro_b._super(
          domainName, curve, G, n, _h, seed);

  ECCurve_gostr3410_2001_cryptopro_b._super(domainName, curve, G, n, _h, seed)
      : super(domainName, curve, G, n, _h, seed);
}
