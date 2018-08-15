// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.ec_domain_parameters.prime256v1;

import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/src/ec_standard_curve_constructor.dart";

class ECCurve_prime256v1 extends ECDomainParametersImpl {
  factory ECCurve_prime256v1() => constructFpStandardCurve(
      "prime256v1", ECCurve_prime256v1._make,
      q: BigInt.parse(
          "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
          radix: 16),
      a: BigInt.parse(
          "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc",
          radix: 16),
      b: BigInt.parse(
          "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
          radix: 16),
      g: BigInt.parse(
          "036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
          radix: 16),
      n: BigInt.parse(
          "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
          radix: 16),
      h: BigInt.parse("1", radix: 16),
      seed:
          BigInt.parse("c49d360886e704936a6678e1139d26b7819f7e90", radix: 16));

  static ECCurve_prime256v1 _make(domainName, curve, G, n, _h, seed) =>
      new ECCurve_prime256v1._super(domainName, curve, G, n, _h, seed);

  ECCurve_prime256v1._super(domainName, curve, G, n, _h, seed)
      : super(domainName, curve, G, n, _h, seed);
}
