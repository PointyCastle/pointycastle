

// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.ec_domain_parameters.secp160k1;

import "package:bignum/bignum.dart";

import "package:pointycastle/ecc/api.dart";
import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/src/registry/registry.dart";
import "package:pointycastle/src/ec_standard_curve_constructor.dart";

class ECCurve_secp160k1 extends ECDomainParametersImpl {

  static final FactoryConfig FACTORY_CONFIG =
  new StaticFactoryConfig(ECDomainParameters, "secp160k1");

  factory ECCurve_secp160k1() => constructFpStandardCurve("secp160k1",
    ECCurve_secp160k1._make,
    q: new BigInteger("fffffffffffffffffffffffffffffffeffffac73", 16),
    a: new BigInteger("0", 16),
    b: new BigInteger("7", 16),
    g: new BigInteger("043b4c382ce37aa192a4019e763036f4f5dd4d7ebb938cf935318fdced6bc28286531733c3f03c4fee", 16),
    n: new BigInteger("100000000000000000001b8fa16dfab9aca16b6b3", 16),
    h: new BigInteger("1", 16),
    seed: null
  );

  static ECCurve_secp160k1 _make(domainName, curve, G, n, _h, seed) =>
    new ECCurve_secp160k1._super(domainName, curve, G, n, _h, seed);

  ECCurve_secp160k1._super(domainName, curve, G, n, _h, seed)
    : super(domainName, curve, G, n, _h, seed);

}