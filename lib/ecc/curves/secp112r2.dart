

// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.ec_domain_parameters.secp112r2;

import "package:bignum/bignum.dart";

import "package:pointycastle/ecc/api.dart";
import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/src/registry/registry.dart";
import "package:pointycastle/src/ec_standard_curve_constructor.dart";

class ECCurve_secp112r2 extends ECDomainParametersImpl {

  static final FactoryConfig FACTORY_CONFIG =
  new StaticFactoryConfig(ECDomainParameters, "secp112r2");

  factory ECCurve_secp112r2() => constructFpStandardCurve("secp112r2",
    ECCurve_secp112r2._make,
    q: new BigInteger("db7c2abf62e35e668076bead208b", 16),
    a: new BigInteger("6127c24c05f38a0aaaf65c0ef02c", 16),
    b: new BigInteger("51def1815db5ed74fcc34c85d709", 16),
    g: new BigInteger("044ba30ab5e892b4e1649dd0928643adcd46f5882e3747def36e956e97", 16),
    n: new BigInteger("36df0aafd8b8d7597ca10520d04b", 16),
    h: new BigInteger("4", 16),
    seed: new BigInteger("002757a1114d696e6768756151755316c05e0bd4", 16)
  );

  static ECCurve_secp112r2 _make(domainName, curve, G, n, _h, seed) =>
    new ECCurve_secp112r2._super(domainName, curve, G, n, _h, seed);

  ECCurve_secp112r2._super(domainName, curve, G, n, _h, seed)
    : super(domainName, curve, G, n, _h, seed);

}