

// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.ec_domain_parameters.secp112r1;

import "package:bignum/bignum.dart";

import "package:pointycastle/ecc/api.dart";
import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/src/registry/registry.dart";
import "package:pointycastle/src/ec_standard_curve_constructor.dart";

class ECCurve_secp112r1 extends ECDomainParametersImpl {

  static final FactoryConfig FACTORY_CONFIG =
  new StaticFactoryConfig(ECDomainParameters, "secp112r1");

  factory ECCurve_secp112r1() => constructFpStandardCurve("secp112r1",
    ECCurve_secp112r1._make,
    q: new BigInteger("db7c2abf62e35e668076bead208b", 16),
    a: new BigInteger("db7c2abf62e35e668076bead2088", 16),
    b: new BigInteger("659ef8ba043916eede8911702b22", 16),
    g: new BigInteger("0409487239995a5ee76b55f9c2f098a89ce5af8724c0a23e0e0ff77500", 16),
    n: new BigInteger("db7c2abf62e35e7628dfac6561c5", 16),
    h: new BigInteger("1", 16),
    seed: new BigInteger("00f50b028e4d696e676875615175290472783fb1", 16)
  );

  static ECCurve_secp112r1 _make(domainName, curve, G, n, _h, seed) =>
    new ECCurve_secp112r1._super(domainName, curve, G, n, _h, seed);

  ECCurve_secp112r1._super(domainName, curve, G, n, _h, seed)
    : super(domainName, curve, G, n, _h, seed);

}