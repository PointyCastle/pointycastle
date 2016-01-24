

// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.ec_domain_parameters.brainpoolp192t1;

import "package:bignum/bignum.dart";

import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/src/registry/registry.dart";
import "package:pointycastle/src/ec_standard_curve_constructor.dart";

class ECCurve_brainpoolp192t1 extends ECDomainParametersImpl {

  static final FactoryConfig FACTORY_CONFIG =
  new StaticFactoryConfig("brainpoolp192t1");

  factory ECCurve_brainpoolp192t1() => constructFpStandardCurve("brainpoolp192t1",
    ECCurve_brainpoolp192t1._make,
    q: new BigInteger("c302f41d932a36cda7a3463093d18db78fce476de1a86297", 16),
    a: new BigInteger("c302f41d932a36cda7a3463093d18db78fce476de1a86294", 16),
    b: new BigInteger("13d56ffaec78681e68f9deb43b35bec2fb68542e27897b79", 16),
    g: new BigInteger("043ae9e58c82f63c30282e1fe7bbf43fa72c446af6f4618129097e2c5667c2223a902ab5ca449d0084b7e5b3de7ccc01c9", 16),
    n: new BigInteger("c302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1", 16),
    h: new BigInteger("1", 16),
    seed: null
  );

  static ECCurve_brainpoolp192t1 _make(domainName, curve, G, n, _h, seed) =>
    new ECCurve_brainpoolp192t1._super(domainName, curve, G, n, _h, seed);

  ECCurve_brainpoolp192t1._super(domainName, curve, G, n, _h, seed)
    : super(domainName, curve, G, n, _h, seed);

}