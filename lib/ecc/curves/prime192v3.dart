

// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.ec_domain_parameters.prime192v3;

import "package:bignum/bignum.dart";

import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/src/registry/registry.dart";
import "package:pointycastle/src/ec_standard_curve_constructor.dart";

class ECCurve_prime192v3 extends ECDomainParametersImpl {

  static final FactoryConfig FACTORY_CONFIG =
  new StaticFactoryConfig("prime192v3");

  factory ECCurve_prime192v3() => constructFpStandardCurve("prime192v3",
    ECCurve_prime192v3._make,
    q: new BigInteger("fffffffffffffffffffffffffffffffeffffffffffffffff", 16),
    a: new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16),
    b: new BigInteger("22123dc2395a05caa7423daeccc94760a7d462256bd56916", 16),
    g: new BigInteger("027d29778100c65a1da1783716588dce2b8b4aee8e228f1896", 16),
    n: new BigInteger("ffffffffffffffffffffffff7a62d031c83f4294f640ec13", 16),
    h: new BigInteger("1", 16),
    seed: new BigInteger("c469684435deb378c4b65ca9591e2a5763059a2e", 16)
  );

  static ECCurve_prime192v3 _make(domainName, curve, G, n, _h, seed) =>
    new ECCurve_prime192v3._super(domainName, curve, G, n, _h, seed);

  ECCurve_prime192v3._super(domainName, curve, G, n, _h, seed)
    : super(domainName, curve, G, n, _h, seed);

}