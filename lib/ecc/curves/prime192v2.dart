

// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.ec_domain_parameters.prime192v2;

import "package:bignum/bignum.dart";

import "package:pointycastle/ecc/api.dart";
import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/src/registry/registry.dart";
import "package:pointycastle/src/ec_standard_curve_constructor.dart";

class ECCurve_prime192v2 extends ECDomainParametersImpl {

  static final FactoryConfig FACTORY_CONFIG =
  new StaticFactoryConfig(ECDomainParameters, "prime192v2");

  factory ECCurve_prime192v2() => constructFpStandardCurve("prime192v2",
    ECCurve_prime192v2._make,
    q: new BigInteger("fffffffffffffffffffffffffffffffeffffffffffffffff", 16),
    a: new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16),
    b: new BigInteger("cc22d6dfb95c6b25e49c0d6364a4e5980c393aa21668d953", 16),
    g: new BigInteger("03eea2bae7e1497842f2de7769cfe9c989c072ad696f48034a", 16),
    n: new BigInteger("fffffffffffffffffffffffe5fb1a724dc80418648d8dd31", 16),
    h: new BigInteger("1", 16),
    seed: new BigInteger("31a92ee2029fd10d901b113e990710f0d21ac6b6", 16)
  );

  static ECCurve_prime192v2 _make(domainName, curve, G, n, _h, seed) =>
    new ECCurve_prime192v2._super(domainName, curve, G, n, _h, seed);

  ECCurve_prime192v2._super(domainName, curve, G, n, _h, seed)
    : super(domainName, curve, G, n, _h, seed);

}