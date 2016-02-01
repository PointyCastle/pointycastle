

// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.ec_domain_parameters.secp192r1;

import "package:bignum/bignum.dart";

import "package:pointycastle/ecc/api.dart";
import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/src/registry/registry.dart";
import "package:pointycastle/src/ec_standard_curve_constructor.dart";

class ECCurve_secp192r1 extends ECDomainParametersImpl {

  static final FactoryConfig FACTORY_CONFIG =
  new StaticFactoryConfig(ECDomainParameters, "secp192r1");

  factory ECCurve_secp192r1() => constructFpStandardCurve("secp192r1",
    ECCurve_secp192r1._make,
    q: new BigInteger("fffffffffffffffffffffffffffffffeffffffffffffffff", 16),
    a: new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16),
    b: new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16),
    g: new BigInteger("04188da80eb03090f67cbf20eb43a18800f4ff0afd82ff101207192b95ffc8da78631011ed6b24cdd573f977a11e794811", 16),
    n: new BigInteger("ffffffffffffffffffffffff99def836146bc9b1b4d22831", 16),
    h: new BigInteger("1", 16),
    seed: new BigInteger("3045ae6fc8422f64ed579528d38120eae12196d5", 16)
  );

  static ECCurve_secp192r1 _make(domainName, curve, G, n, _h, seed) =>
    new ECCurve_secp192r1._super(domainName, curve, G, n, _h, seed);

  ECCurve_secp192r1._super(domainName, curve, G, n, _h, seed)
    : super(domainName, curve, G, n, _h, seed);

}