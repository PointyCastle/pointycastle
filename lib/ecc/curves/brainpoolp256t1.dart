

// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.ec_domain_parameters.brainpoolp256t1;

import "package:bignum/bignum.dart";

import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/src/registry/registry.dart";
import "package:pointycastle/src/ec_standard_curve_constructor.dart";

class ECCurve_brainpoolp256t1 extends ECDomainParametersImpl {

  static final FactoryConfig FACTORY_CONFIG =
  new StaticFactoryConfig("brainpoolp256t1");

  factory ECCurve_brainpoolp256t1() => constructFpStandardCurve("brainpoolp256t1",
    ECCurve_brainpoolp256t1._make,
    q: new BigInteger("a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377", 16),
    a: new BigInteger("a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5374", 16),
    b: new BigInteger("662c61c430d84ea4fe66a7733d0b76b7bf93ebc4af2f49256ae58101fee92b04", 16),
    g: new BigInteger("04a3e8eb3cc1cfe7b7732213b23a656149afa142c47aafbc2b79a191562e1305f42d996c823439c56d7f7b22e14644417e69bcb6de39d027001dabe8f35b25c9be", 16),
    n: new BigInteger("a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7", 16),
    h: new BigInteger("1", 16),
    seed: null
  );

  static ECCurve_brainpoolp256t1 _make(domainName, curve, G, n, _h, seed) =>
    new ECCurve_brainpoolp256t1._super(domainName, curve, G, n, _h, seed);

  ECCurve_brainpoolp256t1._super(domainName, curve, G, n, _h, seed)
    : super(domainName, curve, G, n, _h, seed);

}