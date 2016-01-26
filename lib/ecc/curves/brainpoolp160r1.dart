

library cipher.impl.ec_domain_parameters.brainpoolp160r1;

import "package:bignum/bignum.dart";

import "package:cipher/ecc/ecc_base.dart";
import "package:cipher/src/registry/registry.dart";
import "package:cipher/src/ec_standard_curve_constructor.dart";

class ECCurve_brainpoolp160r1 extends ECDomainParametersImpl {

  static final FactoryConfig FACTORY_CONFIG =
  new StaticFactoryConfig("brainpoolp160r1");

  factory ECCurve_brainpoolp160r1() => constructFpStandardCurve("brainpoolp160r1",
    ECCurve_brainpoolp160r1._make,
    q: new BigInteger("e95e4a5f737059dc60dfc7ad95b3d8139515620f", 16),
    a: new BigInteger("340e7be2a280eb74e2be61bada745d97e8f7c300", 16),
    b: new BigInteger("1e589a8595423412134faa2dbdec95c8d8675e58", 16),
    g: new BigInteger("04bed5af16ea3f6a4f62938c4631eb5af7bdbcdbc31667cb477a1a8ec338f94741669c976316da6321", 16),
    n: new BigInteger("e95e4a5f737059dc60df5991d45029409e60fc09", 16),
    h: new BigInteger("1", 16),
    seed: null
  );

  static ECCurve_brainpoolp160r1 _make(domainName, curve, G, n, _h, seed) =>
      new ECCurve_brainpoolp160r1._super(domainName, curve, G, n, _h, seed);

  ECCurve_brainpoolp160r1._super(domainName, curve, G, n, _h, seed)
      : super(domainName, curve, G, n, _h, seed);

}