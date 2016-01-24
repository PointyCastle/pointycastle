

library pointycastle.impl.ec_domain_parameters.secp384r1;

import "package:bignum/bignum.dart";

import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/src/registry/registry.dart";
import "package:pointycastle/src/ec_standard_curve_constructor.dart";

class ECCurve_secp384r1 extends ECDomainParametersImpl {

  static final FactoryConfig FACTORY_CONFIG =
  new StaticFactoryConfig("secp384r1");

  factory ECCurve_secp384r1() => constructFpStandardCurve("secp384r1",
    ECCurve_secp384r1._make,
    q: new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16),
    a: new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc", 16),
    b: new BigInteger("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16),
    g: new BigInteger("04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16),
    n: new BigInteger("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16),
    h: new BigInteger("1", 16),
    seed: new BigInteger("a335926aa319a27a1d00896a6773a4827acdac73", 16)
  );

  static ECCurve_secp384r1 _make(domainName, curve, G, n, _h, seed) =>
    new ECCurve_secp384r1._super(domainName, curve, G, n, _h, seed);

  ECCurve_secp384r1._super(domainName, curve, G, n, _h, seed)
    : super(domainName, curve, G, n, _h, seed);

}