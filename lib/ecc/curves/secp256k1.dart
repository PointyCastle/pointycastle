

library pointycastle.impl.ec_domain_parameters.secp256k1;

import "package:bignum/bignum.dart";

import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/src/registry/registry.dart";
import "package:pointycastle/src/ec_standard_curve_constructor.dart";

class ECCurve_secp256k1 extends ECDomainParametersImpl {

  static final FactoryConfig FACTORY_CONFIG =
  new StaticFactoryConfig("secp256k1");

  factory ECCurve_secp256k1() => constructFpStandardCurve("secp256k1",
    ECCurve_secp256k1._make,
    q: new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16),
    a: new BigInteger("0", 16),
    b: new BigInteger("7", 16),
    g: new BigInteger("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16),
    n: new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16),
    h: new BigInteger("1", 16),
    seed: null
  );

  static ECCurve_secp256k1 _make(domainName, curve, G, n, _h, seed) =>
    new ECCurve_secp256k1._super(domainName, curve, G, n, _h, seed);

  ECCurve_secp256k1._super(domainName, curve, G, n, _h, seed)
    : super(domainName, curve, G, n, _h, seed);

}