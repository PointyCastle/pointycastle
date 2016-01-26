

library cipher.impl.ec_domain_parameters.secp224r1;

import "package:bignum/bignum.dart";

import "package:cipher/ecc/ecc_base.dart";
import "package:cipher/src/registry/registry.dart";
import "package:cipher/src/ec_standard_curve_constructor.dart";

class ECCurve_secp224r1 extends ECDomainParametersImpl {

  static final FactoryConfig FACTORY_CONFIG =
  new StaticFactoryConfig("secp224r1");

  factory ECCurve_secp224r1() => constructFpStandardCurve("secp224r1",
    ECCurve_secp224r1._make,
    q: new BigInteger("ffffffffffffffffffffffffffffffff000000000000000000000001", 16),
    a: new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffffffffffe", 16),
    b: new BigInteger("b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4", 16),
    g: new BigInteger("04b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34", 16),
    n: new BigInteger("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d", 16),
    h: new BigInteger("1", 16),
    seed: new BigInteger("bd71344799d5c7fcdc45b59fa3b9ab8f6a948bc5", 16)
  );

  static ECCurve_secp224r1 _make(domainName, curve, G, n, _h, seed) =>
    new ECCurve_secp224r1._super(domainName, curve, G, n, _h, seed);

  ECCurve_secp224r1._super(domainName, curve, G, n, _h, seed)
    : super(domainName, curve, G, n, _h, seed);

}