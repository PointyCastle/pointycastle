

library cipher.impl.ec_domain_parameters.prime192v3;

import "package:bignum/bignum.dart";

import "package:cipher/ecc/ecc_base.dart";
import "package:cipher/src/registry/registry.dart";
import "package:cipher/src/ec_standard_curve_constructor.dart";

class ECCurve_prime192v3 extends ECDomainParametersImpl {

  static final FactoryConfig FACTORY =
  new StaticFactoryConfig("prime192v3");

  factory ECCurve_prime192v3() => constructFpStandardCurve("prime192v3",
    q: new BigInteger("fffffffffffffffffffffffffffffffeffffffffffffffff", 16),
    a: new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16),
    b: new BigInteger("22123dc2395a05caa7423daeccc94760a7d462256bd56916", 16),
    g: new BigInteger("027d29778100c65a1da1783716588dce2b8b4aee8e228f1896", 16),
    n: new BigInteger("ffffffffffffffffffffffff7a62d031c83f4294f640ec13", 16),
    h: new BigInteger("1", 16),
    seed: new BigInteger("c469684435deb378c4b65ca9591e2a5763059a2e", 16)
  );

}