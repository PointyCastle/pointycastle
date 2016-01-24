

library cipher.impl.ec_domain_parameters.prime239v2;

import "package:bignum/bignum.dart";

import "package:cipher/ecc/ecc_base.dart";
import "package:cipher/src/registry/registry.dart";
import "package:cipher/src/ec_standard_curve_constructor.dart";

class ECCurve_prime239v2 extends ECDomainParametersImpl {

  static final FactoryConfig FACTORY =
  new StaticFactoryConfig("prime239v2");

  factory ECCurve_prime239v2() => constructFpStandardCurve("prime239v2",
    q: new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff", 16),
    a: new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16),
    b: new BigInteger("617fab6832576cbbfed50d99f0249c3fee58b94ba0038c7ae84c8c832f2c", 16),
    g: new BigInteger("0238af09d98727705120c921bb5e9e26296a3cdcf2f35757a0eafd87b830e7", 16),
    n: new BigInteger("7fffffffffffffffffffffff800000cfa7e8594377d414c03821bc582063", 16),
    h: new BigInteger("1", 16),
    seed: new BigInteger("e8b4011604095303ca3b8099982be09fcb9ae616", 16)
  );

}