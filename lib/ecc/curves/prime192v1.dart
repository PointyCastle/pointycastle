

library cipher.ec_domain_parameters.prime192v1;

import "package:bignum/bignum.dart";

import "package:cipher/ecc/ecc_base.dart";
import "package:cipher/src/registry/registry.dart";
import "package:cipher/src/registry/ec_standard_curve_constructor.dart";

class ECCurve_prime192v1 extends ECDomainParametersImpl {

  static final FactoryConfig FACTORY =
  new StaticFactoryConfig("prime192v1");

  factory ECCurve_prime192v1() => constructFpStandardCurve("prime192v1",
    q: new BigInteger("fffffffffffffffffffffffffffffffeffffffffffffffff", 16),
    a: new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16),
    b: new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16),
    g: new BigInteger("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16),
    n: new BigInteger("ffffffffffffffffffffffff99def836146bc9b1b4d22831", 16),
    h: new BigInteger("1", 16),
    seed: new BigInteger("3045ae6fc8422f64ed579528d38120eae12196d5", 16)
  );

}