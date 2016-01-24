

library cipher.ec_domain_parameters.brainpoolp160t1;

import "package:bignum/bignum.dart";

import "package:cipher/ecc/ecc_base.dart";
import "package:cipher/src/registry/registry.dart";
import "package:cipher/src/registry/ec_standard_curve_constructor.dart";

class ECCurve_brainpoolp160t1 extends ECDomainParametersImpl {

  static final FactoryConfig FACTORY =
  new StaticFactoryConfig("brainpoolp160t1");

  factory ECCurve_brainpoolp160t1() => constructFpStandardCurve("brainpoolp160t1",
    q: new BigInteger("e95e4a5f737059dc60dfc7ad95b3d8139515620f", 16),
    a: new BigInteger("e95e4a5f737059dc60dfc7ad95b3d8139515620c", 16),
    b: new BigInteger("7a556b6dae535b7b51ed2c4d7daa7a0b5c55f380", 16),
    g: new BigInteger("04b199b13b9b34efc1397e64baeb05acc265ff2378add6718b7c7c1961f0991b842443772152c9e0ad", 16),
    n: new BigInteger("e95e4a5f737059dc60df5991d45029409e60fc09", 16),
    h: new BigInteger("1", 16),
    seed: null
  );

}