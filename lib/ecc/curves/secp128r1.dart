

library cipher.ec_domain_parameters.secp128r1;

import "package:bignum/bignum.dart";

import "package:cipher/ecc/ecc_base.dart";
import "package:cipher/src/registry/registry.dart";
import "package:cipher/src/registry/ec_standard_curve_constructor.dart";

class ECCurve_secp128r1 extends ECDomainParametersImpl {

  static final FactoryConfig FACTORY =
  new StaticFactoryConfig("secp128r1");

  factory ECCurve_secp128r1() => constructFpStandardCurve("secp128r1",
    q: new BigInteger("fffffffdffffffffffffffffffffffff", 16),
    a: new BigInteger("fffffffdfffffffffffffffffffffffc", 16),
    b: new BigInteger("e87579c11079f43dd824993c2cee5ed3", 16),
    g: new BigInteger("04161ff7528b899b2d0c28607ca52c5b86cf5ac8395bafeb13c02da292dded7a83", 16),
    n: new BigInteger("fffffffe0000000075a30d1b9038a115", 16),
    h: new BigInteger("1", 16),
    seed: new BigInteger("000e0d4d696e6768756151750cc03a4473d03679", 16)
  );

}