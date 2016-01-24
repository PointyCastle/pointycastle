

library cipher.ec_domain_parameters.secp192k1;

import "package:bignum/bignum.dart";

import "package:cipher/ecc/ecc_base.dart";
import "package:cipher/src/registry/registry.dart";
import "package:cipher/src/registry/ec_standard_curve_constructor.dart";

class ECCurve_secp192k1 extends ECDomainParametersImpl {

  static final FactoryConfig FACTORY =
  new StaticFactoryConfig("secp192k1");

  factory ECCurve_secp192k1() => constructFpStandardCurve("secp192k1",
    q: new BigInteger("fffffffffffffffffffffffffffffffffffffffeffffee37", 16),
    a: new BigInteger("0", 16),
    b: new BigInteger("3", 16),
    g: new BigInteger("04db4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d", 16),
    n: new BigInteger("fffffffffffffffffffffffe26f2fc170f69466a74defd8d", 16),
    h: new BigInteger("1", 16),
    seed: null
  );

}