

// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.ec_domain_parameters.secp224k1;

import "package:bignum/bignum.dart";

import "package:pointycastle/ecc/api.dart";
import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/src/registry/registry.dart";
import "package:pointycastle/src/ec_standard_curve_constructor.dart";

class ECCurve_secp224k1 extends ECDomainParametersImpl {

  static final FactoryConfig FACTORY_CONFIG =
  new StaticFactoryConfig(ECDomainParameters, "secp224k1");

  factory ECCurve_secp224k1() => constructFpStandardCurve("secp224k1",
    ECCurve_secp224k1._make,
    q: new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffeffffe56d", 16),
    a: new BigInteger("0", 16),
    b: new BigInteger("5", 16),
    g: new BigInteger("04a1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5", 16),
    n: new BigInteger("10000000000000000000000000001dce8d2ec6184caf0a971769fb1f7", 16),
    h: new BigInteger("1", 16),
    seed: null
  );

  static ECCurve_secp224k1 _make(domainName, curve, G, n, _h, seed) =>
    new ECCurve_secp224k1._super(domainName, curve, G, n, _h, seed);

  ECCurve_secp224k1._super(domainName, curve, G, n, _h, seed)
    : super(domainName, curve, G, n, _h, seed);

}