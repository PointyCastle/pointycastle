

// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.impl.ec_domain_parameters.secp192k1;

import "package:bignum/bignum.dart";

import "package:pointycastle/ecc/ecc_base.dart";
import "package:pointycastle/src/registry/registry.dart";
import "package:pointycastle/src/ec_standard_curve_constructor.dart";

class ECCurve_secp192k1 extends ECDomainParametersImpl {

  static final FactoryConfig FACTORY_CONFIG =
  new StaticFactoryConfig("secp192k1");

  factory ECCurve_secp192k1() => constructFpStandardCurve("secp192k1",
    ECCurve_secp192k1._make,
    q: new BigInteger("fffffffffffffffffffffffffffffffffffffffeffffee37", 16),
    a: new BigInteger("0", 16),
    b: new BigInteger("3", 16),
    g: new BigInteger("04db4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d", 16),
    n: new BigInteger("fffffffffffffffffffffffe26f2fc170f69466a74defd8d", 16),
    h: new BigInteger("1", 16),
    seed: null
  );

  static ECCurve_secp192k1 _make(domainName, curve, G, n, _h, seed) =>
    new ECCurve_secp192k1._super(domainName, curve, G, n, _h, seed);

  ECCurve_secp192k1._super(domainName, curve, G, n, _h, seed)
    : super(domainName, curve, G, n, _h, seed);

}