

library cipher.ec_domain_parameters.brainpoolp192r1;

import "package:bignum/bignum.dart";

import "package:cipher/ecc/ecc_base.dart";
import "package:cipher/src/registry/registry.dart";
import "package:cipher/src/registry/ec_standard_curve_constructor.dart";

class ECCurve_brainpoolp192r1 extends ECDomainParametersImpl {

  static final FactoryConfig FACTORY =
  new StaticFactoryConfig("brainpoolp192r1");

  factory ECCurve_brainpoolp192r1() => constructFpStandardCurve("brainpoolp192r1",
    q: new BigInteger("c302f41d932a36cda7a3463093d18db78fce476de1a86297", 16),
    a: new BigInteger("6a91174076b1e0e19c39c031fe8685c1cae040e5c69a28ef", 16),
    b: new BigInteger("469a28ef7c28cca3dc721d044f4496bcca7ef4146fbf25c9", 16),
    g: new BigInteger("04c0a0647eaab6a48753b033c56cb0f0900a2f5c4853375fd614b690866abd5bb88b5f4828c1490002e6773fa2fa299b8f", 16),
    n: new BigInteger("c302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1", 16),
    h: new BigInteger("1", 16),
    seed: null
  );

}