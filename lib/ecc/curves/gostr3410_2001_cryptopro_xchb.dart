

library cipher.impl.ec_domain_parameters.gostr3410_2001_cryptopro_xchb;

import "package:bignum/bignum.dart";

import "package:cipher/ecc/ecc_base.dart";
import "package:cipher/src/registry/registry.dart";
import "package:cipher/src/ec_standard_curve_constructor.dart";

class ECCurve_gostr3410_2001_cryptopro_xchb extends ECDomainParametersImpl {

  static final FactoryConfig FACTORY =
  new StaticFactoryConfig("GostR3410-2001-CryptoPro-XchB");

  factory ECCurve_gostr3410_2001_cryptopro_xchb() => constructFpStandardCurve("GostR3410-2001-CryptoPro-XchB",
    q: new BigInteger("9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d759b", 16),
    a: new BigInteger("9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d7598", 16),
    b: new BigInteger("805a", 16),
    g: new BigInteger("04000000000000000000000000000000000000000000000000000000000000000041ece55743711a8c3cbf3783cd08c0ee4d4dc440d4641a8f366e550dfdb3bb67", 16),
    n: new BigInteger("9b9f605f5a858107ab1ec85e6b41c8aa582ca3511eddfb74f02f3a6598980bb9", 16),
    h: new BigInteger("1", 16),
    seed: null
  );

}