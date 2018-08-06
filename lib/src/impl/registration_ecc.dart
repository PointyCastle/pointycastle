part of pointycastle.impl;

void _registerEccStandardCurves() {
  _registerGOST34102001StandardCurves();
  _registerSECEccStandardCurves();
  _registerTeleTrusTEccStandardCurves();
  _registerX962EccStandardCurves();
}

void _registerGOST34102001StandardCurves() {
  ECDomainParameters.registry["GostR3410-2001-CryptoPro-A"] =
      (_) => ECCurve_gostr3410_2001_cryptopro_a();
  ECDomainParameters.registry["GostR3410-2001-CryptoPro-XchB"] =
      (_) => ECCurve_gostr3410_2001_cryptopro_xchb();
  ECDomainParameters.registry["GostR3410-2001-CryptoPro-XchA"] =
      (_) => ECCurve_gostr3410_2001_cryptopro_xcha();
  ECDomainParameters.registry["GostR3410-2001-CryptoPro-C"] =
      (_) => ECCurve_gostr3410_2001_cryptopro_c();
  ECDomainParameters.registry["GostR3410-2001-CryptoPro-B"] =
      (_) => ECCurve_gostr3410_2001_cryptopro_b();
}

void _registerSECEccStandardCurves() {
  ECDomainParameters.registry["secp112r1"] = (_) => ECCurve_secp112r1();
  ECDomainParameters.registry["secp112r2"] = (_) => ECCurve_secp112r2();
  ECDomainParameters.registry["secp128r1"] = (_) => ECCurve_secp128r1();
  ECDomainParameters.registry["secp128r1"] = (_) => ECCurve_secp128r1();
  ECDomainParameters.registry["secp128r2"] = (_) => ECCurve_secp112r2();
  ECDomainParameters.registry["secp160k1"] = (_) => ECCurve_secp160k1();
  ECDomainParameters.registry["secp160r1"] = (_) => ECCurve_secp160r1();
  ECDomainParameters.registry["secp192k1"] = (_) => ECCurve_secp192k1();
  ECDomainParameters.registry["secp192r1"] = (_) => ECCurve_secp192r1();
  ECDomainParameters.registry["secp224k1"] = (_) => ECCurve_secp224k1();
  ECDomainParameters.registry["secp224r1"] = (_) => ECCurve_secp224r1();
  ECDomainParameters.registry["secp256k1"] = (_) => ECCurve_secp256k1();
  ECDomainParameters.registry["secp256r1"] = (_) => ECCurve_secp256r1();
  ECDomainParameters.registry["secp384r1"] = (_) => ECCurve_secp384r1();
  ECDomainParameters.registry["secp521r1"] = (_) => ECCurve_secp521r1();
}

void _registerTeleTrusTEccStandardCurves() {
  ECDomainParameters.registry["brainpoolp160r1"] =
      (_) => ECCurve_brainpoolp160r1();
  ECDomainParameters.registry["brainpoolp160t1"] =
      (_) => ECCurve_brainpoolp160t1();
  ECDomainParameters.registry["brainpoolp192r1"] =
      (_) => ECCurve_brainpoolp192r1();
  ECDomainParameters.registry["brainpoolp192t1"] =
      (_) => ECCurve_brainpoolp192t1();
  ECDomainParameters.registry["brainpoolp224r1"] =
      (_) => ECCurve_brainpoolp224r1();
  ECDomainParameters.registry["brainpoolp224t1"] =
      (_) => ECCurve_brainpoolp224t1();
  ECDomainParameters.registry["brainpoolp256r1"] =
      (_) => ECCurve_brainpoolp256r1();
  ECDomainParameters.registry["brainpoolp256t1"] =
      (_) => ECCurve_brainpoolp256t1();
  ECDomainParameters.registry["brainpoolp320r1"] =
      (_) => ECCurve_brainpoolp320r1();
  ECDomainParameters.registry["brainpoolp320t1"] =
      (_) => ECCurve_brainpoolp320t1();
  ECDomainParameters.registry["brainpoolp384r1"] =
      (_) => ECCurve_brainpoolp384r1();
  ECDomainParameters.registry["brainpoolp384t1"] =
      (_) => ECCurve_brainpoolp384t1();
  ECDomainParameters.registry["brainpoolp512r1"] =
      (_) => ECCurve_brainpoolp512r1();
  ECDomainParameters.registry["brainpoolp512t1"] =
      (_) => ECCurve_brainpoolp512t1();
}

void _registerX962EccStandardCurves() {
  ECDomainParameters.registry["prime192v1"] = (_) => ECCurve_prime192v1();
  ECDomainParameters.registry["prime192v2"] = (_) => ECCurve_prime192v2();
  ECDomainParameters.registry["prime192v3"] = (_) => ECCurve_prime192v3();
  ECDomainParameters.registry["prime192v3"] = (_) => ECCurve_prime192v3();
  ECDomainParameters.registry["prime239v1"] = (_) => ECCurve_prime239v1();
  ECDomainParameters.registry["prime239v2"] = (_) => ECCurve_prime239v2();
  ECDomainParameters.registry["prime239v3"] = (_) => ECCurve_prime239v3();
  ECDomainParameters.registry["prime256v1"] = (_) => ECCurve_prime256v1();
}
