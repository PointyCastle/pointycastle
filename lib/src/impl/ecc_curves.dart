// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

part of cipher.impl;

//TODO originally in src/impl/
void _registerEccStandardCurves() {
  _registerGOST34102001StandardCurves();
  _registerSECEccStandardCurves();
  _registerTeleTrusTEccStandardCurves();
  _registerX962EccStandardCurves();
}

void _registerGOST34102001StandardCurves() {
  _registerFpStandardCurve("GostR3410-2001-CryptoPro-A",
      q: new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97", 16),
      a: new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd94", 16),
      b: new BigInteger("a6", 16),
      g: new BigInteger("0400000000000000000000000000000000000000000000000000000000000000018d91e471e0989cda27df505a453f2b7635294f2ddf23e3b122acc99c9e9f1e14", 16),
      n: new BigInteger("ffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893", 16),
      h: new BigInteger("1", 16),
      seed: null
  );
  _registerFpStandardCurve("GostR3410-2001-CryptoPro-XchB",
      q: new BigInteger("9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d759b", 16),
      a: new BigInteger("9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d7598", 16),
      b: new BigInteger("805a", 16),
      g: new BigInteger("04000000000000000000000000000000000000000000000000000000000000000041ece55743711a8c3cbf3783cd08c0ee4d4dc440d4641a8f366e550dfdb3bb67", 16),
      n: new BigInteger("9b9f605f5a858107ab1ec85e6b41c8aa582ca3511eddfb74f02f3a6598980bb9", 16),
      h: new BigInteger("1", 16),
      seed: null
  );
  _registerFpStandardCurve("GostR3410-2001-CryptoPro-XchA",
      q: new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd97", 16),
      a: new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd94", 16),
      b: new BigInteger("a6", 16),
      g: new BigInteger("0400000000000000000000000000000000000000000000000000000000000000018d91e471e0989cda27df505a453f2b7635294f2ddf23e3b122acc99c9e9f1e14", 16),
      n: new BigInteger("ffffffffffffffffffffffffffffffff6c611070995ad10045841b09b761b893", 16),
      h: new BigInteger("1", 16),
      seed: null
  );
  _registerFpStandardCurve("GostR3410-2001-CryptoPro-C",
      q: new BigInteger("9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d759b", 16),
      a: new BigInteger("9b9f605f5a858107ab1ec85e6b41c8aacf846e86789051d37998f7b9022d7598", 16),
      b: new BigInteger("805a", 16),
      g: new BigInteger("04000000000000000000000000000000000000000000000000000000000000000041ece55743711a8c3cbf3783cd08c0ee4d4dc440d4641a8f366e550dfdb3bb67", 16),
      n: new BigInteger("9b9f605f5a858107ab1ec85e6b41c8aa582ca3511eddfb74f02f3a6598980bb9", 16),
      h: new BigInteger("1", 16),
      seed: null
  );
  _registerFpStandardCurve("GostR3410-2001-CryptoPro-B",
      q: new BigInteger("8000000000000000000000000000000000000000000000000000000000000c99", 16),
      a: new BigInteger("8000000000000000000000000000000000000000000000000000000000000c96", 16),
      b: new BigInteger("3e1af419a269a5f866a7d3c25c3df80ae979259373ff2b182f49d4ce7e1bbc8b", 16),
      g: new BigInteger("0400000000000000000000000000000000000000000000000000000000000000013fa8124359f96680b83d1c3eb2c070e5c545c9858d03ecfb744bf8d717717efc", 16),
      n: new BigInteger("800000000000000000000000000000015f700cfff1a624e5e497161bcc8a198f", 16),
      h: new BigInteger("1", 16),
      seed: null
  );
}

void _registerSECEccStandardCurves() {
  _registerFpStandardCurve("secp112r1",
      q: new BigInteger("db7c2abf62e35e668076bead208b", 16),
      a: new BigInteger("db7c2abf62e35e668076bead2088", 16),
      b: new BigInteger("659ef8ba043916eede8911702b22", 16),
      g: new BigInteger("0409487239995a5ee76b55f9c2f098a89ce5af8724c0a23e0e0ff77500", 16),
      n: new BigInteger("db7c2abf62e35e7628dfac6561c5", 16),
      h: new BigInteger("1", 16),
      seed: new BigInteger("00f50b028e4d696e676875615175290472783fb1", 16)
  );
  _registerFpStandardCurve("secp112r2",
      q: new BigInteger("db7c2abf62e35e668076bead208b", 16),
      a: new BigInteger("6127c24c05f38a0aaaf65c0ef02c", 16),
      b: new BigInteger("51def1815db5ed74fcc34c85d709", 16),
      g: new BigInteger("044ba30ab5e892b4e1649dd0928643adcd46f5882e3747def36e956e97", 16),
      n: new BigInteger("36df0aafd8b8d7597ca10520d04b", 16),
      h: new BigInteger("4", 16),
      seed: new BigInteger("002757a1114d696e6768756151755316c05e0bd4", 16)
  );
  _registerFpStandardCurve("secp128r1",
      q: new BigInteger("fffffffdffffffffffffffffffffffff", 16),
      a: new BigInteger("fffffffdfffffffffffffffffffffffc", 16),
      b: new BigInteger("e87579c11079f43dd824993c2cee5ed3", 16),
      g: new BigInteger("04161ff7528b899b2d0c28607ca52c5b86cf5ac8395bafeb13c02da292dded7a83", 16),
      n: new BigInteger("fffffffe0000000075a30d1b9038a115", 16),
      h: new BigInteger("1", 16),
      seed: new BigInteger("000e0d4d696e6768756151750cc03a4473d03679", 16)
  );
  _registerFpStandardCurve("secp128r2",
      q: new BigInteger("fffffffdffffffffffffffffffffffff", 16),
      a: new BigInteger("d6031998d1b3bbfebf59cc9bbff9aee1", 16),
      b: new BigInteger("5eeefca380d02919dc2c6558bb6d8a5d", 16),
      g: new BigInteger("047b6aa5d85e572983e6fb32a7cdebc14027b6916a894d3aee7106fe805fc34b44", 16),
      n: new BigInteger("3fffffff7fffffffbe0024720613b5a3", 16),
      h: new BigInteger("4", 16),
      seed: new BigInteger("004d696e67687561517512d8f03431fce63b88f4", 16)
  );
  _registerFpStandardCurve("secp160k1",
      q: new BigInteger("fffffffffffffffffffffffffffffffeffffac73", 16),
      a: new BigInteger("0", 16),
      b: new BigInteger("7", 16),
      g: new BigInteger("043b4c382ce37aa192a4019e763036f4f5dd4d7ebb938cf935318fdced6bc28286531733c3f03c4fee", 16),
      n: new BigInteger("100000000000000000001b8fa16dfab9aca16b6b3", 16),
      h: new BigInteger("1", 16),
      seed: null
  );
  _registerFpStandardCurve("secp160r1",
      q: new BigInteger("ffffffffffffffffffffffffffffffff7fffffff", 16),
      a: new BigInteger("ffffffffffffffffffffffffffffffff7ffffffc", 16),
      b: new BigInteger("1c97befc54bd7a8b65acf89f81d4d4adc565fa45", 16),
      g: new BigInteger("044a96b5688ef573284664698968c38bb913cbfc8223a628553168947d59dcc912042351377ac5fb32", 16),
      n: new BigInteger("100000000000000000001f4c8f927aed3ca752257", 16),
      h: new BigInteger("1", 16),
      seed: new BigInteger("1053cde42c14d696e67687561517533bf3f83345", 16)
  );
  _registerFpStandardCurve("secp160r2",
      q: new BigInteger("fffffffffffffffffffffffffffffffeffffac73", 16),
      a: new BigInteger("fffffffffffffffffffffffffffffffeffffac70", 16),
      b: new BigInteger("b4e134d3fb59eb8bab57274904664d5af50388ba", 16),
      g: new BigInteger("0452dcb034293a117e1f4ff11b30f7199d3144ce6dfeaffef2e331f296e071fa0df9982cfea7d43f2e", 16),
      n: new BigInteger("100000000000000000000351ee786a818f3a1a16b", 16),
      h: new BigInteger("1", 16),
      seed: new BigInteger("b99b99b099b323e02709a4d696e6768756151751", 16)
  );
  _registerFpStandardCurve("secp192k1",
      q: new BigInteger("fffffffffffffffffffffffffffffffffffffffeffffee37", 16),
      a: new BigInteger("0", 16),
      b: new BigInteger("3", 16),
      g: new BigInteger("04db4ff10ec057e9ae26b07d0280b7f4341da5d1b1eae06c7d9b2f2f6d9c5628a7844163d015be86344082aa88d95e2f9d", 16),
      n: new BigInteger("fffffffffffffffffffffffe26f2fc170f69466a74defd8d", 16),
      h: new BigInteger("1", 16),
      seed: null
  );
  _registerFpStandardCurve("secp192r1",
      q: new BigInteger("fffffffffffffffffffffffffffffffeffffffffffffffff", 16),
      a: new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16),
      b: new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16),
      g: new BigInteger("04188da80eb03090f67cbf20eb43a18800f4ff0afd82ff101207192b95ffc8da78631011ed6b24cdd573f977a11e794811", 16),
      n: new BigInteger("ffffffffffffffffffffffff99def836146bc9b1b4d22831", 16),
      h: new BigInteger("1", 16),
      seed: new BigInteger("3045ae6fc8422f64ed579528d38120eae12196d5", 16)
  );
  _registerFpStandardCurve("secp224k1",
      q: new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffeffffe56d", 16),
      a: new BigInteger("0", 16),
      b: new BigInteger("5", 16),
      g: new BigInteger("04a1455b334df099df30fc28a169a467e9e47075a90f7e650eb6b7a45c7e089fed7fba344282cafbd6f7e319f7c0b0bd59e2ca4bdb556d61a5", 16),
      n: new BigInteger("10000000000000000000000000001dce8d2ec6184caf0a971769fb1f7", 16),
      h: new BigInteger("1", 16),
      seed: null
  );
  _registerFpStandardCurve("secp224r1",
      q: new BigInteger("ffffffffffffffffffffffffffffffff000000000000000000000001", 16),
      a: new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffffffffffe", 16),
      b: new BigInteger("b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4", 16),
      g: new BigInteger("04b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34", 16),
      n: new BigInteger("ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d", 16),
      h: new BigInteger("1", 16),
      seed: new BigInteger("bd71344799d5c7fcdc45b59fa3b9ab8f6a948bc5", 16)
  );
  _registerFpStandardCurve("secp256k1",
      q: new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16),
      a: new BigInteger("0", 16),
      b: new BigInteger("7", 16),
      g: new BigInteger("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 16),
      n: new BigInteger("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16),
      h: new BigInteger("1", 16),
      seed: null
  );
  _registerFpStandardCurve("secp256r1",
      q: new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16),
      a: new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16),
      b: new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16),
      g: new BigInteger("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
      n: new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
      h: new BigInteger("1", 16),
      seed: new BigInteger("c49d360886e704936a6678e1139d26b7819f7e90", 16)
  );
  _registerFpStandardCurve("secp384r1",
      q: new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff", 16),
      a: new BigInteger("fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc", 16),
      b: new BigInteger("b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef", 16),
      g: new BigInteger("04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f", 16),
      n: new BigInteger("ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973", 16),
      h: new BigInteger("1", 16),
      seed: new BigInteger("a335926aa319a27a1d00896a6773a4827acdac73", 16)
  );
  _registerFpStandardCurve("secp521r1",
      q: new BigInteger("1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff", 16),
      a: new BigInteger("1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc", 16),
      b: new BigInteger("51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00", 16),
      g: new BigInteger("0400c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650", 16),
      n: new BigInteger("1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409", 16),
      h: new BigInteger("1", 16),
      seed: new BigInteger("d09e8800291cb85396cc6717393284aaa0da64ba", 16)
  );
}

void _registerTeleTrusTEccStandardCurves() {
  _registerFpStandardCurve("brainpoolp160r1",
      q: new BigInteger("e95e4a5f737059dc60dfc7ad95b3d8139515620f", 16),
      a: new BigInteger("340e7be2a280eb74e2be61bada745d97e8f7c300", 16),
      b: new BigInteger("1e589a8595423412134faa2dbdec95c8d8675e58", 16),
      g: new BigInteger("04bed5af16ea3f6a4f62938c4631eb5af7bdbcdbc31667cb477a1a8ec338f94741669c976316da6321", 16),
      n: new BigInteger("e95e4a5f737059dc60df5991d45029409e60fc09", 16),
      h: new BigInteger("1", 16),
      seed: null
  );
  _registerFpStandardCurve("brainpoolp160t1",
      q: new BigInteger("e95e4a5f737059dc60dfc7ad95b3d8139515620f", 16),
      a: new BigInteger("e95e4a5f737059dc60dfc7ad95b3d8139515620c", 16),
      b: new BigInteger("7a556b6dae535b7b51ed2c4d7daa7a0b5c55f380", 16),
      g: new BigInteger("04b199b13b9b34efc1397e64baeb05acc265ff2378add6718b7c7c1961f0991b842443772152c9e0ad", 16),
      n: new BigInteger("e95e4a5f737059dc60df5991d45029409e60fc09", 16),
      h: new BigInteger("1", 16),
      seed: null
  );
  _registerFpStandardCurve("brainpoolp192r1",
      q: new BigInteger("c302f41d932a36cda7a3463093d18db78fce476de1a86297", 16),
      a: new BigInteger("6a91174076b1e0e19c39c031fe8685c1cae040e5c69a28ef", 16),
      b: new BigInteger("469a28ef7c28cca3dc721d044f4496bcca7ef4146fbf25c9", 16),
      g: new BigInteger("04c0a0647eaab6a48753b033c56cb0f0900a2f5c4853375fd614b690866abd5bb88b5f4828c1490002e6773fa2fa299b8f", 16),
      n: new BigInteger("c302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1", 16),
      h: new BigInteger("1", 16),
      seed: null
  );
  _registerFpStandardCurve("brainpoolp192t1",
      q: new BigInteger("c302f41d932a36cda7a3463093d18db78fce476de1a86297", 16),
      a: new BigInteger("c302f41d932a36cda7a3463093d18db78fce476de1a86294", 16),
      b: new BigInteger("13d56ffaec78681e68f9deb43b35bec2fb68542e27897b79", 16),
      g: new BigInteger("043ae9e58c82f63c30282e1fe7bbf43fa72c446af6f4618129097e2c5667c2223a902ab5ca449d0084b7e5b3de7ccc01c9", 16),
      n: new BigInteger("c302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1", 16),
      h: new BigInteger("1", 16),
      seed: null
  );
  _registerFpStandardCurve("brainpoolp224r1",
      q: new BigInteger("d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff", 16),
      a: new BigInteger("68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43", 16),
      b: new BigInteger("2580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400b", 16),
      g: new BigInteger("040d9029ad2c7e5cf4340823b2a87dc68c9e4ce3174c1e6efdee12c07d58aa56f772c0726f24c6b89e4ecdac24354b9e99caa3f6d3761402cd", 16),
      n: new BigInteger("d7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f", 16),
      h: new BigInteger("1", 16),
      seed: null
  );
  _registerFpStandardCurve("brainpoolp224t1",
      q: new BigInteger("d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff", 16),
      a: new BigInteger("d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0fc", 16),
      b: new BigInteger("4b337d934104cd7bef271bf60ced1ed20da14c08b3bb64f18a60888d", 16),
      g: new BigInteger("046ab1e344ce25ff3896424e7ffe14762ecb49f8928ac0c76029b4d5800374e9f5143e568cd23f3f4d7c0d4b1e41c8cc0d1c6abd5f1a46db4c", 16),
      n: new BigInteger("d7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f", 16),
      h: new BigInteger("1", 16),
      seed: null
  );
  _registerFpStandardCurve("brainpoolp256r1",
      q: new BigInteger("a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377", 16),
      a: new BigInteger("7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9", 16),
      b: new BigInteger("26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6", 16),
      g: new BigInteger("048bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997", 16),
      n: new BigInteger("a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7", 16),
      h: new BigInteger("1", 16),
      seed: null
  );
  _registerFpStandardCurve("brainpoolp256t1",
      q: new BigInteger("a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377", 16),
      a: new BigInteger("a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5374", 16),
      b: new BigInteger("662c61c430d84ea4fe66a7733d0b76b7bf93ebc4af2f49256ae58101fee92b04", 16),
      g: new BigInteger("04a3e8eb3cc1cfe7b7732213b23a656149afa142c47aafbc2b79a191562e1305f42d996c823439c56d7f7b22e14644417e69bcb6de39d027001dabe8f35b25c9be", 16),
      n: new BigInteger("a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7", 16),
      h: new BigInteger("1", 16),
      seed: null
  );
  _registerFpStandardCurve("brainpoolp320r1",
      q: new BigInteger("d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27", 16),
      a: new BigInteger("3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f492f375a97d860eb4", 16),
      b: new BigInteger("520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd884539816f5eb4ac8fb1f1a6", 16),
      g: new BigInteger("0443bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c710af8d0d39e2061114fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7d35245d1692e8ee1", 16),
      n: new BigInteger("d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311", 16),
      h: new BigInteger("1", 16),
      seed: null
  );
  _registerFpStandardCurve("brainpoolp320t1",
      q: new BigInteger("d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e27", 16),
      a: new BigInteger("d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28fcd412b1f1b32e24", 16),
      b: new BigInteger("a7f561e038eb1ed560b3d147db782013064c19f27ed27c6780aaf77fb8a547ceb5b4fef422340353", 16),
      g: new BigInteger("04925be9fb01afc6fb4d3e7d4990010f813408ab106c4f09cb7ee07868cc136fff3357f624a21bed5263ba3a7a27483ebf6671dbef7abb30ebee084e58a0b077ad42a5a0989d1ee71b1b9bc0455fb0d2c3", 16),
      n: new BigInteger("d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e98691555b44c59311", 16),
      h: new BigInteger("1", 16),
      seed: null
  );
  _registerFpStandardCurve("brainpoolp384r1",
      q: new BigInteger("8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53", 16),
      a: new BigInteger("7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f8aa5814a503ad4eb04a8c7dd22ce2826", 16),
      b: new BigInteger("4a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57cb4390295dbc9943ab78696fa504c11", 16),
      g: new BigInteger("041d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8e826e03436d646aaef87b2e247d4af1e8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff99129280e4646217791811142820341263c5315", 16),
      n: new BigInteger("8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565", 16),
      h: new BigInteger("1", 16),
      seed: null
  );
  _registerFpStandardCurve("brainpoolp384t1",
      q: new BigInteger("8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec53", 16),
      a: new BigInteger("8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123acd3a729901d1a71874700133107ec50", 16),
      b: new BigInteger("7f519eada7bda81bd826dba647910f8c4b9346ed8ccdc64e4b1abd11756dce1d2074aa263b88805ced70355a33b471ee", 16),
      g: new BigInteger("0418de98b02db9a306f2afcd7235f72a819b80ab12ebd653172476fecd462aabffc4ff191b946a5f54d8d0aa2f418808cc25ab056962d30651a114afd2755ad336747f93475b7a1fca3b88f2b6a208ccfe469408584dc2b2912675bf5b9e582928", 16),
      n: new BigInteger("8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7cf3ab6af6b7fc3103b883202e9046565", 16),
      h: new BigInteger("1", 16),
      seed: null
  );
  _registerFpStandardCurve("brainpoolp512r1",
      q: new BigInteger("aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3", 16),
      a: new BigInteger("7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca", 16),
      b: new BigInteger("3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723", 16),
      g: new BigInteger("0481aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098eff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f8227dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892", 16),
      n: new BigInteger("aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069", 16),
      h: new BigInteger("1", 16),
      seed: null
  );
  _registerFpStandardCurve("brainpoolp512t1",
      q: new BigInteger("aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3", 16),
      a: new BigInteger("aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca703308717d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f0", 16),
      b: new BigInteger("7cbbbcf9441cfab76e1890e46884eae321f70c0bcb4981527897504bec3e36a62bcdfa2304976540f6450085f2dae145c22553b465763689180ea2571867423e", 16),
      g: new BigInteger("04640ece5c12788717b9c1ba06cbc2a6feba85842458c56dde9db1758d39c0313d82ba51735cdb3ea499aa77a7d6943a64f7a3f25fe26f06b51baa2696fa9035da5b534bd595f5af0fa2c892376c84ace1bb4e3019b71634c01131159cae03cee9d9932184beef216bd71df2dadf86a627306ecff96dbb8bace198b61e00f8b332", 16),
      n: new BigInteger("aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069", 16),
      h: new BigInteger("1", 16),
      seed: null
  );
}

void _registerX962EccStandardCurves() {
  _registerFpStandardCurve("prime192v1",
      q: new BigInteger("fffffffffffffffffffffffffffffffeffffffffffffffff", 16),
      a: new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16),
      b: new BigInteger("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16),
      g: new BigInteger("03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16),
      n: new BigInteger("ffffffffffffffffffffffff99def836146bc9b1b4d22831", 16),
      h: new BigInteger("1", 16),
      seed: new BigInteger("3045ae6fc8422f64ed579528d38120eae12196d5", 16)
  );
  _registerFpStandardCurve("prime192v2",
      q: new BigInteger("fffffffffffffffffffffffffffffffeffffffffffffffff", 16),
      a: new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16),
      b: new BigInteger("cc22d6dfb95c6b25e49c0d6364a4e5980c393aa21668d953", 16),
      g: new BigInteger("03eea2bae7e1497842f2de7769cfe9c989c072ad696f48034a", 16),
      n: new BigInteger("fffffffffffffffffffffffe5fb1a724dc80418648d8dd31", 16),
      h: new BigInteger("1", 16),
      seed: new BigInteger("31a92ee2029fd10d901b113e990710f0d21ac6b6", 16)
  );
  _registerFpStandardCurve("prime192v3",
      q: new BigInteger("fffffffffffffffffffffffffffffffeffffffffffffffff", 16),
      a: new BigInteger("fffffffffffffffffffffffffffffffefffffffffffffffc", 16),
      b: new BigInteger("22123dc2395a05caa7423daeccc94760a7d462256bd56916", 16),
      g: new BigInteger("027d29778100c65a1da1783716588dce2b8b4aee8e228f1896", 16),
      n: new BigInteger("ffffffffffffffffffffffff7a62d031c83f4294f640ec13", 16),
      h: new BigInteger("1", 16),
      seed: new BigInteger("c469684435deb378c4b65ca9591e2a5763059a2e", 16)
  );
  _registerFpStandardCurve("prime239v1",
      q: new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff", 16),
      a: new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16),
      b: new BigInteger("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a", 16),
      g: new BigInteger("020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf", 16),
      n: new BigInteger("7fffffffffffffffffffffff7fffff9e5e9a9f5d9071fbd1522688909d0b", 16),
      h: new BigInteger("1", 16),
      seed: new BigInteger("e43bb460f0b80cc0c0b075798e948060f8321b7d", 16)
  );
  _registerFpStandardCurve("prime239v2",
      q: new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff", 16),
      a: new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16),
      b: new BigInteger("617fab6832576cbbfed50d99f0249c3fee58b94ba0038c7ae84c8c832f2c", 16),
      g: new BigInteger("0238af09d98727705120c921bb5e9e26296a3cdcf2f35757a0eafd87b830e7", 16),
      n: new BigInteger("7fffffffffffffffffffffff800000cfa7e8594377d414c03821bc582063", 16),
      h: new BigInteger("1", 16),
      seed: new BigInteger("e8b4011604095303ca3b8099982be09fcb9ae616", 16)
  );
  _registerFpStandardCurve("prime239v3",
      q: new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007fffffffffff", 16),
      a: new BigInteger("7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc", 16),
      b: new BigInteger("255705fa2a306654b1f4cb03d6a750a30c250102d4988717d9ba15ab6d3e", 16),
      g: new BigInteger("036768ae8e18bb92cfcf005c949aa2c6d94853d0e660bbf854b1c9505fe95a", 16),
      n: new BigInteger("7fffffffffffffffffffffff7fffff975deb41b3a6057c3c432146526551", 16),
      h: new BigInteger("1", 16),
      seed: new BigInteger("7d7374168ffe3471b60a857686a19475d3bfa2ff", 16)
  );
  _registerFpStandardCurve("prime256v1",
      q: new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16),
      a: new BigInteger("ffffffff00000001000000000000000000000000fffffffffffffffffffffffc", 16),
      b: new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16),
      g: new BigInteger("036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
      n: new BigInteger("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16),
      h: new BigInteger("1", 16),
      seed: new BigInteger("c49d360886e704936a6678e1139d26b7819f7e90", 16)
  );
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

void _registerFpStandardCurve( String name, {BigInteger q, BigInteger a, BigInteger b, BigInteger g, BigInteger n,
  BigInteger h, BigInteger seed } ) {

  var curve = new fp.ECCurve(q,a,b);
  var seedBytes = (seed == null) ? null : seed.toByteArray();
  ECDomainParameters.registry[name] = (_)
    => new ECDomainParametersImpl( name, curve, curve.decodePoint( g.toByteArray() ), n, h, seedBytes );
}

