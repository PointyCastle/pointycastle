library pointycastle.src.registry.impl;

import 'package:pointycastle/digests/md2.dart';
import 'package:pointycastle/digests/md4.dart';
import 'package:pointycastle/digests/md5.dart';
import 'package:pointycastle/digests/ripemd128.dart';
import 'package:pointycastle/digests/ripemd160.dart';
import 'package:pointycastle/digests/ripemd256.dart';
import 'package:pointycastle/digests/ripemd320.dart';
import 'package:pointycastle/digests/sha1.dart';
import 'package:pointycastle/digests/sha224.dart';
import 'package:pointycastle/digests/sha256.dart';
import 'package:pointycastle/digests/sha3.dart';
import 'package:pointycastle/digests/sha384.dart';
import 'package:pointycastle/digests/sha512.dart';
import 'package:pointycastle/digests/sha512t.dart';
import 'package:pointycastle/digests/tiger.dart';
import 'package:pointycastle/digests/whirlpool.dart';
import 'package:pointycastle/src/registry/registry.dart';

void registerFactories(FactoryRegistry registry) {
  _registerDigests(registry);
}

void _registerDigests(FactoryRegistry registry) {
  registry.register(MD2Digest.FACTORY_CONFIG);
  registry.register(MD4Digest.FACTORY_CONFIG);
  registry.register(MD5Digest.FACTORY_CONFIG);
  registry.register(RIPEMD128Digest.FACTORY_CONFIG);
  registry.register(RIPEMD160Digest.FACTORY_CONFIG);
  registry.register(RIPEMD256Digest.FACTORY_CONFIG);
  registry.register(RIPEMD320Digest.FACTORY_CONFIG);
  registry.register(SHA1Digest.FACTORY_CONFIG);
  registry.register(SHA3Digest.FACTORY_CONFIG);
  registry.register(SHA224Digest.FACTORY_CONFIG);
  registry.register(SHA256Digest.FACTORY_CONFIG);
  registry.register(SHA384Digest.FACTORY_CONFIG);
  registry.register(SHA512Digest.FACTORY_CONFIG);
  registry.register(SHA512tDigest.FACTORY_CONFIG);
  registry.register(TigerDigest.FACTORY_CONFIG);
  registry.register(WhirlpoolDigest.FACTORY_CONFIG);
}
