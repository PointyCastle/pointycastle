// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library cipher.test.test.registry_tests;

import "package:cipher/cipher.dart";

import "package:unittest/unittest.dart";
import "package:unittest/matcher.dart";

void testAsymmetricBlockCipher(String algorithmName) {
  var cipher = new AsymmetricBlockCipher(algorithmName);
  expect(cipher, new isInstanceOf<AsymmetricBlockCipher>("AsymmetricBlockCipher"));
  expect(cipher.algorithmName, algorithmName);
}

void testBlockCipher(String algorithmName) {
  var cipher = new BlockCipher(algorithmName);
  expect(cipher, new isInstanceOf<BlockCipher>("BlockCipher"));
  expect(cipher.algorithmName, algorithmName);
}

void testDigest(String algorithmName) {
  var digest = new Digest(algorithmName);
  expect(digest, new isInstanceOf<Digest>("Digest"));
  expect(digest.algorithmName, algorithmName);
}

void testECDomainParameters(String domainName) {
  var domain = new ECDomainParameters(domainName);
  expect(domain, new isInstanceOf<ECDomainParameters>("ECDomainParameters"));
  expect(domain.domainName, domainName);
}

void testKeyDerivator(String algorithmName) {
  var kf = new KeyDerivator(algorithmName);
  expect(kf, new isInstanceOf<KeyDerivator>("KeyDerivator"));
  expect(kf.algorithmName, algorithmName);
}

void testKeyGenerator(String algorithmName) {
  var kg = new KeyGenerator(algorithmName);
  expect(kg, new isInstanceOf<KeyGenerator>("KeyGenerator"));
  expect(kg.algorithmName, algorithmName);
}

void testMac(String algorithmName) {
  var mac = new Mac(algorithmName);
  expect(mac, new isInstanceOf<Mac>("Mac"));
  expect(mac.algorithmName, algorithmName);
}

void testPaddedBlockCipher(String algorithmName) {
  var parts = algorithmName.split("/");

  var pbc = new PaddedBlockCipher(algorithmName);
  expect(pbc, new isInstanceOf<PaddedBlockCipher>("PaddedBlockCipher"));
  expect(pbc.algorithmName, algorithmName);

  var padding = pbc.padding;
  expect(padding, new isInstanceOf<Padding>("Padding"));
  expect(padding.algorithmName, equals(parts[2]));

  var cbc = pbc.cipher;
  expect(cbc, new isInstanceOf<BlockCipher>("BlockCipher"));
  expect(cbc.algorithmName, equals("${parts[0]}/${parts[1]}"));
}

void testPadding(String algorithmName) {
  var padding = new Padding(algorithmName);
  expect(padding, new isInstanceOf<Padding>("Padding"));
  expect(padding.algorithmName, algorithmName);
}

void testSecureRandom(String algorithmName) {
  var rnd = new SecureRandom(algorithmName);
  expect(rnd, new isInstanceOf<SecureRandom>("SecureRandom"));
  expect(rnd.algorithmName, algorithmName);
}

void testSigner(String algorithmName) {
  var signer = new Signer(algorithmName);
  expect(signer, new isInstanceOf<Signer>("Signer"));
  expect(signer.algorithmName, algorithmName);
}

void testStreamCipher(String algorithmName) {
  var cipher = new StreamCipher(algorithmName);
  expect(cipher, new isInstanceOf<StreamCipher>("StreamCipher"));
  expect(cipher.algorithmName, algorithmName);
}


