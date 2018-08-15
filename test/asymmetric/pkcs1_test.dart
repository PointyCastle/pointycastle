// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.test.asymmetric.pkcs1_test;

import "package:pointycastle/pointycastle.dart";

import "../test/asymmetric_block_cipher_tests.dart";
import "../test/src/null_asymmetric_block_cipher.dart";
import "../test/src/null_secure_random.dart";

void main() {
  initCipher();
  AsymmetricBlockCipher.registry["Null"] =
      (_) => new NullAsymmetricBlockCipher(70, 70);

  var pubpar = () => new ParametersWithRandom(
      new PublicKeyParameter(new NullPublicKey()), new NullSecureRandom());
  var privpar = () => new ParametersWithRandom(
      new PrivateKeyParameter(new NullPrivateKey()), new NullSecureRandom());

  runAsymmetricBlockCipherTests(
      new AsymmetricBlockCipher("Null/PKCS1"), pubpar, privpar, [
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "020a010203040506070809004c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e73656374657475722061646970697363696e6720656c69742e2e2e",
    "01ffffffffffffffffffff004c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e73656374657475722061646970697363696e6720656c69742e2e2e",
    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme",
    "02080102030405060700456e20756e206c75676172206465204c61204d616e6368612c206465206375796f206e6f6d627265206e6f2071756965726f2061636f726461726d65",
    "01ffffffffffffffff00456e20756e206c75676172206465204c61204d616e6368612c206465206375796f206e6f6d627265206e6f2071756965726f2061636f726461726d65",
  ]);
}
