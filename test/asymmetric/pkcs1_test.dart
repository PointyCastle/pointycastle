// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.asymmetric.pkcs1_test;

import "package:cipher/cipher.dart";
import "package:cipher/impl/base.dart";

import "../test/asymmetric_block_cipher_tests.dart";
import "../test/src/null_asymmetric_block_cipher.dart";
import "../test/src/null_secure_random.dart";

/// NOTE: the expected results for these tests are computed using the Java version of Bouncy Castle
void main() {

  initCipher();
  AsymmetricBlockCipher.registry["Null"] = (_) => new NullAsymmetricBlockCipher(70,70);

  var encpar = () => new ParametersWithRandom(new PrivateKeyParameter(new NullPrivateKey()), new NullSecureRandom());
  var decpar = () => new ParametersWithRandom(new PublicKeyParameter(new NullPublicKey()), new NullSecureRandom());

  runAsymmetricBlockCipherTests(new AsymmetricBlockCipher("Null/PKCS1"), encpar, decpar, [

    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "01ffffffffffffffffffff004c6f72656d20697073756d20646f6c6f722073697420616d65742c20636f6e73656374657475722061646970697363696e6720656c69742e2e2e",

    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme",
    "01ffffffffffffffff00456e20756e206c75676172206465204c61204d616e6368612c206465206375796f206e6f6d627265206e6f2071756965726f2061636f726461726d65",

  ]);

}

