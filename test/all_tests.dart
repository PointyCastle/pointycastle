// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cpiher.test.all_tests;

import "./adapters/stream_cipher_adapters_test.dart" as stream_cipher_adapters_test;

import "./digests/ripemd160_test.dart" as ripemd160_test;

import "./engines/aes_fast_test.dart" as aes_fast_test;
import "./engines/null_block_cipher_test.dart" as null_block_cipher_test;
import "./engines/null_stream_cipher_test.dart" as null_stream_cipher_test;
import "./engines/salsa20_test.dart" as salsa20_test;

import "./modes/sic_test.dart" as sic_test;
import "./modes/cbc_test.dart" as cbc_test;

import "./paddings/padded_block_cipher_test.dart" as padded_block_cipher_test;
import "./paddings/pkcs7_test.dart" as pkcs7_test;

import "./signers/ecdsa_signer_test.dart" as ecdsa_signer_test;

import "./src/registry_test.dart" as registry_test;
import "./src/ufixnum_test.dart" as ufixnum_test;

void main() {

  // adapters
  stream_cipher_adapters_test.main();

  // digests
  ripemd160_test.main();

  // engines
  aes_fast_test.main();
  null_block_cipher_test.main();
  null_stream_cipher_test.main();
  salsa20_test.main();

  // modes
  sic_test.main();
  cbc_test.main();

  // paddings
  padded_block_cipher_test.main();
  pkcs7_test.main();

	// signers
	ecdsa_signer_test.main();

  // src
  registry_test.main();
  ufixnum_test.main();

}