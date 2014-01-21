// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.all_tests;

import "./block/aes_fast_test.dart" as aes_fast_test;

import "./digests/md2_test.dart" as md2_test;
import "./digests/md4_test.dart" as md4_test;
import "./digests/ripemd160_test.dart" as ripemd160_test;
import "./digests/sha1_test.dart" as sha1_test;
import "./digests/sha256_test.dart" as sha256_test;

// These two cannot be run as they are integration tests (need external dependencies)
import "./entropy/file_entropy_source_test.dart" as dev_random_entropy_source_test;
import "./entropy/url_entropy_source_test.dart" as random_org_entropy_source_test;

import "./key_derivators/pbkdf2_test.dart" as pbkdf2_test;
import "./key_derivators/scrypt_test.dart" as scrypt_test;

import "./key_generators/ec_key_generator_test.dart" as ec_key_generator_test;

import "./macs/hmac_test.dart" as hmac_test;

import "./modes/cbc_test.dart" as cbc_test;
import "./modes/cfb_test.dart" as cfb_test;
import "./modes/ecb_test.dart" as ecb_test;
import "./modes/gctr_test.dart" as gctr_test;
import "./modes/ofb_test.dart" as ofb_test;
import "./modes/sic_test.dart" as sic_test;

import "./paddings/padded_block_cipher_test.dart" as padded_block_cipher_test;
import "./paddings/pkcs7_test.dart" as pkcs7_test;

import "./random/auto_seed_block_ctr_random_test.dart" as auto_seed_block_ctr_random_test;
import "./random/block_ctr_random_test.dart" as block_ctr_random_test;

import "./signers/ecdsa_signer_test.dart" as ecdsa_signer_test;

import "./stream/salsa20_test.dart" as salsa20_test;

import "./src/registry_test.dart" as registry_test;
import "./src/ufixnum_test.dart" as ufixnum_test;
import "./src/adapters/stream_cipher_adapters_test.dart" as stream_cipher_adapters_test;

void main() {

  // block ciphers
  aes_fast_test.main();

  // digests
  md2_test.main();
  md4_test.main();
  ripemd160_test.main();
  sha1_test.main();
  sha256_test.main();

  // entropy sources (some commented because they need external resources)
  //dev_random_entropy_source_test.main();
  //random_org_entropy_source_test.main();

  // key derivators
  pbkdf2_test.main();
  scrypt_test.main();

  // key generators
  ec_key_generator_test.main();

  // MACs
  hmac_test.main();

  // modes
  cbc_test.main();
  cfb_test.main();
  ecb_test.main();
  gctr_test.main();
  ofb_test.main();
  sic_test.main();

  // paddings
  padded_block_cipher_test.main();
  pkcs7_test.main();

  // secure randoms
  auto_seed_block_ctr_random_test.main();
  block_ctr_random_test.main();

  // signers
  ecdsa_signer_test.main();

  // stream ciphers
  salsa20_test.main();

  // src
  registry_test.main();
  ufixnum_test.main();

  // src/adapters
  stream_cipher_adapters_test.main();

}