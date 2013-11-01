// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com  
// Use of this source code is governed by a LGPL v3 license. 
// See the LICENSE file for more information.

library cpiher.test.all_tests;

import "./factories_test.dart" as factories;

import "./digests/ripemd160_test.dart" as ripemd160;

import "./engines/aes_fast_test.dart" as aes_fast;
import "./engines/null_cipher_test.dart" as null_cipher;
import "./engines/salsa20_test.dart" as salsa20;

import "./modes/sic_test.dart" as sic;

import "./src/util_test.dart" as util;

void main() {
  
  // generic
  factories.main();

  // digests
  ripemd160.main();
  
  // engines
  aes_fast.main();
  null_cipher.main();
  salsa20.main();
  
  // modes
  sic.main();
  
  // src
  util.main();

}