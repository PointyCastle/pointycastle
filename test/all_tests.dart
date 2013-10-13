library all_tests;

import "./digests/ripemd160_test.dart" as ripemd160;

import "./engines/aes_fast_test.dart" as aes;
import "./engines/salsa20_test.dart" as salsa20;

import "./modes/sic_test.dart" as sic;


void main() {
  ripemd160.main();
  aes.main();
  salsa20.main();
  sic.main();
}