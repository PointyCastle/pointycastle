library all_tests;

import "./engines/aes_fast_test.dart" as aes;
import "./engines/salsa20_test.dart" as salsa20;

import "./modes/sic_test.dart" as sic;


void main() {
  aes.main();
  salsa20.main();
  sic.main();
}