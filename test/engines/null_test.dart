library null_test;

import "package:cipher/engines/null.dart";

import "../test/helpers.dart";
import "../test/block_cipher_tests.dart";

void main() {

  runBlockCipherTests( new NullBlockCipher(), null, [
                                                
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit ........",
    formatBytesAsHexString( createUint8ListFromString (
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit ........"
    )),

    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme ...",
    formatBytesAsHexString( createUint8ListFromString (
      "En un lugar de La Mancha, de cuyo nombre no quiero acordarme ..."
    )),
                                                
  ] );

}

