// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.engines.null_stream_cipher_test;

import "package:cipher/engines/null_stream_cipher.dart";

import "../test/helpers.dart";
import "../test/stream_cipher_tests.dart";

void main() {

  runStreamCipherTests( new NullStreamCipher(), null, [

    "Lorem ipsum dolor sit amet, consectetur adipiscing elit",
    formatBytesAsHexString( createUint8ListFromString (
        "Lorem ipsum dolor sit amet, consectetur adipiscing elit"
    )),

    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme",
    formatBytesAsHexString( createUint8ListFromString (
      "En un lugar de La Mancha, de cuyo nombre no quiero acordarme"
    )),

  ] );

}

