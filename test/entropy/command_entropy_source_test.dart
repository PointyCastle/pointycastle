// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.entropy.command_entropy_source_test;

import "package:cipher/cipher.dart";
import "package:cipher/impl/server.dart";
import "package:unittest/unittest.dart";

void main() {

  initCipher();

  var source = new EntropySource("command:echo|12345");
  const count = 32;

  group("${source.sourceName}:", () {

    test("getBytes:", () {

      return source.getBytes(count).then((bytes) {
        expect(bytes.length, count);
        expect(bytes, "12345123451234512345123451234512".codeUnits);
      });

    });

  });

}

