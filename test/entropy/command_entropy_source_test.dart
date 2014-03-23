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
        expectValid(bytes);
      });

    });

  });

}

void expectValid(List<int> bytes) {
  switch (bytes.length) {
    case 1:
      expect(bytes.sublist(0, 1), "1".codeUnits);
      break;

    case 2:
      expect(bytes.sublist(0, 2), "12".codeUnits);
      break;

    case 3:
      expect(bytes.sublist(0, 3), "123".codeUnits);
      break;

    case 4:
      expect(bytes.sublist(0, 4), "1234".codeUnits);
      break;

    default:
      expect(bytes.sublist(0, 5), "12345".codeUnits);
  }

  for (int i = 5; i < bytes.length; i++) {
    if ((bytes[i] != 10) && (bytes[i] != 13)) {
      return expectValid(bytes.sublist(i));
    }
  }
}

