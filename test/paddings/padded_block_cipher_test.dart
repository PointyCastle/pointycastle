// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library pointycastle.test.padded_block_cipher_test;

import "package:pointycastle/pointycastle.dart";

import "package:test/test.dart";

import "../test/src/null_block_cipher.dart";
import "../test/src/helpers.dart";

void main() {

  var params = new PaddedBlockCipherParameters(null, null);
  var pbc = new PaddedBlockCipher("Null/PKCS7");

  group("PaddedBlockCipher:", () {
    group("partial blocks:", () {
      var sequence = createUint8ListFromSequentialNumbers(24);
      var paddedSequenceHex = "000102030405060708090a0b0c0d0e0f10111213141516170808080808080808";

      test("cipher", () {
        pbc.init(true, params);

        var out = pbc.process(sequence);

        expect(formatBytesAsHexString(out), paddedSequenceHex);
      });

      test("decipher", () {
        pbc.init(false, params);

        var out = pbc.process(createUint8ListFromHexString(paddedSequenceHex));

        expect(formatBytesAsHexString(out), formatBytesAsHexString(sequence));
      });
    });

    group("whole blocks:", () {
      var sequence = createUint8ListFromSequentialNumbers(16);
      var paddedSequenceHex = "000102030405060708090a0b0c0d0e0f10101010101010101010101010101010";

      test("cipher", () {
        pbc.init(true, params);

        var out = pbc.process(sequence);

        expect(formatBytesAsHexString(out), paddedSequenceHex);
      });

      test("decipher", () {
        pbc.init(false, params);

        var out = pbc.process(createUint8ListFromHexString(paddedSequenceHex));

        expect(formatBytesAsHexString(out), formatBytesAsHexString(sequence));
      });
    });
  });
}
