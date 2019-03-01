// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.test.test.mac_tests;

import "dart:typed_data" show Uint8List;

import "package:test/test.dart";
import "package:pointycastle/pointycastle.dart";

import "./src/helpers.dart";

class PlainTextDigestPair {
  PlainTextDigestPair(this.plainText, this.hexDigestText);

  final Uint8List plainText;
  final String hexDigestText;
}

void runMacTests(Mac mac, List<PlainTextDigestPair> plainDigestTextPairs) {
  group("${mac.algorithmName}:", () {
    group("digest:", () {
      for (var i = 0; i < plainDigestTextPairs.length; i++) {
        var plainText = plainDigestTextPairs[i].plainText;
        var digestText = plainDigestTextPairs[i].hexDigestText;

        test("${formatAsTruncated(plainText.toString())}",
            () => _runMacTest(mac, plainText, digestText));
      }
    });
  });
}

void _runMacTest(Mac mac, Uint8List plainText, String expectedHexDigestText) {
  mac.reset();

  var out = mac.process(plainText);
  var hexOut = formatBytesAsHexString(out);

  expect(hexOut, equals(expectedHexDigestText));
}
