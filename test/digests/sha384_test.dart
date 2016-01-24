// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

library pointycastle.test.digests.sha384_test;

import "package:pointycastle/pointycastle.dart";

import "../test/digest_tests.dart";

void main() {



  runDigestTests( new Digest("SHA-384"), [

    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "3b6ae66bd9a8c2e447051836d5b74326037a9f0f875c904f6dec446aa3cd18b9ae4618cc63abc35a1d68a7acf45835a1",

    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme...",
    "198d957423fab1fc8489ba431629ff0d6350e8f8fccd68dd7fa02b344234491d99a43ec454521d19e304ad95c9507079",

  ]);

}

