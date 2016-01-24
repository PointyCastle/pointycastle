// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library pointycastle.test.digests.sha512t_test;

import "package:pointycastle/pointycastle.dart";

import "../test/digest_tests.dart";

void main() {



  runDigestTests( new Digest("SHA-512/488"), [

    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "77c5a401110133e531d1acf33ea6010d8d8149f9804310b6d32a69033aee079e88603166478069b1d4622030a508930a062199150f66462e26063266e5",

    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme...",
    "149a6a1e7f9741b56186b01c9195e1c5a003197ff559604653ea176c6d6e75c7cd117d3105cf10bc8d1f24e46c98c5a8b2fa2e53c16e95ada867b20ea1",

  ]);

}

