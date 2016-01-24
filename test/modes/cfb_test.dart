// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

library pointycastle.test.modes.cfb_test;

import "dart:typed_data";

import "package:pointycastle/pointycastle.dart";

import "../test/block_cipher_tests.dart";
import "../test/src/null_block_cipher.dart";

void main() {

  final iv = new Uint8List.fromList( [0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xAA,0xBB,0xCC,0xDD,0xEE,0xFF] );
  final params = new ParametersWithIV(null, iv);

  runBlockCipherTests( new BlockCipher("Null/CFB-128"), params, [

    "Lorem ipsum dolor sit amet, consectetur adipiscing elit ........",
    "4c7e505629750f07fbecc79ba8b282903e5e233f5d556e6a9e98ebbbcbddece35b3d575a29201c4afffc82cba2ae8f8a355a773f4549686ad1d2ace58c80a1a4",

    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme ...",
    "457f02462a750a02eff8d89ba8b8ceb3245f4f2744166263c3d8bcfe88dbbbca4b7f214829741006e3b6d3def9aed2af391001294a1b626282c4bebbd980fc81",

  ] );

}

