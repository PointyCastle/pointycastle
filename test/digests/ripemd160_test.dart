// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com  
// Use of this source code is governed by a LGPL v3 license. 
// See the LICENSE file for more information.

library cipher.test.digests.ripemd160_test;

import "package:cipher/digests/ripemd160.dart";

import "../test/digest_tests.dart";


/**
 * NOTE: the expected results for these tests are computed using the Java
 * version of Bouncy Castle (except for abc and empty string which were taken
 * from http://homes.esat.kuleuven.be/~bosselae/ripemd160.html).
 */
void main() {

  runDigestTests( new RIPEMD160Digest(), [

    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "7cc186f1d641709ec2bd363b10d3d66f122b365e",

    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme ...",
    "48573da6caf89431a195e70f305f0df3b4f7ace6",

    "abc",
    "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",

    "",
    "9c1185a5c5e9fc54612808977ee8f548b2258d31",

  ]);
  
}

