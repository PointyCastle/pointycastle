// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.key_derivators.pbkdf2_test;

import 'package:cipher/cipher.dart';

import 'package:cipher/key_derivators/pbkdf2.dart';
import "package:cipher/params/pbkdf2_parameters.dart";

import '../test/key_derivators_tests.dart';
import '../test/helpers.dart';


/// NOTE: the expected results for these tests are computed using the Java
void main() {

  initCipher();

  var salt = createUint8ListFromString("salt");
  var pkcs = new PBKDF2KeyDerivator(new Mac("SHA-1/HMAC"));
  var params = new Pbkdf2Parameters(salt, 100, 16);

  runKeyDerivatorTests( pkcs, [

    params,
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit...",
    "12aaf52b2fc239db41778c59d0e3c927",

    params,
    "En un lugar de La Mancha, de cuyo nombre no quiero acordarme...",
    "5b78b99ac2cc6b6626558f53c7490f4a",

  ]);

}

