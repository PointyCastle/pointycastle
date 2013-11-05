// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com  
// Use of this source code is governed by a LGPL v3 license. 
// See the LICENSE file for more information.

library cipher.test.paddings.pkcs7_test;

import "package:cipher/paddings/pkcs7.dart";

import "../test/padding_tests.dart";

void main() {

  runPaddingTest( new PKCS7Padding(), null, 
      "123456789", 16, 
      "31323334353637383907070707070707" 
  );
  runPaddingTest( new PKCS7Padding(), null, 
      "", 16, 
      "10101010101010101010101010101010" 
  );
  
}

