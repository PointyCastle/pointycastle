// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.test.entropy.url_entropy_source_test;

import "package:cipher/cipher.dart";
import "package:cipher/impl/server.dart";
import "package:unittest/unittest.dart";

void main() {

  initCipher();

  var source = new EntropySource("https://www.random.org/cgi-bin/randbyte?nbytes={count}&format=f");
  const count = 1024;

  group( "${source.sourceName}:", () {

    test( "getBytes:", () {

      return source.getBytes(count).then( (bytes) {
        //print(bytes);
        expect( bytes.length, count );

        //var sum = bytes.fold(0, (prev, element) => prev + element);
        //var avg = sum/bytes.length;
        //print("AVG = $avg");
        //expect( avg>128-4, true );
        //expect( avg<128+4, true );
      });

    });

  });

}


