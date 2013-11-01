// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com  
// Use of this source code is governed by a LGPL v3 license. 
// See the LICENSE file for more information.

part of cipher.test.test.helpers;

Uint8List processBlocks( BlockCipher cipher, Uint8List inp ) {
  var out = new Uint8List(inp.lengthInBytes);
  for( var offset=0 ; offset<inp.lengthInBytes ; offset+=cipher.blockSize ) {
    cipher.processBlock( inp, offset, out, offset );
  }
  return out;
}

Uint8List processStream( StreamCipher cipher, Uint8List inp ) {
  var out = new Uint8List(inp.lengthInBytes);
  cipher.processBytes(inp, 0, inp.length, out, 0);
  return out;
}

