part of cipher_test_helpers;

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

