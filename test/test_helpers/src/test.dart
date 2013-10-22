part of cipher_test_helpers;

void runStreamCipherTest( StreamCipher cipher, String plainTextString, String expectedHexCipherText ) {
  var plainText = createUint8ListFromString( plainTextString );
  var cipherText = processStream( cipher, plainText );
  var hexCipherText = formatBytesAsHexString(cipherText);

  expect( hexCipherText, equals(expectedHexCipherText) );
}

void runStreamDecipherTest( StreamCipher cipher, String hexCipherText, String expectedPlainText ) {
  var cipherText = createUint8ListFromHexString(hexCipherText);
  var plainText = processStream( cipher, cipherText );

  expect( new String.fromCharCodes(plainText), equals(expectedPlainText) );
}

void runStreamCipherDecipherTest( StreamCipher cipher, CipherParameters params, Uint8List plainText ) {
  cipher.init( true, params );
  var cipherText = processStream( cipher, plainText );

  cipher..reset()
    ..init( false, params );
  var plainTextAgain = processStream( cipher, cipherText );

  expect( plainTextAgain, equals(plainText) );
}
