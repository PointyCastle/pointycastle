library example.aes;

import "dart:convert";
import "dart:typed_data";

import "package:hex/hex.dart";
import "package:pointycastle/pointycastle.dart";

void main() {
  // Key must be multiple of block size (16 bytes).
  var key = new Digest("SHA-256").process(
      utf8.encode("correct horse battery staple"));
  // Can be anything.
  var message = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed d"
      "o eiusmod tempor incididunt ut labore et dolore magna aliqua.";
  // The initialization vector must be unique for every message, so it is a
  // good idea to use a message digest as the IV.
  // IV must be equal to block size (16 bytes).
  var iv = new Digest("SHA-256").process(utf8.encode(message)).sublist(0, 16);
  // The parameters your cipher will need. (PKCS7 does not need params.)
  CipherParameters params = new PaddedBlockCipherParameters(
      new ParametersWithIV(new KeyParameter(key), iv), null);

  print("Message: \n$message");

  ////////////////
  // Encrypting //
  ////////////////

  // As for why you would need CBC mode and PKCS7 padding, consult the internet
  // (f.e. http://www.di-mgt.com.au/properpassword.html).
  BlockCipher encryptionCipher = new PaddedBlockCipher("AES/CBC/PKCS7");
  encryptionCipher.init(true, params);
  Uint8List encrypted = encryptionCipher.process(utf8.encode(message));

  print("Encrypted: \n" + HEX.encode(encrypted));


  ////////////////
  // Decrypting //
  ////////////////

  BlockCipher decryptionCipher = new PaddedBlockCipher("AES/CBC/PKCS7");
  decryptionCipher.init(false, params);
  String decrypted = utf8.decode(decryptionCipher.process(encrypted));

  print("Decrypted: \n$decrypted");
}
