library cipher_impl;

import "package:cipher/api.dart";

import "package:cipher/digests/ripemd160.dart";

import "package:cipher/engines/aes_fast.dart";
import "package:cipher/engines/salsa20.dart";

import "package:cipher/modes/sic.dart";

void initCipher() {
  
  // Register block ciphers
  BlockCipher.register( "AES", () => new AESFastEngine() );
  // TODO: BlockCipher.register( "SIC", (underlyingCipher) => new SICBlockCipher(underlyingCipher) );
  // TODO: BlockCipher.register( "CTR", (underlyingCipher) => new SICBlockCipher(underlyingCipher) );
  
  // Register stream ciphers
  StreamCipher.register( "Salsa20", () => new Salsa20Engine() );
  
  // Register digests
  Digest.register( "RIPEMD-160", () => new RIPEMD160Digest() );
  
}