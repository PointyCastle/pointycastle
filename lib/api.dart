library cipher_api;

import "dart:typed_data";

/** Block cipher engines are expected to conform to this interface. */
abstract class BlockCipher {
  
  String get algorithmName;
  int get blockSize;

  void reset();
  void init( bool forEncryption, CipherParameters params );
  int processBlock( Uint8List inp, int inpOff, Uint8List out, int outOff );
  
}

/** All parameter classes implement this. */
abstract class CipherParameters {
}

