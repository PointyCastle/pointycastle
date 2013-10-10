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

/** The interface stream ciphers conform to. */
abstract class StreamCipher {

  String get algorithmName;

  void reset();
  void init(bool forEncryption, CipherParameters params);
  int returnByte(int inp);
  void processBytes( Uint8List inp, int inpOff, int len, Uint8List out, int outOff);

}


/** All parameter classes implement this. */
abstract class CipherParameters {
}

