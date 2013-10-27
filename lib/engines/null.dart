library cipher_engines_null;

import "dart:typed_data";

import "package:cipher/api.dart";

/**
 * An implementation of a null cipher, that is, a cipher that does not encrypt,
 * neither decrypt. It can be used for testing or benchmarking chaining 
 * algorithms.
 */
class NullBlockCipher implements BlockCipher {

  static const _BLOCK_SIZE = 16;

  String get algorithmName => "Null";

  int get blockSize => _BLOCK_SIZE;

  void reset() {
  }

  void init( bool forEncryption, CipherParameters params ) {
  }

  int processBlock( Uint8List inp, int inpOff, Uint8List out, int outOff ) {
      out.setAll( outOff, inp.sublist(inpOff) );
      return _BLOCK_SIZE;
  }

}

