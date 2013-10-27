library cipher_api;

import "dart:typed_data";

part "./src/factories.dart";

/** All parameter classes implement this. */
abstract class CipherParameters {
}

/** Factory function to create [BlockCipher]s */
typedef BlockCipher BlockCipherFactory();

/** Block cipher engines are expected to conform to this interface. */
abstract class BlockCipher {
  
  static void register( String algorithmName, BlockCipherFactory creator ) 
    => _registerBlockCipher(algorithmName,creator);

  factory BlockCipher( String algorithmName ) 
    => _createBlockCipher(algorithmName);
  
  String get algorithmName;
  int get blockSize;

  void reset();
  void init( bool forEncryption, CipherParameters params );
  int processBlock( Uint8List inp, int inpOff, Uint8List out, int outOff );

}

/** Factory function to create [ChainingBlockCipher]s */
typedef ChainingBlockCipher ChainingBlockCipherFactory(BlockCipher underlyingCipher);

/** 
 * Chaining block cipher (i.e.:modes of operation) are expected to conform 
 * to this interface. 
 */
abstract class ChainingBlockCipher implements BlockCipher {
  
  static void register( String algorithmName, ChainingBlockCipherFactory creator ) 
    => _registerChainingBlockCipher(algorithmName,creator);

  factory ChainingBlockCipher( String algorithmName, BlockCipher underlyingCipher ) 
    => _createChainingBlockCipher(algorithmName,underlyingCipher);

  BlockCipher get underlyingCipher;

}

/** Factory function to create [StreamCipher]s */
typedef StreamCipher StreamCipherFactory();

/** The interface stream ciphers conform to. */
abstract class StreamCipher {

  static void register( String algorithmName, StreamCipherFactory creator ) 
    => _registerStreamCipher(algorithmName,creator);

  factory StreamCipher( String algorithmName ) 
    => _createStreamCipher(algorithmName);

  String get algorithmName;

  void reset();
  void init( bool forEncryption, CipherParameters params );
  int returnByte( int inp );
  void processBytes( Uint8List inp, int inpOff, int len, Uint8List out, int outOff );

}

/** Factory function to create [Digest]s */
typedef Digest DigestFactory();

/** The interface that a message digest conforms to. */
abstract class Digest {

  static void register( String algorithmName, dynamic creator ) 
    => _registerDigest(algorithmName,creator);

  factory Digest( String algorithmName ) 
    => _createDigest(algorithmName);

  String get algorithmName;
  int get digestSize;

  void reset();
  void updateByte( int inp );
  void update( Uint8List inp, int inpOff, int len );
  int doFinal( Uint8List out, int outOff );

}

abstract class ExtendedDigest implements Digest {
  
  int get byteLength;
  
}
