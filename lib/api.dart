// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com  
// Use of this source code is governed by a LGPL v3 license. 
// See the LICENSE file for more information.

/**
 * This is the API specification library for the cipher project.
 * 
 * It declares all abstract types used by the cipher library. In addition, it
 * implements the factories mechanism that allows users to instantiate 
 * algorithms by their standard name.
 */
library cipher.api;

import "dart:typed_data";

part "./src/factories.dart";

/// All cipher initialization parameters classes implement this.
abstract class CipherParameters {
}

/// Factory function to create [BlockCipher]s. 
typedef BlockCipher BlockCipherFactory();

/// Block cipher engines are expected to conform to this interface. 
abstract class BlockCipher {
  
  /// Register an algorithm by its standard name.
  static void register( String algorithmName, BlockCipherFactory creator ) 
    => _registerBlockCipher(algorithmName,creator);

  /// Create the cipher specified by the standard [algorithmName]. 
  factory BlockCipher( String algorithmName ) 
    => _createBlockCipher(algorithmName);
  
  /// Get this cipher's standard algorithm name.
  String get algorithmName;
  
  /// Get this ciphers's block size.
  int get blockSize;

  /// Reset the cipher to its original state.
  void reset();
  
  /** 
   * Init the cipher with its initialization [params]. The type of 
   * [CipherParameters] depends on the algorithm being used (see the 
   * documentation of each implementation to find out more).
   * 
   * Use the argument [forEncryption] to tell the cipher if you want to encrypt
   * or decrypt data.  
   */
  void init( bool forEncryption, CipherParameters params );
  
  /**
   * Process a whole block of data given by [inp] and starting at offset
   * [inpOff]. 
   * 
   * The resulting cipher text is put in [out] beginning at position [outOff].
   * 
   * This method returns the total bytes processed (which is the same as the 
   * block size of the algorithm).
   */
  int processBlock( Uint8List inp, int inpOff, Uint8List out, int outOff );

}

/// Factory function to create [ChainingBlockCipher]s. 
typedef ChainingBlockCipher ChainingBlockCipherFactory(BlockCipher underlyingCipher);

/** 
 * Chaining block cipher are expected to conform to this interface.
 * 
 * A [ChainingBlockCipher] is a [BlockCipher] that delegates in another 
 * [BlockCipher] to perform its operation. 
 * 
 * Implementers of this interface ususally are block cipher modes of operation,
 * as described in [http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation].
 */
abstract class ChainingBlockCipher implements BlockCipher {
  
  /// Register an algorithm by its standard name.
  static void register( String algorithmName, ChainingBlockCipherFactory creator ) 
    => _registerChainingBlockCipher(algorithmName,creator);

  /**
   *  Create the cipher specified by the standard [algorithmName] using the
   *  provided [underlyingCipher]. 
   */
  factory ChainingBlockCipher( String algorithmName, BlockCipher underlyingCipher ) 
    => _createChainingBlockCipher(algorithmName,underlyingCipher);

  /// Get the underlying [BlockCipher] wrapped by this cipher.
  BlockCipher get underlyingCipher;

}

/// Factory function to create [StreamCipher]s. 
typedef StreamCipher StreamCipherFactory();

/// The interface stream ciphers conform to. 
abstract class StreamCipher {

  /// Register an algorithm by its standard name.
  static void register( String algorithmName, StreamCipherFactory creator ) 
    => _registerStreamCipher(algorithmName,creator);

  /// Create the cipher specified by the standard [algorithmName]. 
  factory StreamCipher( String algorithmName ) 
    => _createStreamCipher(algorithmName);

  /// Get this cipher's standard algorithm name.
  String get algorithmName;

  /// Reset the cipher to its original state.
  void reset();

  /** 
   * Init the cipher with its initialization [params]. The type of 
   * [CipherParameters] depends on the algorithm being used (see the 
   * documentation of each implementation to find out more).
   * 
   * Use the argument [forEncryption] to tell the cipher if you want to encrypt
   * or decrypt data.  
   */
  void init( bool forEncryption, CipherParameters params );

  /// Process one byte of data given by [inp] and return its encrypted value. 
  int returnByte( int inp );

  /**
   * Process [len] bytes of data given by [inp] and starting at offset [inpOff]. 
   * The resulting cipher text is put in [out] beginning at position [outOff].
   */
  void processBytes( Uint8List inp, int inpOff, int len, Uint8List out, int outOff );

}

/// Factory function to create [Digest]s. 
typedef Digest DigestFactory();

/// The interface that a message digest conforms to.
abstract class Digest {

  /// Register an algorithm by its standard name.
  static void register( String algorithmName, DigestFactory creator ) 
    => _registerDigest(algorithmName,creator);

  /// Create the digest specified by the standard [algorithmName].
  factory Digest( String algorithmName ) 
    => _createDigest(algorithmName);

  /// Get this digest's standard algorithm name.
  String get algorithmName;
  
  /// Get this digest's output size.
  int get digestSize;

  /// Reset the digest to its original state.
  void reset();
  
  /// Add one byte of data to the digested input.
  void updateByte( int inp );
  
  /**
   * Add [len] bytes of data contained in [inp], starting at position [inpOff]
   * ti the digested input.
   */
  void update( Uint8List inp, int inpOff, int len );
  
  /**
   * Store the digest of previously given data in buffer [out] starting at 
   * offset [outOff]. This method returns the size of the digest. 
   */
  int doFinal( Uint8List out, int outOff );

}

