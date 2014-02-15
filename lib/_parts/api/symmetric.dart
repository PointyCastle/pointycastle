// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

part of cipher.api;

/// Block cipher engines are expected to conform to this interface.
abstract class BlockCipher {

  /// The [Registry] for [BlockCipher] algorithms
  static final registry = new Registry<BlockCipher>();

  /// Create the cipher specified by the standard [algorithmName].
  factory BlockCipher( String algorithmName ) => registry.create(algorithmName);

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

  /// Process a whole block of [data] at once, returning the result in a new byte array.
  Uint8List process(Uint8List data);

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

/**
 * All padded block ciphers conform to this interface.
 *
 * A padded block cipher is a wrapper around a [BlockCipher] that allows padding the last procesed block if it is smaller
 * than the [blockSize].
 */
abstract class PaddedBlockCipher implements BlockCipher {

  /// The [Registry] for [PaddedBlockCipher] algorithms
  static final registry = new Registry<PaddedBlockCipher>();

  /// Create the padded block cipher specified by the standard [algorithmName].
  factory PaddedBlockCipher( String algorithmName ) => registry.create(algorithmName);

  /// Get the underlying [Padding] used by this cipher.
  Padding get padding;

  /// Get the underlying [BlockCipher] used by this cipher.
  BlockCipher get cipher;

  /// Process a whole block of [data] at once, returning the result in a new byte array.
  Uint8List process(Uint8List data);

  /**
   * Process the last block of data given by [inp] and starting at offset
   * [inpOff] and pad it if necessary (i.e: if it is smaller than [blockSize]).
   *
   * The resulting cipher text is put in [out] beginning at position [outOff].
   *
   * This method returns the total bytes processed without taking the padding into account.
   */
  int doFinal( Uint8List inp, int inpOff, Uint8List out, int outOff );

}

/// The interface stream ciphers conform to.
abstract class StreamCipher {

  /// The [Registry] for [StreamCipher] algorithms
  static final registry = new Registry<StreamCipher>();

  /// Create the cipher specified by the standard [algorithmName].
  factory StreamCipher( String algorithmName ) => registry.create(algorithmName);

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

  /// Process a whole block of [data] at once, returning the result in a new byte array.
  Uint8List process(Uint8List data);

  /// Process one byte of data given by [inp] and return its encrypted value.
  int returnByte( int inp );

  /**
   * Process [len] bytes of data given by [inp] and starting at offset [inpOff].
   * The resulting cipher text is put in [out] beginning at position [outOff].
   */
  void processBytes( Uint8List inp, int inpOff, int len, Uint8List out, int outOff );

}

/// The interface that a MAC (message authentication code) conforms to.
abstract class Mac {

  /// The [Registry] for [Mac] algorithms
  static final registry = new Registry<Mac>();

  /// Create the MAC specified by the standard [algorithmName].
  factory Mac( String algorithmName ) => registry.create(algorithmName);

  /// Get this MAC's standard algorithm name.
  String get algorithmName;

  /// Get this MAC's output size.
  int get macSize;

  /// Reset the MAC to its original state.
  void reset();

  /**
   * Init the MAC with its initialization [params]. The type of [CipherParameters] depends on the algorithm being used (see
   * the documentation of each implementation to find out more).
   */
  void init( CipherParameters params );

  /// Process a whole block of [data] at once, returning the result in a new byte array.
  Uint8List process(Uint8List data);

  /// Add one byte of data to the MAC input.
  void updateByte( int inp );

  /**
   * Add [len] bytes of data contained in [inp], starting at position [inpOff]
   * to the MAC'ed input.
   */
  void update( Uint8List inp, int inpOff, int len );

  /**
   * Store the MAC of previously given data in buffer [out] starting at
   * offset [outOff]. This method returns the size of the digest.
   */
  int doFinal( Uint8List out, int outOff );

}

/**
 * The interface that a symmetric key derivator conforms to.
 *
 * A [KeyDerivator] is normally used to convert some master data (like a password, for instance) to a symmetric key.
 */
abstract class KeyDerivator {

  /// The [Registry] for [KeyDerivator] algorithms
  static final registry = new Registry<KeyDerivator>();

  /// Create the key derivator specified by the standard [algorithmName].
  factory KeyDerivator( String algorithmName ) => registry.create(algorithmName);

  /// Get this derivator's standard algorithm name.
  String get algorithmName;

  /// Get this derivator key's output size.
  int get keySize;

  /**
   * Init the derivator with its initialization [params]. The type of [CipherParameters] depends on the algorithm being used
   * (see the documentation of each implementation to find out more).
   */
  void init( CipherParameters params );

  /// Process a whole block of [data] at once, returning the result in a new byte array.
  Uint8List process(Uint8List data);

  /// Derive key from given input and put it in [out] at offset [outOff].
  int deriveKey( Uint8List inp, int inpOff, Uint8List out, int outOff );

}

