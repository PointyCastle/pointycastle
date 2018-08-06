// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

part of pointycastle.api;

/// Block cipher engines are expected to conform to this interface.
abstract class BlockCipher extends Algorithm {
  /// The [Registry] for [BlockCipher] algorithms.
  static final registry = new Registry<BlockCipher>();

  /// Create the cipher specified by the standard [algorithmName].
  factory BlockCipher(String algorithmName) => registry.create(algorithmName);

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
  void init(bool forEncryption, CipherParameters params);

  /**
   * Process a whole block of [blockSize] bytes stored in [data] at once, returning the result in a
   * new byte array.
   *
   * This call is equivalent to [processBlock] but it allocates the array under the hood.
   */
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
  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff);
}
