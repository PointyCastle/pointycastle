// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

part of pointycastle.api;

/// The interface stream ciphers conform to.
abstract class StreamCipher extends Algorithm {
  /// The [Registry] for [StreamCipher] algorithms.
  static final registry = new Registry<StreamCipher>();

  /// Create the cipher specified by the standard [algorithmName].
  factory StreamCipher(String algorithmName) => registry.create(algorithmName);

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

  /// Process a whole block of [data] at once, returning the result in a new byte array.
  Uint8List process(Uint8List data);

  /// Process one byte of data given by [inp] and return its encrypted value.
  int returnByte(int inp);

  /**
   * Process [len] bytes of data given by [inp] and starting at offset [inpOff].
   * The resulting cipher text is put in [out] beginning at position [outOff].
   */
  void processBytes(
      Uint8List inp, int inpOff, int len, Uint8List out, int outOff);
}
