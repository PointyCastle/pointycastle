// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

part of pointycastle.api;

/**
 * All padded block ciphers conform to this interface.
 *
 * A padded block cipher is a wrapper around a [BlockCipher] that allows padding the last procesed
 * block (when encrypting) in the following way:
 *
 * *If it is smaller than the [blockSize] it will be padded to [blockSize] bytes.
 * *If it is equal to the [blockSize] a new pad block will be added.
 *
 * When decrypting, a [PaddedBlockCipher] also removes the padding from the last cipher text block.
 *
 * It is advised to use method [process] as it is much easier than making the correct calls to
 * [processBlock] and [doFinal] which are different depending on whether you are encrypting or
 * decrypting and also depending on the data length being a multiple of the cipher's block size.
 */
abstract class PaddedBlockCipher implements BlockCipher {

  /// The [Registry] for [PaddedBlockCipher] algorithms.
  static final registry = new Registry<PaddedBlockCipher>();

  /// Create the padded block cipher specified by the standard [algorithmName].
  factory PaddedBlockCipher(String algorithmName) =>
      registry.create(algorithmName);

  /// Get the underlying [Padding] used by this cipher.
  Padding get padding;

  /// Get the underlying [BlockCipher] used by this cipher.
  BlockCipher get cipher;

  /**
   * Process a whole block of [data] at once, returning the result in a new byte array.
   *
   * This call does as many calls to [processBlock] as needed to process all the given data and a
   * final one to [doFinal] so that the padding can do its job.
   */
  Uint8List process(Uint8List data);

  /**
   * Process the last block of data given by [inp] and starting at offset [inpOff] and pad it as
   * explained in this interface's description.
   *
   * For encryption, the resulting cipher text is put in [out] beginning at position [outOff] and
   * the method returns the total bytes put in [out], including the padding. Note that, if [inp]
   * length is equal to the cipher's block size, [out] will need to be twice the cipher's block size
   * to allow place for the padding.
   *
   * For decryption, the resulting plain text is put in [out] beginning at position [outOff] and the
   * method returns the total bytes put in [out], excluding the padding. Note that the method may
   * return 0 if the last block was all padding.
   */
  int doFinal(Uint8List inp, int inpOff, Uint8List out, int outOff);
}
