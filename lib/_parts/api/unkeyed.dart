// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

part of cipher.api;

/// The interface that a message digest conforms to.
abstract class Digest {

  /// The [Registry] for [Digest] algorithms
  static final registry = new Registry<Digest>();

  /// Create the digest specified by the standard [algorithmName].
  factory Digest( String algorithmName ) => registry.create(algorithmName);

  /// Get this digest's standard algorithm name.
  String get algorithmName;

  /// Get this digest's output size.
  int get digestSize;

  /// Reset the digest to its original state.
  void reset();

  /// Process a whole block of [data] at once, returning the result in a new byte array.
  Uint8List process(Uint8List data);

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

/// The interface that a padding conforms to.
abstract class Padding {

  /// The [Registry] for [Padding] algorithms
  static final registry = new Registry<Padding>();

  /// Create the digest specified by the standard [algorithmName].
  factory Padding( String algorithmName ) => registry.create(algorithmName);

  /// Get this padding's standard algorithm name.
  String get algorithmName;

  /// Initialise the padder. Normally, paddings don't need any init params.
  void init( [CipherParameters params] );

  /**
   * Process a whole block of [data] at once, returning the result in a new byte array. If [pad] is true adds padding to the
   * given block, otherwise, padding is removed.
   *
   * Note: this assumes that the last block of plain text is always passed to it inside [data]. The reason for this is that some
   * modes such as "trailing bit compliment" base the padding on the last byte of plain text.
   */
  Uint8List process(bool pad, Uint8List data);

  /**
   * Add the pad bytes to the passed in block, returning the number of bytes
   * added.
   *
   * Note: this assumes that the last block of plain text is always passed to it
   * inside [data]. i.e. if [offset] is zero, indicating the entire block is to
   * be overwritten with padding the value of [data] should be the same as the
   * last block of plain text. The reason for this is that some modes such as
   * "trailing bit compliment" base the padding on the last byte of plain text.
   */
  int addPadding( Uint8List data, int offset );

  /// Get the number of pad bytes present in the block.
  int padCount( Uint8List data );

}

