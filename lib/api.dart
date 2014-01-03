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

import "dart:async";
import "dart:typed_data";

//import "package:bignum/bignum.dart" as bn;
import 'dart:math' as Mathx;
part "src/bignum/big_integer.dart";

part "./src/registry.dart";
part "./src/ufixnum.dart";
part "./src/api/ecc.dart";

/// All cipher initialization parameters classes implement this.
abstract class CipherParameters {
}

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
 * Chaining block cipher are expected to conform to this interface.
 *
 * A [ChainingBlockCipher] is a [BlockCipher] that delegates in another
 * [BlockCipher] to perform its operation.
 *
 * Implementers of this interface ususally are block cipher modes of operation,
 * as described in [http://en.wikipedia.org/wiki/Block_cipher_mode_of_operation].
 */
abstract class ChainingBlockCipher implements BlockCipher {

  /// The [Registry] for [ChainingBlockCipher] algorithms
  static final registry = new Registry<ChainingBlockCipher>();

  /**
   * Create the chaining block cipher specified by the standard [algorithmName].
   *
   * Standard algorithms can be chained using / as a separator. For example: you
   * can ask for "AES/CBC".
   */
  factory ChainingBlockCipher( String algorithmName ) => registry.create(algorithmName);

  /// Get the underlying [BlockCipher] wrapped by this cipher.
  BlockCipher get underlyingCipher;

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

  /// Process one byte of data given by [inp] and return its encrypted value.
  int returnByte( int inp );

  /**
   * Process [len] bytes of data given by [inp] and starting at offset [inpOff].
   * The resulting cipher text is put in [out] beginning at position [outOff].
   */
  void processBytes( Uint8List inp, int inpOff, int len, Uint8List out, int outOff );

}

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

/**
 * All padded block ciphers conform to this interface.
 *
 * A padded block cipher is a wrapper around a [BlockCipher] or a
 * [ChainingBlockCipher] that allows padding the last procesed block if it is
 * smaller than the [blockSize].
 */
abstract class PaddedBlockCipher implements ChainingBlockCipher {

  /// The [Registry] for [PaddedBlockCipher] algorithms
  static final registry = new Registry<PaddedBlockCipher>();

  /**
   * Create the padded block cipher specified by the standard [algorithmName].
   *
   * Standard algorithms can be chained using / as a separator. For example: you
   * can ask for "AES/CBC/PKCS7".
   */
  factory PaddedBlockCipher( String algorithmName ) => registry.create(algorithmName);

  /// Get the underlying [Padding] used by this cipher.
  Padding get padding;

  /**
   * Process the last block of data given by [inp] and starting at offset
   * [inpOff] and pad it if necessary (i.e: if it is smaller than [blockSize]).
   *
   * The resulting cipher text is put in [out] beginning at position [outOff].
   *
   * This method returns the total bytes processed (which is the same as the
   * block size of the algorithm).
   */
  int doFinal( Uint8List inp, int inpOff, Uint8List out, int outOff );

}

/// An interface for DSAs (digital signature algorithms)
abstract class Signer {

  /// The [Registry] for [Signer] algorithms
  static final registry = new Registry<Signer>();

  /// Create the signer specified by the standard [algorithmName].
  factory Signer( String algorithmName ) => registry.create(algorithmName);

  /// Get this signer's standard algorithm name.
  String get algorithmName;

  /// Reset the signer to its original state.
  void reset();

  /**
   * Init the signer with its initialization [params]. The type of [CipherParameters] depends on the algorithm being used (see
   * the documentation of each implementation to find out more).
   *
   * Use the argument [forSigning] to tell the signer if you want to generate or verify signatures.
   */
  void init( bool forSigning, CipherParameters params );

  /// Sign the passed in [message] (usually the output of a hash function)
  Signature generateSignature( Uint8List message );

  /// Verify the [message] against the [signature].
  bool verifySignature( Uint8List message, Signature signature );

}

/// A signature created by a [Signer]
class Signature {

  final BigInteger r;
  final BigInteger s;

  Signature( this.r, this.s );

  String toString() => "(${r.toString()},${s.toString()})";

}

/**
 * A synchronous secure random number generator (RNG).
 *
 * Being synchronous, this RNG cannot return direct results from sources of randomness like "/dev/random" or similar. For that,
 * use an [EntropySource] which allows to be called asynchronously. Usually an [EntropySource] should be seen like a random
 * generation device while a [SecureRandom] should be seen like a cryptographic PRNG. Thus, data from an [EntropySource] should
 * be seen as "more random" than that returned from a [SecureRandom].
 */
// see: http://www.std.com/~cme/P1363/ranno.html
// see: http://edc.tversu.ru/elib/inf/0088/0596003943_secureprgckbk-chp-11-sect-5.html (secure_programming_cookbook_for_c_and_c)
abstract class SecureRandom {

  /// The [Registry] for [SecureRandom] algorithms
  static final registry = new Registry<SecureRandom>();

  /// Create the secure random specified by the standard [algorithmName].
  factory SecureRandom( [String algorithmName=""] ) => registry.create(algorithmName);

  /// Get this secure random standard algorithm name.
  String get algorithmName;

  /// Initialize the RNG (usually with a seed from an [EntropySource]).
  void init( CipherParameters params );

	/// Get one byte long random int.
  Uint8 nextUint8();

	/// Get two byte long random int.
  Uint16 nextUint16();

	/// Get four byte long random int.
  Uint32 nextUint32();

	/// Get a random [BigInteger] of [bitLength] bits.
  BigInteger nextBigInteger( int bitLength );

	/// Get a list of bytes of arbitrary length.
	Uint8List nextBytes( int count );

}

/**
 * An asynchronous source of pure random data (entropy). Data returned by an [EntropySource] should be supposed to be
 * impredictable and of more quality than data obtained from a [SecureRandom]. Usually an [EntropySource] should be seen like
 * a random generation device while a [SecureRandom] should be seen like a cryptographic PRNG.
 */
abstract class EntropySource {

	/// The [Registry] for [EntropySource] objects
	static final registry = new Registry<EntropySource>();

	/// Create the entropy source specified by the standard [sourceName].
	factory EntropySource( [String sourceName=""] ) => registry.create(sourceName);

	/// Get this entropy source name.
	String get sourceName;

  /// Initialize the [EntropySource] (usually not necessary).
  void init( CipherParameters params );

	/// Get [count] random bytes from the entropy source.
	Future<Uint8List> getBytes( int count );

}











