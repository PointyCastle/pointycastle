// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

part of cipher.api;

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

  /// Seed the RNG (usually the seed is obtained from an [EntropySource]).
  void seed( CipherParameters params );

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

  /// Seed the [EntropySource].
  void seed( CipherParameters params );

  /// Get [count] random bytes from the entropy source.
  Future<Uint8List> getBytes( int count );

}
