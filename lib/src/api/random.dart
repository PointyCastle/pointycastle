// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

part of cipher.api;

/**
 * A synchronous secure random number generator (RNG).
 *
 * Being synchronous, this RNG cannot return direct results from sources of randomness like
 * "/dev/random" or similar. For that, use an [EntropySource] which allows to be called
 * asynchronously. Usually an [EntropySource] should be seen like a random generation device while
 * a [SecureRandom] should be seen like a cryptographic PRNG. Thus, data from an [EntropySource]
 * should be seen as "more random" than that returned from a [SecureRandom].
 */
abstract class SecureRandom {

  /// The [Registry] for [SecureRandom] algorithms
  static final registry = new Registry<SecureRandom>();

  /// Create the secure random specified by the standard [algorithmName].
  factory SecureRandom([String algorithmName = ""]) => registry.create(algorithmName);

  /// Get this secure random standard algorithm name.
  String get algorithmName;

  /// Seed the RNG with some entropy (look at package cipher_entropy providing entropy sources).
  void seed(CipherParameters params);

  /// Get one byte long random int.
  int nextUint8();

  /// Get two bytes long random int.
  int nextUint16();

  /// Get four bytes long random int.
  int nextUint32();

  /// Get a random [BigInteger] of [bitLength] bits.
  BigInteger nextBigInteger(int bitLength);

  /// Get a list of bytes of arbitrary length.
  Uint8List nextBytes(int count);

}
