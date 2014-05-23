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

  /// Seed the RNG (usually the seed is obtained from an [EntropySource]).
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

/**
 * An asynchronous source of pure random data (entropy). Data returned by an [EntropySource] should
 * be supposed to be unpredictable and of more quality than data obtained from a [SecureRandom].
 * Usually an [EntropySource] should be seen like a random generation device while a [SecureRandom]
 * should be seen like a cryptographic PRNG.
 */
abstract class EntropySource {

  /// The [Registry] for [EntropySource] objects
  static final registry = new Registry<EntropySource>();

  /// Create the entropy source specified by the standard [sourceName].
  factory EntropySource([String sourceName = ""]) => registry.create(sourceName);

  /// Get this entropy source name.
  String get sourceName;

  /// Get [count] random bytes from the entropy source.
  Future<Uint8List> getBytes(int count);

}

/**
 * An utility class to be able to estimate entropy in a big sample of data. It can be used for
 * analytical, testing or monitoring of random data generators.
 */
abstract class EntropyEstimator {

  /// The [Registry] for [EntropyEstimator] objects
  static final registry = new Registry<EntropyEstimator>();

  /// Create the entropy estimator specified by the standard [algorithmName].
  factory EntropyEstimator(String algorithmName) => registry.create(algorithmName);

  /// Get this estimator algorithm name.
  String get algorithmName;

  /// Init the [EntropyEstimator].
  void init(CipherParameters params);

  /// Reset the estimator to its original state.
  void reset();

  /// Add one byte of data to the processed input.
  void updateByte(int inp);

  /**
   * Add [len] bytes of data contained in [inp], starting at position [inpOff] to the processed
   * input.
   */
  void update(Uint8List inp, int inpOff, int len);

  /// Get the length of processed data.
  int get dataLength;

  /**
   * Get the estimated entropy of the processed data. The estimated entropy is a number between 0
   * and [dataLength] and expresses the amount of random noise data contained in the processed
   * input. The bigger the number, the more entropy found in the processed data.
   */
  int get estimatedEntropy;

  /// One-shot method that returns the entropy found in [data].
  int process(Uint8List data);

}

/**
 * An interface to be implemented by all object capable of collecting entropy from the outer world.
 * Instances of [EntropyCollector] are normally used to seed an [EntropySource] continously and
 * whenever new entropy is available.
 *
 * An [EntropyCollector] normally returns unpredictable data but not necessarily uniformly
 * distributed (as opposed to an [EntropySource]). Also, an [EntropySource] is a pull source, while
 * [EntropyCollector] push data to listeners as soon as it is available.
 */
abstract class EntropyCollector {

  /// The [Registry] for [EntropyCollector] objects.
  static final registry = new Registry<EntropyCollector>();

  /// Create the entropy collector specified by the standard [algorithmName].
  factory EntropyCollector(String algorithmName) => registry.create(algorithmName);

  /// Get this collector's algorithm name.
  String get algorithmName;

  /// Init the [EntropyCollector].
  void init(CipherParameters params);

  /// Start the collector.
  void start();

  /// Stop the collector.
  void stop();

  /// The stream to which subscribe to receive new entropy available events.
  Stream<Uint8List> get entropy;

}



