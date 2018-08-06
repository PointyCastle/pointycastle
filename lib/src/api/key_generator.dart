// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

part of pointycastle.api;

/**
 * The interface that asymmetric key generators conform to.
 *
 * A [KeyGenerator] is used to create a pair of public and private keys.
 */
abstract class KeyGenerator extends Algorithm {
  /// The [Registry] for [KeyGenerator] algorithms.
  static final registry = new Registry<KeyGenerator>();

  /// Create the key generator specified by the standard [algorithmName].
  factory KeyGenerator(String algorithmName) => registry.create(algorithmName);

  /**
   * Init the generator with its initialization [params]. The type of [CipherParameters] depends on the algorithm being used
   * (see the documentation of each implementation to find out more).
   */
  void init(CipherParameters params);

  /// Generate a new key pair.
  AsymmetricKeyPair generateKeyPair();
}
