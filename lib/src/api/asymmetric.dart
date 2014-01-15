// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

part of cipher.api;

/// The interface that asymmetric (public and private) keys conform to.
abstract class AsymmetricKey {
}

/// The interface that asymmetric public keys conform to.
abstract class PublicKey implements AsymmetricKey {
}

/// The interface that asymmetric private keys conform to.
abstract class PrivateKey implements AsymmetricKey {
}

/// A pair of public and private asymmetric keys.
class AsymmetricKeyPair {

  final PublicKey publicKey;
  final PrivateKey privateKey;

  AsymmetricKeyPair(this.publicKey, this.privateKey);

}

/// An interface for signatures created by a [Signer]
abstract class Signature {
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

/**
 * The interface that asymmetric key generators conform to.
 *
 * A [KeyGenerator] is used to create a pair of public and private keys.
 */
abstract class KeyGenerator {

  /// The [Registry] for [KeyGenerator] algorithms
  static final registry = new Registry<KeyGenerator>();

  /// Create the key generator specified by the standard [algorithmName].
  factory KeyGenerator( String algorithmName ) => registry.create(algorithmName);

  /// Get this generator's standard algorithm name.
  String get algorithmName;

  /**
   * Init the generator with its initialization [params]. The type of [CipherParameters] depends on the algorithm being used
   * (see the documentation of each implementation to find out more).
   */
  void init( CipherParameters params );

  /// Generate a new key pair.
  AsymmetricKeyPair generateKeyPair();

}
