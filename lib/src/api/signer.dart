// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

part of pointycastle.api;

/// An interface for DSAs (digital signature algorithms)
abstract class Signer extends Algorithm {
  /// Create the signer specified by the standard [algorithmName].
  factory Signer(String algorithmName) =>
      registry.create<Signer>(algorithmName);

  /// Reset the signer to its original state.
  void reset();

  /**
   * Init the signer with its initialization [params]. The type of [CipherParameters] depends on the algorithm being used (see
   * the documentation of each implementation to find out more).
   *
   * Use the argument [forSigning] to tell the signer if you want to generate or verify signatures.
   */
  void init(bool forSigning, CipherParameters params);

  /// Sign the passed in [message] (usually the output of a hash function)
  Signature generateSignature(Uint8List message, {bool normalize = false});

  /// Verify the [message] against the [signature].
  bool verifySignature(Uint8List message, Signature signature);
}
