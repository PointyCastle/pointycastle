// Copyright (c) 2013-present, Iván Zaera Avellón - izaera@gmail.com

// This library is dually licensed under LGPL 3 and MPL 2.0. See file LICENSE for more information.

// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of
// the MPL was not distributed with this file, you can obtain one at http://mozilla.org/MPL/2.0/.

part of cipher.api;

/// Abstract [CipherParameters] to hold an asymmetric (public or private) key
abstract class AsymmetricKeyParameter<T extends AsymmetricKey> implements CipherParameters {

  final T key;

  AsymmetricKeyParameter(this.key);

}

/// All cipher initialization parameters classes implement this.
abstract class CipherParameters {
}

/// Abstract [CipherParameters] to init an asymmetric key generator.
abstract class KeyGeneratorParameters implements CipherParameters {

  final int bitStrength;

  KeyGeneratorParameters(this.bitStrength);

}

/// [CipherParameters] consisting of just a key of arbitrary length.
class KeyParameter extends CipherParameters {

  final Uint8List key;

  KeyParameter(this.key);

}

/**
 * [CipherParameters] for [PaddedBlockCipher]s consisting of two underlying [CipherParameters], one for the [BlockCipher] (of
 * type [UnderlyingCipherParameters]) and the other for the [Padding] (of type [PaddingCipherParameters]).
 */
class PaddedBlockCipherParameters<UnderlyingCipherParameters extends CipherParameters,
    PaddingCipherParameters extends CipherParameters> implements CipherParameters {

  final UnderlyingCipherParameters underlyingCipherParameters;
  final UnderlyingCipherParameters paddingCipherParameters;

  PaddedBlockCipherParameters(this.underlyingCipherParameters, this.paddingCipherParameters);

}

/**
 * [CipherParameters] consisting of an underlying [CipherParameters] (of type [UnderlyingParameters]) and an initialization
 * vector of arbitrary length.
 */
class ParametersWithIV<UnderlyingParameters extends CipherParameters> implements CipherParameters {

  final Uint8List iv;
  final UnderlyingParameters parameters;

  ParametersWithIV(this.parameters, this.iv);

}

/**
 * [CipherParameters] consisting of an underlying [CipherParameters] (of type
 * [UnderlyingParameters]) and an acompanying [SecureRandom].
 */
class ParametersWithRandom<UnderlyingParameters extends CipherParameters> implements
    CipherParameters {

  final UnderlyingParameters parameters;
  final SecureRandom random;

  ParametersWithRandom(this.parameters, this.random);

}

/// A [CipherParameters] to hold an asymmetric private key
class PrivateKeyParameter<T extends PrivateKey> extends AsymmetricKeyParameter<T> {

  PrivateKeyParameter(PrivateKey key) : super(key);

}

/// A [CipherParameters] to hold an asymmetric public key
class PublicKeyParameter<T extends PublicKey> extends AsymmetricKeyParameter<T> {

  PublicKeyParameter(PublicKey key) : super(key);

}
