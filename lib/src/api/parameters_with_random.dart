// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

part of pointycastle.api;

//TODO consider mixin
/**
 * [CipherParameters] consisting of an underlying [CipherParameters] (of type
 * [UnderlyingParameters]) and an acompanying [SecureRandom].
 */
class ParametersWithRandom<UnderlyingParameters extends CipherParameters>
    implements CipherParameters {
  final UnderlyingParameters parameters;
  final SecureRandom random;

  ParametersWithRandom(this.parameters, this.random);
}
