
// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

part of pointycastle.api;

//TODO rename
/**
 * [CipherParameters] consisting of an underlying [CipherParameters] (of type [UnderlyingParameters]) and an initialization
 * vector of arbitrary length.
 */
class ParametersWithIV<UnderlyingParameters extends CipherParameters> implements CipherParameters {

  final Uint8List iv;
  final UnderlyingParameters parameters;

  ParametersWithIV(this.parameters, this.iv);

}