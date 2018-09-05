
// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

part of pointycastle.api;

/**
 * [CipherParameters] consisting of an underlying [CipherParameters], associated
 * data (or additional authentication data), a nonce (or initialization
 * vector) and the requested size of the authentication tag.
 */
class AEADParameters<UnderlyingCipherParameters extends CipherParameters>
    implements CipherParameters {

  final UnderlyingCipherParameters parameters;

  final Uint8List associatedData;

  final Uint8List nonce;

  final int macSize;


  AEADParameters(this.parameters, this.macSize, this.nonce,
      this.associatedData);

}