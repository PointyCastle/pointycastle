// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

part of pointycastle.api;

/// A [CipherParameters] to hold an asymmetric public key
class PublicKeyParameter<T extends PublicKey>
    extends AsymmetricKeyParameter<T> {
  PublicKeyParameter(PublicKey key) : super(key);
}
