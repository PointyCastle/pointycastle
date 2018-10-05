// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

part of pointycastle.api;

/// [CipherParameters] consisting of just a key of arbitrary length.
class KeyParameter extends CipherParameters {
  final Uint8List key;

  KeyParameter(this.key);
}
