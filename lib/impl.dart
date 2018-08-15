// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

/**
 * This library contains all out-of-the-box implementations of the interfaces provided in the API
 * which are compatible with client and server sides.
 */
library pointycastle.impl;

// cipher implementations

// asymmetric
import "package:pointycastle/export.dart";

export "package:pointycastle/asymmetric/api.dart";
export "package:pointycastle/ecc/api.dart";
export "package:pointycastle/key_derivators/api.dart";
export "package:pointycastle/key_generators/api.dart";

part './src/impl/registration.dart';
part './src/impl/registration_ecc.dart';

// This one imports all libraries.
// ecc
// key_derivators
// key_generators

bool _initialized = false;

/**
 * This is the initializer method for this library. It must be called prior to use any of the
 * implementations.
 */
void initCipher() {
  if (!_initialized) {
    _initialized = true;
    _registerAsymmetricBlockCiphers();
    _registerBlockCiphers();
    _registerDigests();
    _registerEccStandardCurves();
    _registerKeyDerivators();
    _registerKeyGenerators();
    _registerMacs();
    _registerModesOfOperation();
    _registerPaddedBlockCiphers();
    _registerPaddings();
    _registerSecureRandoms();
    _registerSigners();
    _registerStreamCiphers();
  }
}
