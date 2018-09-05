
// Copyright (c) 2013-present, the authors of the Pointy Castle project
// This library is dually licensed under LGPL 3 and MPL 2.0.
// See file LICENSE for more information.

part of pointycastle.api;

/// A block cipher mode that includes authenticated encryption
abstract class AEADBlockCipher implements BlockCipher {

  /// Process [len] bytes from [inp] starting at offset [inpOff] and output the
  /// result to [out] at offset [outOff].
  ///
  /// Returns the number of bytes written to the output.
  int processBytes(Uint8List inp, int inpOff, int len, Uint8List out, int outOff);

  /// Finish the operation either appending or verifying the MAC at the end of
  /// the data.
  ///
  /// Returns the number of bytes written to the output.
  int doFinal(Uint8List out, int outOff);

}

class InvalidCipherTextException implements Exception {

  final String message;

  InvalidCipherTextException(this.message);

}

