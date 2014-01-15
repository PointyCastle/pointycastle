// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.paddings.padded_block_cipher;

import "dart:typed_data";

import "package:cipher/api.dart";
import "package:cipher/params/padded_block_cipher_parameters.dart";

/// The standard implementation of [PaddedBlockCipher].
class PaddedBlockCipherImpl implements PaddedBlockCipher {

  final Padding padding;
  final BlockCipher underlyingCipher;

  bool _encrypting;

  PaddedBlockCipherImpl(this.padding,this.underlyingCipher);

  String get algorithmName => underlyingCipher.algorithmName+"/"+padding.algorithmName;

  int get blockSize => underlyingCipher.blockSize;

  void reset() {
    _encrypting = null;
    underlyingCipher.reset();
  }

  void init( bool forEncryption, PaddedBlockCipherParameters params ) {
    _encrypting = forEncryption;
    underlyingCipher.init( forEncryption, params.underlyingCipherParameters );
    padding.init( params.paddingCipherParameters );
  }

  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    return underlyingCipher.processBlock(inp, inpOff, out, outOff);
  }

  int doFinal(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    if( _encrypting ) {
      Uint8List tmp = new Uint8List(blockSize)
        ..setAll( 0, inp.sublist(inpOff) );
      var padCount = inp.length-inpOff;
      padding.addPadding( tmp, padCount );
      var processed = processBlock(tmp, 0, out, outOff);
      return processed - padCount;
    } else {
      var processed = processBlock(inp, inpOff, out, outOff);
      var padCount = padding.padCount(out.sublist(outOff));
      return processed - padCount;
    }
  }

}