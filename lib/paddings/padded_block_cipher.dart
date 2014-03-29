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
  final BlockCipher cipher;

  bool _encrypting;

  PaddedBlockCipherImpl(this.padding, this.cipher);

  String get algorithmName => cipher.algorithmName + "/" + padding.algorithmName;

  int get blockSize => cipher.blockSize;

  void reset() {
    _encrypting = null;
    cipher.reset();
  }

  void init(bool forEncryption, PaddedBlockCipherParameters params) {
    _encrypting = forEncryption;
    cipher.init(forEncryption, params.underlyingCipherParameters);
    padding.init(params.paddingCipherParameters);
  }

  Uint8List process(Uint8List data) {
    var inputBlocks = (data.length + blockSize - 1) ~/ blockSize;

    var outputBlocks;
    if (_encrypting) {
      outputBlocks = (data.length + blockSize) ~/ blockSize;
    } else {
      if ((data.length % blockSize) != 0) {
        throw new ArgumentError("Input data length must be a multiple of cipher's block size");
      }
      outputBlocks = inputBlocks;
    }

    var out = new Uint8List(outputBlocks * blockSize);

    for (var i = 0; i < (inputBlocks - 1); i++) {
      var offset = (i * blockSize);
      processBlock(data, offset, out, offset);
    }

    var lastBlockOffset = ((inputBlocks - 1) * blockSize);
    var lastBlockSize = doFinal(data, lastBlockOffset, out, lastBlockOffset);

    return out.sublist(0, lastBlockOffset + lastBlockSize);
  }

  int processBlock(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    return cipher.processBlock(inp, inpOff, out, outOff);
  }

  int doFinal(Uint8List inp, int inpOff, Uint8List out, int outOff) {
    if (_encrypting) {
      var lastInputBlock = new Uint8List(blockSize)..setAll(0, inp.sublist(inpOff));

      var remainder = inp.length - inpOff;

      if (remainder < blockSize) {
        // Padding goes embedded in last block of data
        padding.addPadding(lastInputBlock, (inp.length - inpOff));

        processBlock(lastInputBlock, 0, out, outOff);

        return blockSize;
      } else {
        // Padding goes alone in an additional block
        processBlock(inp, inpOff, out, outOff);

        padding.addPadding(lastInputBlock, 0);

        processBlock(lastInputBlock, 0, out, outOff + blockSize);

        return 2 * blockSize;
      }
    } else {
      // Decrypt last block and remove padding
      processBlock(inp, inpOff, out, outOff);

      var padCount = padding.padCount(out.sublist(outOff));

      var padOffsetInBlock = blockSize - padCount;

      out.fillRange(outOff + padOffsetInBlock, out.length, 0);

      return padOffsetInBlock;
    }
  }

}
