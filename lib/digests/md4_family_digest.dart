// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.digests.md4_family_digest;

import "dart:typed_data";

import "package:cipher/api/ufixnum.dart";
import "package:cipher/digests/base_digest.dart";

/// Base implementation of MD4 family style digest as outlined in "Handbook of Applied
/// Cryptography", pages 344 - 347.
abstract class MD4FamilyDigest extends BaseDigest {

  var _xBuf = new Uint8List(4);
  int _xBufOff = 0;

  final _byteCount = new Register64(0);

  void reset() {
    _byteCount.set(0);
    _xBufOff = 0;
    _xBuf.fillRange(0, _xBuf.length, 0);
  }

  void updateByte(int inp) {
    _xBuf[_xBufOff++] = clip8(inp);
    _processWordIfBufferFull();
    _byteCount.sum(1);
  }

  void update(Uint8List inp, int inpOff, int len) {
    var nbytes;

    nbytes = _processUntilNextWord(inp, inpOff, len);
    inpOff += nbytes;
    len -= nbytes;

    nbytes = _processWholeWords(inp, inpOff, len);
    inpOff += nbytes;
    len -= nbytes;

    _processBytes(inp, inpOff, len);
  }

  /// Finish digestion of data adding padding and processing data's bit length.
  void finish() {
    var bitLength = new Register64(_byteCount)..shiftl(3);
    _addPadding();
    processLength(bitLength);
    processBlock();
  }

  /// Process a word (4 bytes) of data stored in [inp], starting at [inpOff].
  void processWord(Uint8List inp, int inpOff);

  /// Called from [finish] so that extender can process the number of bits processed.
  void processLength(Register64 bitLength);

  /// Process a whole block of data in extender digest.
  void processBlock();

  /// Pack a 64-bit length into an array of [int]s in big endian format
  void packBigEndianLength(Register64 bitLength, List<int> _X, int i) {
    _X[i+1] = bitLength.hi32;
    _X[i]   = bitLength.lo32;
  }

  /// Pack a 64-bit length into an array of [int]s in little endian format
  void packLittleEndianLength(Register64 bitLength, List<int> _X, int i) {
    _X[i]   = bitLength.hi32;
    _X[i+1] = bitLength.lo32;
  }

  /// Process [len] bytes from [inp]
  void _processBytes(Uint8List inp, int inpOff, int len) {
    while( len > 0 ) {
      updateByte(inp[inpOff]);

      inpOff++;
      len--;
    }
  }

  /// Process data word by word until no more words can be extracted from [inp] and return the number of bytes processed.
  int _processWholeWords(Uint8List inp, int inpOff, int len) {
    var processed = 0;
    while (len > _xBuf.length) {
      processWord( inp, inpOff );

      inpOff += _xBuf.length;
      len -= _xBuf.length;
      _byteCount.sum(_xBuf.length);
      processed += 4;
    }
    return processed;
  }

  /// Process bytes from [inp] until the word buffer [_xBuf] is full and reset and return the number of bytes processed.
  int _processUntilNextWord(Uint8List inp, int inpOff, int len) {
    var processed = 0;

    while( (_xBufOff != 0) && (len > 0) ) {
      updateByte(inp[inpOff]);

      inpOff++;
      len--;
      processed++;
    }

    return processed;
  }

  /// Process a word in [_xBuff] if it is already full and then reset it
  void _processWordIfBufferFull() {
    if (_xBufOff == _xBuf.length) {
      processWord(_xBuf, 0);
      _xBufOff = 0;
    }
  }

  /// Add final padding to the digest
  void _addPadding() {
    updateByte(128);
    while (_xBufOff != 0) {
      updateByte(0);
    }
  }

}