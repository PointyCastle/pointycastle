// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.digests.md4_family_digest;

import "dart:typed_data";

import "package:cipher/api.dart";

/// Base implementation of MD4 family style digest as outlined in "Handbook of Applied Cryptography", pages 344 - 347.
 abstract class MD4FamilyDigest implements Digest {

  /// Working word (4 bytes) buffer
  var _xBuf = new Uint8List(4);

  /// Offset to next position to fill in buffer
  var _xBufOff = 0;

  /// Number of procesed bytes
  var _byteCount = 0;

  void reset() {
    _byteCount = 0;
    _xBufOff = 0;
    _xBuf.fillRange( 0, _xBuf.length, 0 );
  }

  void updateByte( int inp ) {
    _xBuf[_xBufOff++] = inp;
    _processWordIfBufferFull();
    _byteCount++;
  }

  void update( Uint8List inp, int inpOff, int len ) {
    var nbytes;

    nbytes = _processUntilNextWord( inp, inpOff, len );
    inpOff += nbytes;
    len -= nbytes;

    nbytes = _processWholeWords(inp, inpOff, len);
    inpOff += nbytes;
    len -= nbytes;

    _processBytes(inp, inpOff, len);
  }

  /// Finish digestion of data adding padding and processing data's bit length.
  void finish() {
    var bitLength = (_byteCount << 3);
    _addPadding();
    processLength( bitLength );
    processBlock();
  }

  /// Process a word (4 bytes) of data stored in [inp], starting at [inpOff].
  void processWord( Uint8List inp, int inpOff );

  /// Called from [finish] so that extender can process the number of bits processed.
  void processLength( int bitLength );

  /// Process a whole block of data in extender digest.
  void processBlock();

  /// Pack a 64-bit length into an array of [Uint32]s in big endian format
  void packBigEndianLength(int bitLength, List<Uint32> _X, int i) {
    _X[i+1] = new Uint32(bitLength>>32);
    _X[i] = new Uint32(bitLength);
  }

  /// Pack a 64-bit length into an array of [Uint32]s in little endian format
  void packLittleEndianLength(int bitLength, List<Uint32> _X, int i) {
    _X[i] = new Uint32(bitLength>>32);
    _X[i+1] = new Uint32(bitLength);
  }

  /// Process [len] bytes from [inp]
  void _processBytes(Uint8List inp, int inpOff, int len) {
    while( len > 0 ) {
      updateByte( inp[inpOff] );

      inpOff++;
      len--;
    }
  }

  /// Process data word by word until no more words can be extracted from [inp] and return the number of bytes processed.
  int _processWholeWords(Uint8List inp, int inpOff, int len) {
    var processed = 0;
    while( len > _xBuf.length ) {
      processWord( inp, inpOff );

      inpOff += _xBuf.length;
      len -= _xBuf.length;
      _byteCount += _xBuf.length;
      processed += 4;
    }
    return processed;
  }

  /// Process bytes from [inp] until the word buffer [_xBuf] is full and reset and return the number of bytes processed.
  int _processUntilNextWord( Uint8List inp, int inpOff, int len ) {
    var processed = 0;
    while( (_xBufOff != 0) && (len > 0) ) {
      updateByte( inp[inpOff] );

      inpOff++;
      len--;
      processed++;
    }
    return processed;
  }

  /// Process a word in [_xBuff] if it is already full and then reset it
  void _processWordIfBufferFull() {
    if( _xBufOff == _xBuf.length ) {
      processWord( _xBuf, 0 );
      _xBufOff = 0;
    }
  }

  /// Add final padding to the digest
  void _addPadding() {
    updateByte( 128 );
    while( _xBufOff != 0 ) {
      updateByte( 0 );
    }
  }

}