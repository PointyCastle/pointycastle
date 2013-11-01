// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com  
// Use of this source code is governed by a LGPL v3 license. 
// See the LICENSE file for more information.

library cipher.digests.general_digest;

import "dart:typed_data";

import "package:cipher/api.dart";

/**
 * Base implementation of MD4 family style digest as outlined in "Handbook of
 * Applied Cryptography", pages 344 - 347.
 */
abstract class GeneralDigest implements Digest {

  Uint8List _xBuf;
  int _xBufOff;
  /*long*/ int _byteCount;

  GeneralDigest() {
    _xBuf = new Uint8List(4);
    _xBufOff = 0;
  }

  void reset() {
    _byteCount = 0;

    _xBufOff = 0;
    for( var i=0 ; i < _xBuf.length ; i++ ) {
      _xBuf[i] = 0;
    }
  }

  void updateByte( int inp ) {
    _xBuf[_xBufOff++] = inp;

    if( _xBufOff == _xBuf.length ) {
      processWord( _xBuf, 0 );
      _xBufOff = 0;
    }

    _byteCount++;
  }

  void update( Uint8List inp, int inpOff, int len ) {
    //
    // fill the current word
    //
    while( (_xBufOff != 0) && (len > 0) ) {
      updateByte( inp[inpOff] );

      inpOff++;
      len--;
    }

    //
    // process whole words.
    //
    while( len > _xBuf.length ) {
      processWord( inp, inpOff );

      inpOff += _xBuf.length;
      len -= _xBuf.length;
      _byteCount += _xBuf.length;
    }

    //
    // load in the remainder.
    //
    while( len > 0 ) {
      updateByte( inp[inpOff] );

      inpOff++;
      len--;
    }
  }

  void finish() {
    /*long*/ var bitLength = (_byteCount << 3);

    //
    // add the pad bytes.
    //
    updateByte( 128 );

    while( _xBufOff != 0 ) {
      updateByte( 0 );
    }

    processLength( bitLength );

    processBlock();
  }

  void processWord( Uint8List inp, int inpOff );
  void processLength( /*long*/ int bitLength );
  void processBlock();

}