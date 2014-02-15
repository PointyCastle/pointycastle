// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.stream.salsa20;

import "dart:typed_data";

import "package:cipher/api/ufixnum.dart";
import "package:cipher/params/key_parameter.dart";
import "package:cipher/params/parameters_with_iv.dart";
import "package:cipher/stream/base_stream_cipher.dart";

/// Implementation of Daniel J. Bernstein's Salsa20 stream cipher, Snuffle 2005.
class Salsa20Engine extends BaseStreamCipher {

  static const _STATE_SIZE = 16; // 16, 32 bit ints = 64 bytes
  static const _BYTE_LIMIT = 0x400000000000000000;

  static final _sigma = new Uint8List.fromList( "expand 32-byte k".codeUnits );
  static final _tau = new Uint8List.fromList( "expand 16-byte k".codeUnits );

  // Variables to hold the state of the engine during encryption and decryption
  var _index = 0;
  var _engineState = new List<int>(_STATE_SIZE); // state
  var _x = new List<int>(_STATE_SIZE); // internal buffer
  var _keyStream  = new Uint8List(_STATE_SIZE * 4); // expanded state, 64 bytes
  Uint8List _workingKey  = null;
  Uint8List _workingIV   = null;
  var _initialised = false;

  // Internal counter for detecting algorithm limit overflow
  int _counter;

  String get algorithmName => "Salsa20";

  void reset() {
    if( _workingKey!=null ) {
      _setKey(_workingKey, _workingIV);
    }
  }

  void init( bool forEncryption, ParametersWithIV<KeyParameter> params ) {
    // Salsa20 encryption and decryption is completely symmetrical, so the 'forEncryption' is irrelevant.

    var uparams = params.parameters;
    var iv = params.iv;
    if( iv == null || iv.length != 8 ) {
        throw new ArgumentError("Salsa20 requires exactly 8 bytes of IV");
    }

    _workingIV = iv;
    _workingKey = uparams.key;

    _setKey( _workingKey, _workingIV );
  }

  int returnByte( int inp ) {
    if( _limitExceeded() ) {
      throw new StateError(
        "Salsa20 can only securely cipher 2^70 bytes per IV: please change IV in order to stay secure and not incur in a "
        "two-time pad type error"
      );
    }

    if (_index == 0) {
      _generateKeyStream(_keyStream);

      if (++_engineState[8] == 0) {
        ++_engineState[9];
      }
    }

    var out = (_keyStream[_index]^inp)&0xFF;
    _index = (_index + 1) & 63;

    return out;
  }

  void processBytes( Uint8List inp, int inpOff, int len, Uint8List out, int outOff ) {
    if( !_initialised ) {
      throw new StateError( "Salsa20 not initialized: please call init() first" );
    }

    if( (inpOff + len) > inp.length ) {
      throw new ArgumentError( "Input buffer too short or requested length too long" );
    }

    if( (outOff + len) > out.length ) {
      throw new ArgumentError( "Output buffer too short or requested length too long" );
    }

    if( _limitExceeded(len) ) {
      throw new ArgumentError(
        "Salsa20 can only securely cipher 2^70 bytes per IV, requested length too long: call processBytes() several times "
        "changing IV between calls"
      );
    }

    for( var i=0 ; i<len ; i++ ) {
      if( _index==0 ) {
        _generateKeyStream(_keyStream);

        if( ++_engineState[8] == 0 ) {
          ++_engineState[9];
        }
      }

      out[i+outOff] = (_keyStream[_index]^inp[i+inpOff])&0xFF;
      _index = (_index + 1) & 63;
    }
  }


  void _setKey( Uint8List keyBytes, Uint8List ivBytes ) {
    _workingKey = keyBytes;
    _workingIV  = ivBytes;

    _index = 0;
    _resetCounter();
    int offset = 0;
    Uint8List constants;

    // Key
    _engineState[1] = new Uint32.fromLittleEndian(_workingKey,0).toInt();
    _engineState[2] = new Uint32.fromLittleEndian(_workingKey,4).toInt();
    _engineState[3] = new Uint32.fromLittleEndian(_workingKey,8).toInt();
    _engineState[4] = new Uint32.fromLittleEndian(_workingKey,12).toInt();

    if( _workingKey.length == 32 ) {
        constants = _sigma;
        offset = 16;
    } else {
        constants = _tau;
    }

    _engineState[11] = new Uint32.fromLittleEndian(_workingKey,offset).toInt();
    _engineState[12] = new Uint32.fromLittleEndian(_workingKey,offset+4).toInt();
    _engineState[13] = new Uint32.fromLittleEndian(_workingKey,offset+8).toInt();
    _engineState[14] = new Uint32.fromLittleEndian(_workingKey,offset+12).toInt();
    _engineState[0 ] = new Uint32.fromLittleEndian(constants,0).toInt();
    _engineState[5 ] = new Uint32.fromLittleEndian(constants,4).toInt();
    _engineState[10] = new Uint32.fromLittleEndian(constants,8).toInt();
    _engineState[15] = new Uint32.fromLittleEndian(constants,12).toInt();

    // IV
    _engineState[6] = new Uint32.fromLittleEndian(_workingIV,0).toInt();
    _engineState[7] = new Uint32.fromLittleEndian(_workingIV,4).toInt();
    _engineState[8] = _engineState[9] = 0;

    _initialised = true;
  }

  void _generateKeyStream( Uint8List output ) {
    _salsa20Core(20, _engineState, _x);
    var outOff = 0;
    for( var x in _x ) {
      new Uint32(x).toLittleEndian(output, outOff);
      outOff += 4;
    }
  }

  void _resetCounter() {
    _counter = 0;
  }

  bool _limitExceeded([int len=1]) {
    if( len<0 ) throw new ArgumentError("Length is supposed to be >0");
    _counter += len;
    return _counter==_BYTE_LIMIT;
  }

  /// The Salsa20 core function
  void _salsa20Core( int rounds, List<int> input, List<int> x ) {
    x.setAll( 0, input );

    for( var i=rounds ; i>0 ; i-=2 ) {
      x[ 4] ^= _rotl((x[ 0]+x[12]), 7);
      x[ 8] ^= _rotl((x[ 4]+x[ 0]), 9);
      x[12] ^= _rotl((x[ 8]+x[ 4]),13);
      x[ 0] ^= _rotl((x[12]+x[ 8]),18);
      x[ 9] ^= _rotl((x[ 5]+x[ 1]), 7);
      x[13] ^= _rotl((x[ 9]+x[ 5]), 9);
      x[ 1] ^= _rotl((x[13]+x[ 9]),13);
      x[ 5] ^= _rotl((x[ 1]+x[13]),18);
      x[14] ^= _rotl((x[10]+x[ 6]), 7);
      x[ 2] ^= _rotl((x[14]+x[10]), 9);
      x[ 6] ^= _rotl((x[ 2]+x[14]),13);
      x[10] ^= _rotl((x[ 6]+x[ 2]),18);
      x[ 3] ^= _rotl((x[15]+x[11]), 7);
      x[ 7] ^= _rotl((x[ 3]+x[15]), 9);
      x[11] ^= _rotl((x[ 7]+x[ 3]),13);
      x[15] ^= _rotl((x[11]+x[ 7]),18);
      x[ 1] ^= _rotl((x[ 0]+x[ 3]), 7);
      x[ 2] ^= _rotl((x[ 1]+x[ 0]), 9);
      x[ 3] ^= _rotl((x[ 2]+x[ 1]),13);
      x[ 0] ^= _rotl((x[ 3]+x[ 2]),18);
      x[ 6] ^= _rotl((x[ 5]+x[ 4]), 7);
      x[ 7] ^= _rotl((x[ 6]+x[ 5]), 9);
      x[ 4] ^= _rotl((x[ 7]+x[ 6]),13);
      x[ 5] ^= _rotl((x[ 4]+x[ 7]),18);
      x[11] ^= _rotl((x[10]+x[ 9]), 7);
      x[ 8] ^= _rotl((x[11]+x[10]), 9);
      x[ 9] ^= _rotl((x[ 8]+x[11]),13);
      x[10] ^= _rotl((x[ 9]+x[ 8]),18);
      x[12] ^= _rotl((x[15]+x[14]), 7);
      x[13] ^= _rotl((x[12]+x[15]), 9);
      x[14] ^= _rotl((x[13]+x[12]),13);
      x[15] ^= _rotl((x[14]+x[13]),18);
    }

    for (int i = 0; i < _STATE_SIZE; ++i) {
      x[i] += input[i];
    }
  }

  /// Salsa20Core Helper funcion
  int _rotl(int x, int y)  => (x << y) | (new Uint32(x)>>-y).toInt();

}


