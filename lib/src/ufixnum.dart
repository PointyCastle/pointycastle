// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com  
// Use of this source code is governed by a LGPL v3 license. 
// See the LICENSE file for more information.

library cipher.src.ufixnum;

import "dart:typed_data";

/// Implementation of unsigned 8-bit size nums
class Uint8 extends UintX {
  
  static int clip( int value ) => (value&0xFF); 
  
  Uint8(int value) : super(value);

  int get bitLength => 8;
  int get byteLength => 1;

  int _clip( int value ) => clip(value);
  Uint8 _coerce(int value) => new Uint8(value);

}

/// Implementation of unsigned !6-bit size nums
class Uint16 extends UintX {
  
  static int clip( int value ) => (value&0xFFFF);

  Uint16(int value) : super(value);
  
  Uint16.fromBigEndian( Uint8List value, int offset ) :
    super( new ByteData.view(value.buffer).getUint16(offset, Endianness.BIG_ENDIAN ) );

  Uint16.fromLittleEndian( Uint8List value, int offset ) :
    super( new ByteData.view(value.buffer).getUint16(offset, Endianness.LITTLE_ENDIAN ) );

  int get bitLength => 16;
  int get byteLength => 2;

  int _clip( int value ) => clip(value);
  Uint16 _coerce(int value) => new Uint16(value);

}

/// Implementation of unsigned 32-bit size nums
class Uint32 extends UintX {
  
  static int clip( int value ) => (value&0xFFFFFFFF);

  Uint32(int value) : super(value);

  Uint32.fromBigEndian( Uint8List value, int offset ) :
    super( new ByteData.view(value.buffer).getUint32(offset, Endianness.BIG_ENDIAN ) );

  Uint32.fromLittleEndian( Uint8List value, int offset ) :
    super( new ByteData.view(value.buffer).getUint32(offset, Endianness.LITTLE_ENDIAN ) );

  int get bitLength => 32;
  int get byteLength => 4;

  int _clip( int value ) => clip(value);
  Uint32 _coerce(int value) => new Uint32(value);

}

/// Partial implementation of unsigned fixed size nums
abstract class UintX {
  
  int _value;
  
  UintX( int value ) { 
    _value = _clip(value);
  }

  int get bitLength;
  int get byteLength;

  int _clip( int value );
  UintX _coerce( int value );
  
  int toInt() => _value;

  bool operator ==(other) => ( _value == _int(other) );
  bool operator < (other) => ( _value <  _int(other) );
  bool operator <=(other) => ( _value <= _int(other) );
  bool operator > (other) => ( _value >  _int(other) );
  bool operator >=(other) => ( _value >= _int(other) );

  UintX operator -() => _coerce( -_value );
  UintX operator ~() => _coerce( ~_value );

  UintX operator + (other) => _coerce( _value + _int(other) );
  UintX operator - (other) => _coerce( _value - _int(other) );
  UintX operator * (other) => _coerce( _value * _int(other) );
  UintX operator / (other) => this~/other;
  UintX operator ~/(other) => _coerce( _value ~/ _int(other) );
  UintX operator % (other) => _coerce( _value % _int(other) );

  UintX operator &(other) => _coerce( _value & _int(other) );
  UintX operator |(other) => _coerce( _value | _int(other) );
  UintX operator ^(other) => _coerce( _value ^ _int(other) );

  UintX operator <<( int n ) => _coerce( _value<<(n%bitLength) );
  UintX operator >>( int n ) => _coerce( _value>>(n%bitLength) );
  
  /// Circular shift left
  int rotl( int n ) {
    if( n<0 ) throw new ArgumentError("Shift offset cannot be negative");
    n = (n%bitLength);
    return _clip(_value << n) | _clip(_value >> (bitLength - n));
  }

  /// Circular shift right
  int rotr( int n ) {
    if( n<0 ) throw new ArgumentError("Shift offset cannot be negative");
    n = (n%bitLength);
    return _clip(_value >> n) | _clip(_value << (bitLength - n));
  }
  
  /// Conversion of endianness
  void toBigEndian( Uint8List out, int outOff ) {
    var offset = bitLength;
    for( var i=0 ; i<byteLength ; i++ ) {
      offset -= 8;
      out[outOff] = _value >> offset;
      outOff++;
    }
  }

  /// Conversion of endianness
  void toLittleEndian( Uint8List out, int outOff ) {
    var offset = 0;
    for( var i=0 ; i<byteLength ; i++ ) {
      out[outOff] = _value >> offset;
      outOff++;
      offset += 8;
    }
  }
  
  int _int( value ) {
    if( value is int ) {
      return value;
    } else if( value.runtimeType==runtimeType ) {
      return value.toInt();
    } else {
      throw new ArgumentError("Value is not an int, nor an ${runtimeType}: "+value);
    }
  }
}

