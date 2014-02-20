// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

library cipher.api.ufixnum;

import "dart:typed_data";
import "package:bignum/bignum.dart";

/// Interface for unsigned fixed size nums
abstract class UintX<_UintX_> {

  int get bitLength;
  int get byteLength;

  bool operator ==(other);
  bool operator < (other);
  bool operator <=(other);
  bool operator > (other);
  bool operator >=(other);

  _UintX_ operator -();
  _UintX_ operator ~();

  _UintX_ operator +(other);
  _UintX_ operator -(other);
  _UintX_ operator *(other);
  _UintX_ operator /(other);
  _UintX_ operator %(other);

  _UintX_ operator &(other);
  _UintX_ operator |(other);
  _UintX_ operator ^(other);

  _UintX_ operator <<(int n);
  _UintX_ operator >>(int n);

  /// Circular shift left
  _UintX_ rotl(int n);

  /// Circular shift right
  _UintX_ rotr(int n);

  Uint8 toUint8();
  Uint16 toUint16();
  Uint32 toUint32();
  Uint64 toUint64();

  void toBigEndian(Uint8List out, int outOff);
  void toLittleEndian(Uint8List out, int outOff);

  String toString();
  String toRadixString(int radix);

  int get hashCode;
}

/// Base class for unsigned fixed size nums which are compatible with [int] type in VM and Javascript
abstract class UintXSmall<_UintXSmall_> implements UintX<_UintXSmall_> {

  int _value;

  /// Create a [UintXSmall] from a given [value]. The value can be clipped if it cannot fit into this [UintXSmall].
  UintXSmall(int value) {
    _value = _clip(value);
  }

  int toInt() => _value;

  Uint8 toUint8() => new Uint8(_value);
  Uint16 toUint16() => new Uint16(_value);
  Uint32 toUint32() => new Uint32(_value);
  Uint64 toUint64() => new Uint64.fromBigInteger(new BigInteger(_value));

  bool operator ==(other) => (_value == _int(other));
  bool operator < (other) => (_value <  _int(other));
  bool operator <=(other) => (_value <= _int(other));
  bool operator > (other) => (_value >  _int(other));
  bool operator >=(other) => (_value >= _int(other));

  _UintXSmall_ operator -() => _coerce(-_value);
  _UintXSmall_ operator ~() => _coerce(~_value);

  _UintXSmall_ operator +(other) => _coerce(_value + _int(other));
  _UintXSmall_ operator -(other) => _coerce(_value - _int(other));
  _UintXSmall_ operator *(other) => _coerce(_value * _int(other));
  _UintXSmall_ operator /(other) => _coerce(_value ~/ _int(other));
  _UintXSmall_ operator %(other) => _coerce(_value % _int(other));

  _UintXSmall_ operator &(other) => _coerce(_value & _int(other));
  _UintXSmall_ operator |(other) => _coerce(_value | _int(other));
  _UintXSmall_ operator ^(other) => _coerce(_value ^ _int(other));

  _UintXSmall_ operator <<(int n) => _coerce(_value << (n % bitLength));
  _UintXSmall_ operator >>(int n) => _coerce(_value >> (n % bitLength));

  _UintXSmall_ rotl(int n) {
    if( n<0 ) throw new ArgumentError("Shift offset cannot be negative");
    n = (n % bitLength);
    return _coerce(_clip(_value << n) | _clip(_value >> (bitLength - n)));
  }

  _UintXSmall_ rotr(int n) {
    if( n<0 ) throw new ArgumentError("Shift offset cannot be negative");
    n = (n % bitLength);
    return _coerce(_clip(_value >> n) | _clip(_value << (bitLength - n)));
  }

  void toBigEndian( Uint8List out, int outOff ) {
    var offset = bitLength;
    for( var i=0 ; i<byteLength ; i++ ) {
      offset -= 8;
      out[outOff] = (_value >> offset);
      outOff++;
    }
  }

  void toLittleEndian( Uint8List out, int outOff ) {
    var offset = 0;
    for( var i=0 ; i<byteLength ; i++ ) {
      out[outOff] = (_value >> offset);
      outOff++;
      offset += 8;
    }
  }

  String toString() => toInt().toString();
  String toRadixString(int radix) => toInt().toRadixString(radix);

  int get hashCode => _value.hashCode;

  /// Clip [value] to this [UintXSmall] size and return it as an [int]
  int _clip(int value);

  /// Clip [value] to this [UintXSmall] size and return it as an instance of this [UintXSmall] type
  _UintXSmall_ _coerce(int value);

  /// Convert [value] to [int] in case it is a real [int] or if it is of the same type as this object
  int _int(value) {
    if( value is int ) {
      return value;
    } else if( value.runtimeType==runtimeType ) {
      return value.toInt();
    } else {
      throw new ArgumentError("Value is not an int, nor an ${runtimeType}: "+value);
    }
  }
}

/// Base class for unsigned fixed size nums which are compatible with [int] type in VM and Javascript
abstract class UintXBig<_UintXBig_> implements UintX<_UintXBig_> {

  BigInteger _value;

  UintXBig(List<int> values) {
    if (values.length != (byteLength~/4)) {
      throw new ArgumentError("Invalid values array length ${values.length}: should be ${byteLength~/4}");
    }
    _value = BigInteger.ZERO;
    for (var i=0; (i < values.length); i++) {
      var shift = (values.length - i - 1);
      _value |= (new BigInteger(values[i]) << (shift * 32));
    }
  }

  UintXBig.fromBigInteger(BigInteger value) {
    _value = _clip(value);
  }

  BigInteger toBigInteger() => _value;

  Uint8 toUint8() => new Uint8(_value.intValue());
  Uint16 toUint16() => new Uint16(_value.intValue());
  Uint32 toUint32() => new Uint32(_value.intValue());
  Uint64 toUint64() => new Uint64.fromBigInteger(_value);

  bool operator ==(other) => (_value == _bi(other));
  bool operator <(other)  => (_value <  _bi(other));
  bool operator <=(other) => (_value <= _bi(other));
  bool operator >(other)  => (_value >  _bi(other));
  bool operator >=(other) => (_value >= _bi(other));

  _UintXBig_ operator -() => _coerce(-_value);
  _UintXBig_ operator ~() => _coerce(~_value);

  _UintXBig_ operator +(other) => _coerce(_value + _bi(other));
  _UintXBig_ operator -(other) => _coerce(_value - _bi(other));
  _UintXBig_ operator *(other) => _coerce(_value * _bi(other));
  _UintXBig_ operator /(other) => _coerce(_value / _bi(other));
  _UintXBig_ operator %(other) => _coerce(_value % _bi(other));

  _UintXBig_ operator &(other) => _coerce(_value & _bi(other));
  _UintXBig_ operator |(other) => _coerce(_value | _bi(other));
  _UintXBig_ operator ^(other) => _coerce(_value ^ _bi(other));

  _UintXBig_ operator <<(n) => _coerce(_value << (n % bitLength));
  _UintXBig_ operator >>(n) => _coerce(_value >> (n % bitLength));

  _UintXBig_ rotl(int n) {
    if(n < 0) throw new ArgumentError("Shift offset cannot be negative");
    n = (n % bitLength);
    return _coerce(_clip(_value << n) | _clip(_value >> (bitLength - n)));
  }

  _UintXBig_ rotr(int n) {
    if (n < 0) throw new ArgumentError("Shift offset cannot be negative");
    n = (n % bitLength);
    return _coerce(_clip(_value >> n) | _clip(_value << (bitLength - n)));
  }

  void toBigEndian(Uint8List out, int outOff) {
    var bytes = _value.toByteArray();
    // Remove possible leading 0 when topmost bit is 1
    if (bytes[0] == 0) {
      bytes = bytes.sublist(1);
    }
    out.setRange(outOff, outOff+byteLength, bytes);
  }

  void toLittleEndian(Uint8List out, int outOff) {
    var bytes = _value.toByteArray();
    out.setRange(outOff, outOff+byteLength, bytes.reversed);
  }

  String toString() => _value.toString();
  String toRadixString(int radix) => _value.toRadix(radix);

  int get hashCode => _value.hashCode;

  /// Clip [value] to this [UintXBig] size and return it as a [BigInteger]
  BigInteger _clip(BigInteger value);

  /// Clip [value] to this [UintXBig] size and return it as an instance of this [UintXBig] type
  _UintXBig_ _coerce(BigInteger value);

  /// Convert [value] to [BigInteger] if it is [int], [BigInteger] or the same type as this object
  BigInteger _bi(value) {
    if (value is BigInteger) {
      return value;
    } else if (value is int) {
      return new BigInteger(value);
    } else if (value.runtimeType==runtimeType) {
      return value.toBigInteger();
    } else {
      throw new ArgumentError("Value is not a BigInteger, nor an ${runtimeType}: "+value.runtimeType.toString());
    }
  }

}

/// Implementation of unsigned 8-bit size nums
class Uint8 extends UintXSmall<Uint8> {

  static int clip(int value) => (value & 0xFF);

  Uint8(int value) : super(value);

  int get bitLength => 8;
  int get byteLength => 1;

  int _clip(int value) => clip(value);
  Uint8 _coerce(int value) => new Uint8(value);

}

/// Implementation of unsigned 16-bit size nums
class Uint16 extends UintXSmall<Uint16> {

  static int clip(int value) => (value & 0xFFFF);

  Uint16(int value) : super(value.toInt());

  Uint16.fromBigEndian( Uint8List value, int offset ) :
    super( new ByteData.view(value.buffer).getUint16(offset, Endianness.BIG_ENDIAN ) );

  Uint16.fromLittleEndian( Uint8List value, int offset ) :
    super( new ByteData.view(value.buffer).getUint16(offset, Endianness.LITTLE_ENDIAN ) );

  int get bitLength => 16;
  int get byteLength => 2;

  int _clip(int value) => clip(value);
  Uint16 _coerce(int value) => new Uint16(value);

}

/// Implementation of unsigned 32-bit size nums
class Uint32 extends UintXSmall<Uint32> {

  static int clip(int value) => (value & 0xFFFFFFFF);

  Uint32(int value) : super(value.toInt());

  Uint32.fromBigEndian( Uint8List value, int offset ) :
    super( new ByteData.view(value.buffer).getUint32(offset, Endianness.BIG_ENDIAN ) );

  Uint32.fromLittleEndian( Uint8List value, int offset ) :
    super( new ByteData.view(value.buffer).getUint32(offset, Endianness.LITTLE_ENDIAN ) );

  int get bitLength => 32;
  int get byteLength => 4;

  int _clip(int value) => clip(value);
  Uint32 _coerce(int value) => new Uint32(value);

}

/// Implementation of unsigned 64-bit size nums
class Uint64 extends UintXBig<Uint64> {

  static final BigInteger _MODULUS = new BigInteger("FFFFFFFFFFFFFFFF", 16);

  static BigInteger clip(BigInteger value) => (value & _MODULUS);

  Uint64(int hvalue, int lvalue)
    : super([hvalue, lvalue]);

  Uint64.fromBigInteger(BigInteger value)
    : super.fromBigInteger(value);

  Uint64.fromBigEndian(Uint8List value, int offset)
    : super(_toValues(value, offset, 8, Endianness.BIG_ENDIAN));

  Uint64.fromLittleEndian(Uint8List value, int offset)
    : super(_toValues(value, offset, 8, Endianness.LITTLE_ENDIAN));

  int get bitLength => 64;
  int get byteLength => 8;

  BigInteger _clip(BigInteger value) => clip(value);
  Uint64 _coerce(BigInteger value) => new Uint64.fromBigInteger(value);

}
/* Implementation of Uint64 based on native ints, which as of 20-feb-2014 was slower than the one based on BigInteger
class Uint64 extends UintXSmall<Uint64> implements UintXBig<Uint64> {

  static int clip(int value) => (value & 0xFFFFFFFFFFFFFFFF);

  Uint64(int hvalue, int lvalue)
    : super((hvalue << 32) | lvalue);

  Uint64.fromBigInteger(BigInteger value)
    : super(int.parse(value.toString()));

  Uint64.fromBigEndian(Uint8List value, int offset) : super(
    new ByteData.view(value.buffer).getUint32(offset, Endianness.BIG_ENDIAN )<<32 |
    new ByteData.view(value.buffer).getUint32(offset+4, Endianness.BIG_ENDIAN )
  );

  Uint64.fromLittleEndian(Uint8List value, int offset) : super(
    new ByteData.view(value.buffer).getUint32(offset+4, Endianness.LITTLE_ENDIAN )<<32 |
    new ByteData.view(value.buffer).getUint32(offset, Endianness.LITTLE_ENDIAN )
  );

  int get bitLength => 64;
  int get byteLength => 8;

  int _clip(int value) => clip(value);
  Uint64 _coerce(int value) => new Uint64(0,value);

  int _int(value) {
    if (value is int) {
      return value;
    } else if (value is BigInteger) {
      return int.parse(value.toString());
    } else if (value.runtimeType==runtimeType) {
      return value.toInt();
    } else {
      throw new ArgumentError("Value is not an int, nor an ${runtimeType}: "+value);
    }
  }
}
*/

/// Convert an array of bytes with the given [endianness] to a [List<int>] of 32 bits
List<int> _toValues(Uint8List value, int offset, int byteLength, Endianness endianness) {
  var values = [];
  var bytes = new ByteData.view(value.buffer);

  switch (endianness) {

    case Endianness.BIG_ENDIAN:
      for (var i=0; i<byteLength; i+=4) {
        values.add(bytes.getUint32(offset+i, endianness));
      }
      break;

    case Endianness.LITTLE_ENDIAN:
      for (var i=byteLength-4; i>=0; i-=4) {
        values.add(bytes.getUint32(offset+i, endianness));
      }
      break;

    default:
      throw new ArgumentError("Invalid endianness: ${endianness}");

  }

  return values;
}

