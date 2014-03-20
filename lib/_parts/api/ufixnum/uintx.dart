// Copyright (c) 2013, Iván Zaera Avellón - izaera@gmail.com
// Use of this source code is governed by a LGPL v3 license.
// See the LICENSE file for more information.

part of cipher.api.ufixnum;

/// Interface for unsigned fixed size nums
@deprecated
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
@deprecated
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
  Uint64 toUint64() => new Uint64(0, _value);

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
@deprecated
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
      if (value > Uint32.MAX_VALUE.toInt()) {
        throw new ArgumentError("Trying to coerce an int > 0x${Uint32.MAX_VALUE.toRadixString(16)} will fail in Javascript");
      }
      return new BigInteger(value);
    } else if (value.runtimeType==runtimeType) {
      return value.toBigInteger();
    } else {
      throw new ArgumentError("Value is not a BigInteger, nor an ${runtimeType}: "+value.runtimeType.toString());
    }
  }

}

/// Implementation of unsigned 8-bit size nums
@deprecated
class Uint8 extends UintXSmall<Uint8> {

  static final MAX_VALUE = new Uint8(0xFF);

  static int clip(int value) => (value & 0xFF);

  Uint8(int value) : super(value);

  int get bitLength => 8;
  int get byteLength => 1;

  int _clip(int value) => clip(value);
  Uint8 _coerce(int value) => new Uint8(value);

}

/// Implementation of unsigned 16-bit size nums
@deprecated
class Uint16 extends UintXSmall<Uint16> {

  static final MAX_VALUE = new Uint16(0xFFFF);

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
@deprecated
class Uint32 {

  static const _MASK = 0xFFFFFFFF;

  static final MAX_VALUE = new Uint32(_MASK);

  int _value;

  Uint32(int value) :
    _value = (value & _MASK);

  Uint32.fromBigEndian( Uint8List value, int offset ) :
    this(new ByteData.view(value.buffer).getUint32(offset, Endianness.BIG_ENDIAN));

  Uint32.fromLittleEndian( Uint8List value, int offset ) :
    this(new ByteData.view(value.buffer).getUint32(offset, Endianness.LITTLE_ENDIAN));

  final int bitLength = 32;
  final int byteLength = 4;

  int toInt() => _value;

  Uint8 toUint8() => new Uint8(_value);
  Uint16 toUint16() => new Uint16(_value);
  Uint32 toUint32() => new Uint32(_value);
  Uint64 toUint64() => new Uint64(0, _value);

  bool operator ==(other) => (_value == _int(other));
  bool operator < (other) => (_value <  _int(other));
  bool operator <=(other) => (_value <= _int(other));
  bool operator > (other) => (_value >  _int(other));
  bool operator >=(other) => (_value >= _int(other));

  Uint32 operator -() => new Uint32(-_value);
  Uint32 operator ~() => new Uint32(~_value);

  Uint32 operator +(other) => new Uint32(_value + _int(other));
  Uint32 operator -(other) => new Uint32(_value - _int(other));
  Uint32 operator *(other) => new Uint32(_value * _int(other));
  Uint32 operator /(other) => new Uint32(_value ~/ _int(other));
  Uint32 operator %(other) => new Uint32(_value % _int(other));

  Uint32 operator &(other) => new Uint32(_value & _int(other));
  Uint32 operator |(other) => new Uint32(_value | _int(other));
  Uint32 operator ^(other) => new Uint32(_value ^ _int(other));

  Uint32 operator <<(int n) => new Uint32(_value << (n % bitLength));
  Uint32 operator >>(int n) => new Uint32(_value >> (n % bitLength));

  Uint32 rotl(int n) {
    if( n<0 ) throw new ArgumentError("Shift offset cannot be negative");
    n = (n % bitLength);
    return new Uint32(((_value << n) & _MASK) | ((_value >> (bitLength - n)) & _MASK));
  }

  Uint32 rotr(int n) {
    if( n<0 ) throw new ArgumentError("Shift offset cannot be negative");
    n = (n % bitLength);
    return new Uint32(rotr32(_value, n));
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

  /// Convert [value] to [int] in case it is a real [int] or if it is of the same type as this object
  int _int(value) {
    if( value is int ) {
      return value;
    } else if( value is Uint32 ) {
      return value.toInt();
    } else {
      throw new ArgumentError("Value is not an int, nor an ${runtimeType}: "+value);
    }
  }
}

/// Implementation of unsigned 64-bit size nums
@deprecated
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

/* Implementation of Uint64 based on Uint32 ints (not totally finished and I don't know if it runs faster than BigInteger one)
class Uint64 implements UintX<Uint64> {

  static final MAX_VALUE = new Uint64(0xFFFFFFFF, 0xFFFFFFFF);

  static final _BI_HALF_MASK = new BigInteger(0xFFFFFFFF);

  Uint32 _hvalue;
  Uint32 _lvalue;

  /// Create a [UintXSmall] from a given [value]. The value can be clipped if it cannot fit into this [UintXSmall].
  Uint64(int hvalue, int lvalue) {
    _hvalue = new Uint32(hvalue);
    _lvalue = new Uint32(lvalue);
  }

  Uint64.fromBigEndian(Uint8List value, int offset) {
    var view = new ByteData.view(value.buffer);
    _hvalue = new Uint32(view.getUint32(offset+0, Endianness.BIG_ENDIAN));
    _lvalue = new Uint32(view.getUint32(offset+4, Endianness.BIG_ENDIAN));
  }

  Uint64.fromLittleEndian(Uint8List value, int offset) {
    var view = new ByteData.view(value.buffer);
    _hvalue = new Uint32(view.getUint32(offset+4, Endianness.LITTLE_ENDIAN));
    _lvalue = new Uint32(view.getUint32(offset+0, Endianness.LITTLE_ENDIAN));
  }

  int get bitLength => 64;
  int get byteLength => 8;

  Uint32 get highUint32 => _hvalue;
  Uint32 get lowUint32 => _lvalue;

  Uint8 toUint8() => _lvalue.toUint8();
  Uint16 toUint16() => _lvalue.toUint16();
  Uint32 toUint32() => _lvalue;
  Uint64 toUint64() => this;

  bool operator ==(other) {
    var o = _coerce(other);
    return (_hvalue == o._hvalue) && (_lvalue == o._lvalue);
  }

  bool operator < (other) {
    var o = _coerce(other);
    return (_hvalue < o._hvalue) || ((_hvalue == o._hvalue) && (_lvalue < o._lvalue));
  }

  bool operator <=(other) {
    var o = _coerce(other);
    return (this < o) || (this == o);
  }

  bool operator > (other) {
    var o = _coerce(other);
    return (_hvalue > o._hvalue) || ((_hvalue == o._hvalue) && (_lvalue > o._lvalue));
  }

  bool operator >=(other) {
    var o = _coerce(other);
    return (this > o) || (this == o);
  }

  Uint64 operator -() => ((~this) + 1);
  Uint64 operator ~() => new Uint64((~_hvalue).toInt(), (~_lvalue).toInt());

  Uint64 operator +(other) {
    var o = _coerce(other);

    var lvalue = _lvalue.toInt() + o._lvalue.toInt();

    var carry = 0;
    if (lvalue > Uint32.MAX_VALUE.toInt()) {
      carry = 1;
    }

    var hvalue = _hvalue.toInt() + o._hvalue.toInt() + carry;

    return new Uint64(hvalue, lvalue);
  }

  Uint64 operator -(other) {
    var o = _coerce(other);
    return (this + (-o));
  }

  Uint64 operator *(other) {
    var o = _coerce(other);

    // this * o = (h * oh * 2^64) + ((h * ol + l * oh) * 2^32) + (l * ol)
    var h = _hvalue.toInt();
    var l = _lvalue.toInt();
    var oh = o._hvalue.toInt();
    var ol = o._lvalue.toInt();

    var hvalue = (h * ol) + (l * oh);
    var lvalue = (l * ol);

    return new Uint64(hvalue, lvalue);
  }

  Uint64 operator /(other) {
    // TODO: Uint64./
    var o = _coerce(other);
    return _fromBigInteger(_toBigInteger() / o._toBigInteger());
  }

  Uint64 operator %(other) {
    // TODO: Uint64.%
    var o = _coerce(other);
    return _fromBigInteger(_toBigInteger() % o._toBigInteger());
  }

  Uint64 operator &(other) {
    var o = _coerce(other);
    return new Uint64((_hvalue & o._hvalue).toInt(), (_lvalue & o._lvalue).toInt());
  }

  Uint64 operator |(other) {
    var o = _coerce(other);
    return new Uint64((_hvalue | o._hvalue).toInt(), (_lvalue | o._lvalue).toInt());
  }

  Uint64 operator ^(other) {
    var o = _coerce(other);
    return new Uint64((_hvalue ^ o._hvalue).toInt(), (_lvalue ^ o._lvalue).toInt());
  }

  Uint64 operator <<(int n) {
    n = (n % 64);
    if (n == 0) {
      return this;
    } else if(n >= 32) {
      return new Uint64((_lvalue >> (32 - n)).toInt(), 0);
    } else {
      var o = new Uint64(_hvalue.toInt(), _lvalue.toInt());
      o._hvalue <<= n;
      o._hvalue |= (o._lvalue >> (32 - n));
      o._lvalue <<= n;
      return o;
    }
  }

  Uint64 operator >>(int n) {
    n = (n % 64);
    if (n == 0) {
      return this;
    } else if(n >= 32) {
      return new Uint64(0, (_hvalue << (32 - n)).toInt());
    } else {
      var o = new Uint64(_hvalue.toInt(), _lvalue.toInt());
      o._lvalue >>= n;
      o._lvalue |= (o._hvalue << (32 - n));
      o._hvalue >>= n;
      return o;
    }
  }

  Uint64 rotl(int n) {
    n = (n % 64);
    if (n == 0) {
      return this;
    } else {
      var o;

      if(n >= 32) {
        o = new Uint64(_lvalue.toInt(), _hvalue.toInt());
        n -= 32;
      } else {
        o = new Uint64(_hvalue.toInt(), _lvalue.toInt());
      }

      if (n == 0) {
        return o;
      } else {
        o._hvalue <<= n;
        o._hvalue |= (o._lvalue << (32 - n));
        o._lvalue <<= n;
        o._lvalue |= (o._hvalue << (32 - n));
        return o;
      }
    }
  }

  Uint64 rotr(int n) {
    n = (n % 64);
    if (n == 0) {
      return this;
    } else {
      var o;

      if(n >= 32) {
        o = new Uint64(_lvalue.toInt(), _hvalue.toInt());
        n -= 32;
      } else {
        o = new Uint64(_hvalue.toInt(), _lvalue.toInt());
      }

      if (n == 0) {
        return o;
      } else {
        o._hvalue >>= n;
        o._lvalue |= (o._hvalue >> (32 - n));
        o._lvalue >>= n;
        o._hvalue |= (o._lvalue >> (32 - n));
        return o;
      }
    }
  }

  void toBigEndian( Uint8List out, int outOff ) {
    _hvalue.toBigEndian(out, outOff+0);
    _lvalue.toBigEndian(out, outOff+4);
  }

  void toLittleEndian( Uint8List out, int outOff ) {
    _hvalue.toLittleEndian(out, outOff+4);
    _lvalue.toLittleEndian(out, outOff+0);
  }

  String toString() => _toBigInteger().toString();
  String toRadixString(int radix) => _toBigInteger().toRadix(16);

  int get hashCode => _lvalue.hashCode; // TODO: Uint64.hashCode

  Uint64 _coerce(value) {
    if( value is int ) {
      if (value > Uint32.MAX_VALUE.toInt()) {
        throw new ArgumentError("Trying to coerce an int >0x${Uint32.MAX_VALUE.toRadixString(16)} won't work in Javascript");
      }
      return new Uint64(0,value);
    } else if( value is BigInteger ) {
      return _fromBigInteger(value);
    } else if( value.runtimeType==runtimeType ) {
      return value;
    } else {
      throw new ArgumentError("Value is not an int, nor an ${runtimeType}: "+value);
    }
  }

  Uint64 _fromBigInteger(BigInteger bi) {
    var hvalue = (bi >> 32);
    var lvalue = (bi & _BI_HALF_MASK);
    return new Uint64(hvalue.intValue(), lvalue.intValue());
  }

  BigInteger _toBigInteger() {
    var bi = new BigInteger(_lvalue.toInt());
    var hbi = new BigInteger(_hvalue.toInt());
    bi |= (hbi<<32);
    return bi;
  }

}
*/

